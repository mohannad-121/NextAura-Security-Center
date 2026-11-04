// Package scheduler drives the agent loop: heartbeat, scheduled assessments
// and operator-requested re-assessments (fixed collectors only).
package scheduler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/nextaura/agent/internal/client"
	"github.com/nextaura/agent/internal/collectors"
	"github.com/nextaura/agent/internal/config"
	"github.com/nextaura/agent/internal/logging"
	"github.com/nextaura/agent/internal/model"
)

const perCollectorTimeout = 3 * time.Minute

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type Runner struct {
	dir     string
	state   *config.State
	client  *client.Client
	started time.Time
	errors  []model.CollectorError
}

func New(dir string, st *config.State) *Runner {
	return &Runner{dir: dir, state: st, client: client.New(st.ServerURL, st.DeviceToken), started: time.Now()}
}

// RunOnce performs one full cycle (used by `nextaura-agent assess`).
func (r *Runner) RunAssessment(ctx context.Context, trigger string, ids []string, requestID *string) (*model.AssessmentResponse, error) {
	started := time.Now().UTC()
	results, err := collectors.Run(ctx, ids, perCollectorTimeout)
	if err != nil {
		return nil, err
	}
	r.errors = r.errors[:0]
	for _, res := range results {
		if res.Status == "FAILED" && res.Error != nil {
			r.errors = append(r.errors, model.CollectorError{CollectorID: res.CollectorID, Message: *res.Error, OccurredAt: res.CollectedAt})
		}
	}
	req := model.AssessmentRequest{IdempotencyKey: newID(), Trigger: trigger, AgentVersion: config.Version, StartedAt: started, CompletedAt: time.Now().UTC(), AgentRequestID: requestID, Collectors: results}
	var resp *model.AssessmentResponse
	backoff := 5 * time.Second
	for attempt := 1; attempt <= 5; attempt++ {
		resp, err = r.client.SubmitAssessment(ctx, req)
		if err == nil {
			break
		}
		if errors.Is(err, client.ErrUnauthorized) || errors.Is(err, client.ErrRevoked) {
			return nil, err
		}
		logging.Warnf("assessment upload attempt %d failed: %v", attempt, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	if err != nil {
		return nil, err
	}
	logging.Infof("assessment %s accepted (duplicate=%v coverage=%d%%)", resp.AssessmentID, resp.Duplicate, resp.CoveragePercent)
	return resp, nil
}

func (r *Runner) heartbeat(ctx context.Context) (*model.HeartbeatResponse, error) {
	up := int64(time.Since(r.started).Seconds())
	resp, err := r.client.Heartbeat(ctx, model.HeartbeatRequest{RequestID: newID(), AgentVersion: config.Version, Timestamp: time.Now().UTC(), UptimeSeconds: &up, CollectorErrors: r.errors})
	if err != nil {
		return nil, err
	}
	changed := false
	if resp.Config.HeartbeatIntervalMinutes > 0 && resp.Config.HeartbeatIntervalMinutes != r.state.HeartbeatIntervalMinutes {
		r.state.HeartbeatIntervalMinutes = resp.Config.HeartbeatIntervalMinutes
		changed = true
	}
	if resp.Config.PostureIntervalHours > 0 && resp.Config.PostureIntervalHours != r.state.PostureIntervalHours {
		r.state.PostureIntervalHours = resp.Config.PostureIntervalHours
		changed = true
	}
	if resp.Config.InventoryIntervalHours > 0 && resp.Config.InventoryIntervalHours != r.state.InventoryIntervalHours {
		r.state.InventoryIntervalHours = resp.Config.InventoryIntervalHours
		changed = true
	}
	if changed {
		_ = config.Save(r.dir, r.state)
	}
	return resp, nil
}

func (r *Runner) handleRequests(ctx context.Context) {
	reqs, err := r.client.PendingRequests(ctx)
	if err != nil {
		logging.Warnf("fetch requests: %v", err)
		return
	}
	for _, q := range reqs {
		var ids []string
		reject := ""
		for _, c := range q.Collectors {
			if !model.IsKnownCollector(c) {
				reject = fmt.Sprintf("unknown collector %q", c)
				break
			}
			ids = append(ids, c)
		}
		if reject != "" || len(ids) == 0 {
			if reject == "" {
				reject = "no collectors"
			}
			logging.Warnf("rejecting request %s: %s", q.ID, reject)
			_ = r.client.Ack(ctx, model.AckRequest{RequestID: q.ID, Status: "REJECTED", Reason: reject})
			continue
		}
		if err := r.client.Ack(ctx, model.AckRequest{RequestID: q.ID, Status: "ACKNOWLEDGED"}); err != nil {
			logging.Warnf("ack %s: %v", q.ID, err)
		}
		logging.Infof("running operator-requested assessment %s: %v", q.ID, ids)
		id := q.ID
		if _, err := r.RunAssessment(ctx, "MANUAL", ids, &id); err != nil {
			logging.Errorf("requested assessment failed: %v", err)
		}
	}
}

// Loop runs until ctx is cancelled. Returns ErrRevoked if the server revoked us.
func (r *Runner) Loop(ctx context.Context) error {
	if r.state.HeartbeatIntervalMinutes <= 0 {
		r.state.HeartbeatIntervalMinutes = 5
	}
	if r.state.PostureIntervalHours <= 0 {
		r.state.PostureIntervalHours = 6
	}
	if r.state.InventoryIntervalHours <= 0 {
		r.state.InventoryIntervalHours = 24
	}
	consecutiveFailures := 0
	for {
		resp, err := r.heartbeat(ctx)
		if err != nil {
			if errors.Is(err, client.ErrRevoked) {
				logging.Errorf("device access revoked by the server; stopping and clearing local token")
				_ = config.Remove(r.dir)
				return client.ErrRevoked
			}
			if errors.Is(err, client.ErrUnauthorized) {
				consecutiveFailures++
				logging.Errorf("heartbeat unauthorized (%d): %v — re-enrollment required if this persists", consecutiveFailures, err)
			} else {
				logging.Warnf("heartbeat failed: %v", err)
			}
		} else {
			consecutiveFailures = 0
			if resp.PendingRequests > 0 {
				r.handleRequests(ctx)
			}
			now := time.Now()
			var due []string
			if now.Sub(r.state.LastPostureAt) >= time.Duration(r.state.PostureIntervalHours)*time.Hour {
				due = append(due, model.PostureCollectors...)
			}
			if now.Sub(r.state.LastInventoryAt) >= time.Duration(r.state.InventoryIntervalHours)*time.Hour {
				due = append(due, model.InventoryCollectors...)
			}
			if len(due) > 0 {
				if _, err := r.RunAssessment(ctx, "SCHEDULED", due, nil); err != nil {
					logging.Errorf("scheduled assessment failed: %v", err)
				} else {
					if len(due) > len(model.InventoryCollectors) || due[0] == model.CollectorSystemInfo {
						r.state.LastPostureAt = now
					}
					if containsAll(due, model.InventoryCollectors) {
						r.state.LastInventoryAt = now
					}
					_ = config.Save(r.dir, r.state)
				}
			}
		}
		interval := time.Duration(r.state.HeartbeatIntervalMinutes) * time.Minute
		if consecutiveFailures > 3 {
			interval = 30 * time.Minute
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

func containsAll(have, want []string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
