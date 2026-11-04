// Package collectors implements the six fixed, read-only collectors.
//
// Rules every collector follows:
//   - Only read: no settings are changed, no files written, nothing executed
//     beyond the allow-listed read-only system commands in exec.go.
//   - Anything that cannot be observed is reported as UNKNOWN, UNSUPPORTED or
//     PERMISSION_DENIED with the reason; never as PASS.
//   - Every check names its data source and the permission level it needs.
package collectors

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/nextaura/agent/internal/model"
)

const collectorVersion = "1.0.0"

type Collector interface {
	ID() string
	Collect(ctx context.Context) (*model.CollectorResult, error)
}

type collectorFunc struct {
	id string
	fn func(ctx context.Context, r *model.CollectorResult) error
}

func (c collectorFunc) ID() string { return c.id }
func (c collectorFunc) Collect(ctx context.Context) (*model.CollectorResult, error) {
	r := &model.CollectorResult{CollectorID: c.id, CollectorVersion: collectorVersion, Status: "OK", CollectedAt: time.Now().UTC(), Checks: []model.Check{}}
	err := c.fn(ctx, r)
	return r, err
}

// Registry returns the collectors available for this OS. Unsupported ones
// still exist and report UNSUPPORTED so coverage is accounted for honestly.
func Registry() map[string]Collector {
	reg := map[string]Collector{}
	for _, id := range model.AllCollectors {
		reg[id] = collectorFunc{id: id, fn: unsupported(id)}
	}
	registerPlatform(reg)
	return reg
}

func unsupported(id string) func(context.Context, *model.CollectorResult) error {
	return func(_ context.Context, r *model.CollectorResult) error {
		r.Status = "UNSUPPORTED"
		r.Error = model.Str(fmt.Sprintf("collector %s is not implemented for %s/%s", id, runtime.GOOS, runtime.GOARCH))
		return nil
	}
}

// Run executes the requested collectors with a per-collector timeout.
// Unknown collector IDs are rejected outright: there is no dynamic execution.
func Run(ctx context.Context, ids []string, perCollector time.Duration) ([]model.CollectorResult, error) {
	reg := Registry()
	out := make([]model.CollectorResult, 0, len(ids))
	for _, id := range ids {
		if !model.IsKnownCollector(id) {
			return nil, fmt.Errorf("refusing unknown collector %q", id)
		}
		c := reg[id]
		cctx, cancel := context.WithTimeout(ctx, perCollector)
		res, err := c.Collect(cctx)
		cancel()
		if err != nil {
			res.Status = "FAILED"
			res.Error = model.Str(truncate(err.Error(), 900))
		}
		out = append(out, *res)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---- check builders -------------------------------------------------------

type checkBuilder struct {
	id, category, title, source, perms string
}

func ck(id, category, title, source, perms string) checkBuilder {
	return checkBuilder{id: id, category: category, title: title, source: source, perms: perms}
}

func (b checkBuilder) status(status, evidence, confidence string) model.Check {
	return model.Check{CheckID: b.id, Category: b.category, Title: b.title, Status: status, Evidence: evidence, DataSource: b.source, Confidence: confidence, RequiredPermissions: b.perms}
}
func (b checkBuilder) pass(evidence string) model.Check {
	return b.status(model.StatusPass, evidence, "HIGH")
}
func (b checkBuilder) fail(evidence string) model.Check {
	return b.status(model.StatusFail, evidence, "HIGH")
}
func (b checkBuilder) warn(evidence string) model.Check {
	return b.status(model.StatusWarning, evidence, "MEDIUM")
}
func (b checkBuilder) unknown(reason string) model.Check {
	c := b.status(model.StatusUnknown, "Not observed: "+reason, "LOW")
	c.UnavailableReason = model.Str(reason)
	return c
}
func (b checkBuilder) denied(reason string) model.Check {
	c := b.status(model.StatusPermissionDenied, "Not observed: "+reason, "LOW")
	c.UnavailableReason = model.Str(reason)
	return c
}
func (b checkBuilder) unsupportedCheck(reason string) model.Check {
	c := b.status(model.StatusUnsupported, "Not applicable: "+reason, "HIGH")
	c.UnavailableReason = model.Str(reason)
	return c
}

func boolPtr(v bool) *bool { return &v }
