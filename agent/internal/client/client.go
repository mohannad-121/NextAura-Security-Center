// Package client is the only place the agent talks to the network. Every call
// goes to the configured server over HTTPS (HTTP allowed only for localhost
// development) with a bounded timeout and bounded response size.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nextaura/agent/internal/config"
	"github.com/nextaura/agent/internal/model"
)

const maxResponseBytes = 1 << 20

type Client struct {
	base  string
	token string
	http  *http.Client
}

var ErrUnauthorized = errors.New("unauthorized")
var ErrRevoked = errors.New("device access revoked")
var ErrRateLimited = errors.New("rate limited")

func ValidateServerURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", raw)
	}
	host := u.Hostname()
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && isLocal) {
		return "", fmt.Errorf("server URL must use https:// (http is only allowed for localhost)")
	}
	return u.String(), nil
}

func New(serverURL, token string) *Client {
	return &Client{
		base:  strings.TrimRight(serverURL, "/") + "/api/agent/v1",
		token: token,
		http: &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirects are not followed")
			},
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "nextaura-agent/"+config.Version)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == 401:
		return fmt.Errorf("%w: %s", ErrUnauthorized, serverMessage(data))
	case resp.StatusCode == 403:
		return fmt.Errorf("%w: %s", ErrRevoked, serverMessage(data))
	case resp.StatusCode == 429:
		return ErrRateLimited
	case resp.StatusCode >= 400:
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, serverMessage(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func serverMessage(data []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		return e.Error
	}
	s := strings.TrimSpace(string(data))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func (c *Client) Enroll(ctx context.Context, req model.EnrollRequest) (*model.EnrollResponse, error) {
	var out model.EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/enroll", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Heartbeat(ctx context.Context, req model.HeartbeatRequest) (*model.HeartbeatResponse, error) {
	var out model.HeartbeatResponse
	if err := c.do(ctx, http.MethodPost, "/heartbeat", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PendingRequests(ctx context.Context) ([]model.PendingRequest, error) {
	var out model.RequestsResponse
	if err := c.do(ctx, http.MethodGet, "/requests", nil, &out); err != nil {
		return nil, err
	}
	return out.Requests, nil
}

func (c *Client) Ack(ctx context.Context, req model.AckRequest) error {
	return c.do(ctx, http.MethodPost, "/requests/ack", req, nil)
}

func (c *Client) SubmitAssessment(ctx context.Context, req model.AssessmentRequest) (*model.AssessmentResponse, error) {
	var out model.AssessmentResponse
	if err := c.do(ctx, http.MethodPost, "/assessments", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SubmitFileEvidence(ctx context.Context, req interface{}) (*model.FileEvidenceResponse, error) {
	var out model.FileEvidenceResponse
	if err := c.do(ctx, http.MethodPost, "/file-evidence", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
