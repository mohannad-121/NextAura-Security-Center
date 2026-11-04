package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nextaura/agent/internal/model"
)

func TestValidateServerURL(t *testing.T) {
	ok := []string{"https://sec.example.com", "https://sec.example.com/", "http://localhost:3000"}
	for _, u := range ok {
		if _, err := ValidateServerURL(u); err != nil {
			t.Errorf("%s should be valid: %v", u, err)
		}
	}
	bad := []string{"http://sec.example.com", "ftp://x", "", "sec.example.com"}
	for _, u := range bad {
		if _, err := ValidateServerURL(u); err == nil {
			t.Errorf("%s should be rejected", u)
		}
	}
}

func TestHeartbeatUsesDeviceTokenAndVersionedPath(t *testing.T) {
	var gotAuth, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"config":{"heartbeatIntervalMinutes":5,"postureIntervalHours":6,"inventoryIntervalHours":24,"minimumAgentVersion":"0.1.0"},"pendingRequests":0}`))
	}))
	defer server.Close()

	c := New(server.URL, "nxa_test-token")
	_, err := c.Heartbeat(context.Background(), model.HeartbeatRequest{
		RequestID: "request-1", AgentVersion: "0.1.0", Timestamp: time.Now().UTC(), CollectorErrors: []model.CollectorError{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/agent/v1/heartbeat" {
		t.Fatalf("unexpected path %q", gotPath)
	}
	if gotAuth != "Bearer nxa_test-token" {
		t.Fatalf("unexpected authorization header %q", gotAuth)
	}
}

func TestUnauthorizedResponseIsClassified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Device token expired; re-enroll"}`))
	}))
	defer server.Close()

	_, err := New(server.URL, "nxa_expired").Heartbeat(context.Background(), model.HeartbeatRequest{
		RequestID: "request-2", AgentVersion: "0.1.0", Timestamp: time.Now().UTC(), CollectorErrors: []model.CollectorError{},
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}
