package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/nextaura/agent/internal/model"
)

func TestRunRejectsUnknownCollector(t *testing.T) {
	if _, err := Run(context.Background(), []string{"RUN_SHELL"}, time.Second); err == nil {
		t.Fatal("expected unknown collector to be rejected")
	}
}

func TestRegistryHasExactlySixCollectors(t *testing.T) {
	reg := Registry()
	if len(reg) != 6 {
		t.Fatalf("expected 6 collectors, got %d", len(reg))
	}
	for _, id := range model.AllCollectors {
		if _, ok := reg[id]; !ok {
			t.Fatalf("missing collector %s", id)
		}
	}
}

func TestExecAllowList(t *testing.T) {
	if _, err := run(context.Background(), time.Second, "/bin/sh", "-c", "echo hi"); err == nil {
		t.Fatal("shell must not be executable")
	}
	if _, err := run(context.Background(), time.Second, "rm", "-rf", "/tmp/x"); err == nil {
		t.Fatal("rm must not be executable")
	}
}

func TestUnknownNeverPass(t *testing.T) {
	c := ck("X", "SYSTEM", "x", "src", "none").unknown("because")
	if c.Status == model.StatusPass || c.UnavailableReason == nil {
		t.Fatal("unknown check must not be PASS and must carry a reason")
	}
}
