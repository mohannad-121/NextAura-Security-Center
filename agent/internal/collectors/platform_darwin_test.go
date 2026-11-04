//go:build darwin

package collectors

import (
	"testing"

	"github.com/nextaura/agent/internal/model"
)

func TestMacOSSupportTableIsFailClosed(t *testing.T) {
	b := ck("OS_SUPPORT", "OS_SUPPORT", "support", "test", "none")
	cases := []struct {
		version, status string
	}{
		{"27.0.1", model.StatusPass},
		{"26.7.1", model.StatusPass},
		{"15.8.1", model.StatusPass},
		{"14.8.9", model.StatusFail},
		{"28.0", model.StatusUnknown},
	}
	for _, tc := range cases {
		if got := macOSSupportCheck(b, tc.version); got.Status != tc.status {
			t.Errorf("macOS %s: got %s, want %s", tc.version, got.Status, tc.status)
		}
	}
}
