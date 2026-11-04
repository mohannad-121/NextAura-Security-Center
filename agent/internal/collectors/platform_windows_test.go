//go:build windows

package collectors

import (
	"testing"

	"github.com/nextaura/agent/internal/model"
)

func TestWindowsSupportTableDoesNotTreatExpiredConsumerBuildsAsSafe(t *testing.T) {
	b := ck("OS_SUPPORT", "OS_SUPPORT", "support", "test", "none")
	cases := []struct {
		caption, build, status string
	}{
		{"Microsoft Windows 11 Pro", "26100", model.StatusFail},
		{"Microsoft Windows 11 Enterprise", "26100", model.StatusPass},
		{"Microsoft Windows 11 Enterprise", "22631", model.StatusWarning},
		{"Microsoft Windows 11 Pro", "26200", model.StatusPass},
		{"Microsoft Windows 10 Pro", "19045", model.StatusWarning},
	}
	for _, tc := range cases {
		if got := windowsSupportCheck(b, tc.caption, tc.build); got.Status != tc.status {
			t.Errorf("%s build %s: got %s, want %s", tc.caption, tc.build, got.Status, tc.status)
		}
	}
}
