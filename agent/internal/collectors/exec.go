package collectors

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// allowedBinaries is the complete set of executables the agent may invoke.
// All of them are OS-provided and are only ever called with read-only
// arguments. Adding anything here requires a code change and review.
var allowedBinaries = map[string]bool{
	"powershell.exe":  true,
	"system_profiler": true,
	"sw_vers":         true,
	"sysctl":          true,
	"fdesetup":        true,
	"spctl":           true,
	"csrutil":         true,
	"defaults":        true,
	"launchctl":       true,
	"softwareupdate":  true,
	"mdls":            true,
	"dscl":            true,
	"ioreg":           true,
	"uptime":          true,
	"socketfilterfw":  true,
	"ls":              true,
	"nvram":           true,
	"pmset":           true,
	"scutil":          true,
	"uname":           true,
}

var errPermission = errors.New("permission denied")

func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	base := name
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		base = name[i+1:]
	}
	if !allowedBinaries[strings.ToLower(base)] {
		return "", fmt.Errorf("binary %q is not in the agent allow-list", name)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = nil
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		lower := strings.ToLower(msg + " " + out)
		if strings.Contains(lower, "access is denied") || strings.Contains(lower, "permission denied") || strings.Contains(lower, "operation not permitted") || strings.Contains(lower, "not permitted") || strings.Contains(lower, "requires root") || strings.Contains(lower, "must be run as root") {
			return out, fmt.Errorf("%w: %s", errPermission, firstLine(msg))
		}
		if cctx.Err() != nil {
			return out, fmt.Errorf("%s timed out after %s", base, timeout)
		}
		if msg == "" {
			msg = err.Error()
		}
		return out, fmt.Errorf("%s: %s", base, firstLine(msg))
	}
	return out, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
