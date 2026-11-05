// nextaura-agent — read-only endpoint assessment agent for NextAura Security Center.
//
//	printf '%s\n' "$CODE" | nextaura-agent enroll --server https://... --code-stdin
//	nextaura-agent run                 (foreground service loop)
//	nextaura-agent assess [--collectors A,B]  (one-off assessment, uploads)
//	nextaura-agent collect [--collectors A,B] (print results locally, no upload)
//	nextaura-agent inspect-file --path FILE --approved-root DIR (local JSON only)
//	nextaura-agent status
//	nextaura-agent unenroll
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nextaura/agent/internal/client"
	"github.com/nextaura/agent/internal/collectors"
	"github.com/nextaura/agent/internal/config"
	"github.com/nextaura/agent/internal/fileanalysis"
	"github.com/nextaura/agent/internal/logging"
	"github.com/nextaura/agent/internal/model"
	"github.com/nextaura/agent/internal/scheduler"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	dir := config.DefaultDir()
	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(dir, os.Args[2:])
	case "run":
		err = cmdRun(dir)
	case "assess":
		err = cmdAssess(dir, os.Args[2:], true)
	case "collect":
		err = cmdAssess(dir, os.Args[2:], false)
	case "inspect-file":
		err = cmdInspectFile(os.Args[2:])
	case "status":
		err = cmdStatus(dir)
	case "unenroll":
		err = config.Remove(dir)
		if err == nil {
			fmt.Println("Local enrollment removed. Revoke the device in the dashboard to invalidate the server-side token.")
		}
	case "version", "--version", "-v":
		fmt.Printf("nextaura-agent %s (%s/%s)\n", config.Version, runtime.GOOS, runtime.GOARCH)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `nextaura-agent `+config.Version+`
Commands:
  enroll   --server <https url> --code-stdin
  run      run the service loop in the foreground
  assess   run collectors now and upload (--collectors A,B)
  collect  run collectors and print JSON locally without uploading
  inspect-file  bounded local inspection; never uploads or executes the file
  status   show enrollment status (token redacted)
  unenroll delete the local token
  version`)
}

func osType() (string, error) {
	switch runtime.GOOS {
	case "windows":
		return "WINDOWS", nil
	case "darwin":
		return "MACOS", nil
	}
	return "", fmt.Errorf("unsupported operating system %s (see docs/SUPPORTED_PLATFORMS.md)", runtime.GOOS)
}

func cmdEnroll(dir string, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "server URL, e.g. https://security.example.com")
	codeStdin := fs.Bool("code-stdin", false, "read the enrollment code from standard input")
	fs.Parse(args)
	if *server == "" || !*codeStdin {
		return errors.New("--server and --code-stdin are required")
	}
	ost, err := osType()
	if err != nil {
		return err
	}
	srv, err := client.ValidateServerURL(*server)
	if err != nil {
		return err
	}
	if _, err := config.Load(dir); err == nil {
		return errors.New("already enrolled; run `nextaura-agent unenroll` first")
	}
	code, err := readEnrollmentCode(os.Stdin)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	fmt.Println("Collecting system identification…")
	res, err := collectors.Run(ctx, []string{model.CollectorSystemInfo}, 2*time.Minute)
	if err != nil || len(res) == 0 || res[0].System == nil {
		return fmt.Errorf("could not collect system information: %v", err)
	}
	c := client.New(srv, "")
	fmt.Println("Enrolling with", srv, "…")
	resp, err := c.Enroll(ctx, model.EnrollRequest{Code: code, AgentVersion: config.Version, OSType: ost, System: *res[0].System})
	code = ""
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}
	st := &config.State{ServerURL: srv, DeviceID: resp.DeviceID, DeviceToken: resp.DeviceToken, TokenExpiresAt: resp.TokenExpiresAt, OrganizationName: resp.OrganizationName, EnrolledAt: time.Now().UTC(),
		HeartbeatIntervalMinutes: resp.Config.HeartbeatIntervalMinutes, PostureIntervalHours: resp.Config.PostureIntervalHours, InventoryIntervalHours: resp.Config.InventoryIntervalHours}
	if err := config.Save(dir, st); err != nil {
		return fmt.Errorf("save state to %s: %w", dir, err)
	}
	fmt.Printf("Enrolled as device %s in organization %q. State saved to %s\n", resp.DeviceID, resp.OrganizationName, dir)
	fmt.Println("Running initial assessment…")
	r := scheduler.New(dir, st)
	if _, err := r.RunAssessment(ctx, "ENROLLMENT", model.AllCollectors, nil); err != nil {
		fmt.Fprintln(os.Stderr, "warning: initial assessment failed; enrollment succeeded and the service will retry:", err)
		return nil
	}
	st.LastPostureAt = time.Now()
	st.LastInventoryAt = time.Now()
	_ = config.Save(dir, st)
	fmt.Println("Initial assessment uploaded. Install the service to keep reporting (see docs/AGENT_INSTALLATION.md).")
	return nil
}

func readEnrollmentCode(r io.Reader) (string, error) {
	const maxCodeBytes = 256
	b, err := io.ReadAll(io.LimitReader(r, maxCodeBytes+1))
	if err != nil {
		return "", fmt.Errorf("read enrollment code: %w", err)
	}
	if len(b) > maxCodeBytes {
		return "", errors.New("enrollment code input is too long")
	}
	code := strings.TrimSpace(string(b))
	if code == "" {
		return "", errors.New("enrollment code input is empty")
	}
	return code, nil
}

func cmdRun(dir string) error {
	logging.SetupFile(dir)
	st, err := config.Load(dir)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	logging.Infof("nextaura-agent %s starting (device %s, server %s)", config.Version, st.DeviceID, st.ServerURL)
	err = scheduler.New(dir, st).Loop(ctx)
	logging.Infof("nextaura-agent stopped")
	return err
}

func parseCollectors(s string) ([]string, error) {
	if s == "" {
		return model.AllCollectors, nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToUpper(strings.TrimSpace(p))
		if !model.IsKnownCollector(p) {
			return nil, fmt.Errorf("unknown collector %q; valid: %s", p, strings.Join(model.AllCollectors, ","))
		}
		out = append(out, p)
	}
	return out, nil
}

func cmdAssess(dir string, args []string, upload bool) error {
	fs := flag.NewFlagSet("assess", flag.ExitOnError)
	cols := fs.String("collectors", "", "comma-separated collector IDs (default all)")
	fs.Parse(args)
	ids, err := parseCollectors(*cols)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if !upload {
		res, err := collectors.Run(ctx, ids, 3*time.Minute)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	st, err := config.Load(dir)
	if err != nil {
		return err
	}
	resp, err := scheduler.New(dir, st).RunAssessment(ctx, "MANUAL", ids, nil)
	if err != nil {
		return err
	}
	fmt.Printf("Assessment %s uploaded (coverage %d%%)\n", resp.AssessmentID, resp.CoveragePercent)
	return nil
}

func cmdStatus(dir string) error {
	st, err := config.Load(dir)
	if errors.Is(err, config.ErrNotEnrolled) {
		fmt.Println("Not enrolled. State directory:", dir)
		return nil
	}
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(st.Redacted())
}

func cmdInspectFile(args []string) error {
	fs := flag.NewFlagSet("inspect-file", flag.ContinueOnError)
	path := fs.String("path", "", "file to inspect")
	root := fs.String("approved-root", "", "administrator-approved root containing the file")
	hashFeed := fs.String("hash-feed", "", "optional approved local JSON hash intelligence map")
	rulesFile := fs.String("rules", "", "optional approved local JSON offline pattern rules")
	maxMB := fs.Int64("max-file-mb", 128, "maximum file size to inspect (1-512 MiB)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *root == "" {
		return errors.New("--path and --approved-root are required")
	}
	if *maxMB < 1 || *maxMB > 512 {
		return errors.New("--max-file-mb must be between 1 and 512")
	}
	opts := fileanalysis.Options{ApprovedRoot: *root, Limits: fileanalysis.DefaultLimits()}
	opts.Limits.MaxFileBytes = *maxMB << 20
	if *hashFeed != "" {
		opts.HashIntelligence = map[string]fileanalysis.HashIntelligence{}
		if err := decodeBoundedJSON(*hashFeed, &opts.HashIntelligence); err != nil {
			return fmt.Errorf("hash feed: %w", err)
		}
	}
	if *rulesFile != "" {
		if err := decodeBoundedJSON(*rulesFile, &opts.Patterns); err != nil {
			return fmt.Errorf("rules: %w", err)
		}
		if len(opts.Patterns) > 50 {
			return errors.New("rules file exceeds the 50-rule limit")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := fileanalysis.Analyze(ctx, *path, opts)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func decodeBoundedJSON(path string, target interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	limited := io.LimitReader(f, (2<<20)+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(b) > 2<<20 {
		return errors.New("JSON input exceeds 2 MiB")
	}
	if err := json.Unmarshal(b, target); err != nil {
		return err
	}
	return nil
}
