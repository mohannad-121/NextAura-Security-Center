package fileanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScanScopeDoesNotExposePathsAndSkipsSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "invoice.pdf.exe"), []byte("MZsynthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.ps1")
	_ = os.WriteFile(outside, []byte("Write-Host harmless"), 0o600)
	_ = os.Symlink(outside, filepath.Join(root, "escape.ps1"))
	result, err := ScanScope(context.Background(), root, Options{Limits: DefaultLimits()}, ScopeLimits{MaxFiles: 10, MaxDirectories: 10, MaxDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("expected one evidence item, got %d", len(result.Evidence))
	}
	e := result.Evidence[0]
	if e.RelativePathHash == "" || e.Result.FileName != "invoice.pdf.exe" {
		t.Fatalf("unexpected evidence: %#v", e)
	}
}

func TestScanScopeEnforcesFileLimit(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.js", "b.js"} {
		_ = os.WriteFile(filepath.Join(root, name), []byte("const harmless = true"), 0o600)
	}
	result, err := ScanScope(context.Background(), root, Options{}, ScopeLimits{MaxFiles: 1, MaxDirectories: 10, MaxDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial || result.FilesAnalyzed != 1 {
		t.Fatalf("expected bounded partial result: %#v", result)
	}
}
