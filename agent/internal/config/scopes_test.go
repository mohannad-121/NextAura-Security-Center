package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScopeRequiresExistingDirectoryAndRevokes(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "approved")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	scope, err := AddScope(filepath.Join(dir, "state"), "Approved installers", root, true)
	if err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if scope.ID == "" || !samePath(scope.Root, resolvedRoot) {
		t.Fatalf("unexpected scope: %#v", scope)
	}
	if err := RevokeScope(filepath.Join(dir, "state"), scope.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := FindScope(filepath.Join(dir, "state"), scope.ID); err == nil {
		t.Fatal("revoked scope was accepted")
	}
}

func TestScopeDoesNotDuplicateEnabledRoot(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "approved")
	_ = os.Mkdir(root, 0o700)
	state := filepath.Join(dir, "state")
	if _, err := AddScope(state, "one", root, true); err != nil {
		t.Fatal(err)
	}
	if _, err := AddScope(state, "two", root, true); err == nil {
		t.Fatal("duplicate scope was accepted")
	}
}

func TestScopeRejectsFilesystemRoot(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	if root == string(filepath.Separator) {
		root = filepath.Clean(root)
	}
	if _, err := AddScope(filepath.Join(t.TempDir(), "state"), "too broad", root, true); err == nil {
		t.Fatal("filesystem root was accepted")
	}
}
