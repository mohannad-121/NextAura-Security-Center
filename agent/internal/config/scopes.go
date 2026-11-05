package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ScanScope is local policy. Root is never transmitted to the server.
type ScanScope struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Root      string    `json:"root"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

type ScanScopeSummary struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
}

func scopePath(dir string) string { return filepath.Join(dir, "scopes.json") }

func LoadScopes(dir string) ([]ScanScope, error) {
	b, err := os.ReadFile(scopePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return []ScanScope{}, nil
	}
	if err != nil {
		return nil, err
	}
	var scopes []ScanScope
	if err := json.Unmarshal(b, &scopes); err != nil {
		return nil, fmt.Errorf("corrupt scope configuration: %w", err)
	}
	return scopes, nil
}

func SaveScopes(dir string, scopes []ScanScope) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(scopes, "", "  ")
	if err != nil {
		return err
	}
	tmp := scopePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return replaceFile(tmp, scopePath(dir))
}

func AddScope(dir, label, root string, allowPersonal bool) (*ScanScope, error) {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 120 {
		return nil, errors.New("scope label must be between 1 and 120 characters")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve scope root: %w", err)
	}
	info, err := os.Stat(real)
	if err != nil || !info.IsDir() {
		return nil, errors.New("scope root must be an existing directory")
	}
	if filepath.Dir(real) == real {
		return nil, errors.New("a filesystem or volume root cannot be approved as a scan scope")
	}
	if !allowPersonal && isPersonalRoot(real) {
		return nil, errors.New("personal directories are excluded by default; review the scope and pass --include-personal only with explicit authorization")
	}
	scopes, err := LoadScopes(dir)
	if err != nil {
		return nil, err
	}
	for _, scope := range scopes {
		if samePath(scope.Root, real) && scope.Enabled {
			return nil, errors.New("an enabled scope already exists for this root")
		}
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	scope := ScanScope{ID: "scope_" + hex.EncodeToString(b), Label: label, Root: real, Enabled: true, CreatedAt: time.Now().UTC()}
	scopes = append(scopes, scope)
	if err := SaveScopes(dir, scopes); err != nil {
		return nil, err
	}
	return &scope, nil
}

func RevokeScope(dir, id string) error {
	scopes, err := LoadScopes(dir)
	if err != nil {
		return err
	}
	found := false
	for i := range scopes {
		if scopes[i].ID == id {
			scopes[i].Enabled = false
			found = true
		}
	}
	if !found {
		return errors.New("unknown scope ID")
	}
	return SaveScopes(dir, scopes)
}

func FindScope(dir, id string) (*ScanScope, error) {
	scopes, err := LoadScopes(dir)
	if err != nil {
		return nil, err
	}
	for _, scope := range scopes {
		if scope.ID == id && scope.Enabled {
			return &scope, nil
		}
	}
	return nil, errors.New("unknown or revoked local scope")
}

func ScopeSummaries(dir string) ([]ScanScopeSummary, error) {
	scopes, err := LoadScopes(dir)
	if err != nil {
		return nil, err
	}
	out := make([]ScanScopeSummary, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, ScanScopeSummary{ID: scope.ID, Label: scope.Label, Enabled: scope.Enabled})
	}
	return out, nil
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func isPersonalRoot(root string) bool {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		rel, relErr := filepath.Rel(home, root)
		if relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return true
		}
	}
	lower := strings.ToLower(filepath.ToSlash(root))
	return strings.Contains(lower, "/users/") || strings.HasSuffix(lower, "/users") || strings.Contains(lower, "/home/") || strings.HasSuffix(lower, "/home")
}
