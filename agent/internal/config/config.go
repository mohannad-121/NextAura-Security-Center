// Package config persists the agent's enrollment state. The device token is
// the only secret and is stored with 0600 permissions in a root/admin-only
// directory. It is never logged.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const Version = "0.1.0"

type State struct {
	ServerURL        string    `json:"serverUrl"`
	DeviceID         string    `json:"deviceId"`
	DeviceToken      string    `json:"deviceToken"`
	TokenExpiresAt   string    `json:"tokenExpiresAt"`
	OrganizationName string    `json:"organizationName"`
	EnrolledAt       time.Time `json:"enrolledAt"`

	HeartbeatIntervalMinutes int `json:"heartbeatIntervalMinutes"`
	PostureIntervalHours     int `json:"postureIntervalHours"`
	InventoryIntervalHours   int `json:"inventoryIntervalHours"`

	LastPostureAt   time.Time `json:"lastPostureAt"`
	LastInventoryAt time.Time `json:"lastInventoryAt"`
}

func DefaultDir() string {
	if v := os.Getenv("NEXTAURA_AGENT_DIR"); v != "" {
		return v
	}
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "NextAura", "Agent")
	case "darwin":
		return "/Library/Application Support/NextAura/Agent"
	default:
		return "/var/lib/nextaura-agent"
	}
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

var ErrNotEnrolled = errors.New("agent is not enrolled")

func Load(dir string) (*State, error) {
	b, err := os.ReadFile(statePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("corrupt state file: %w", err)
	}
	if s.DeviceToken == "" || s.ServerURL == "" {
		return nil, ErrNotEnrolled
	}
	return &s, nil
}

func Save(dir string, s *State) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return replaceFile(tmp, statePath(dir))
}

func Remove(dir string) error {
	err := os.Remove(statePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Redacted returns a copy safe for printing.
func (s State) Redacted() State {
	c := s
	if len(c.DeviceToken) > 8 {
		c.DeviceToken = c.DeviceToken[:8] + "…(redacted)"
	} else {
		c.DeviceToken = "(redacted)"
	}
	return c
}
