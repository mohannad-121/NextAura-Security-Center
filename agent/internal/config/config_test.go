package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAtomicallyReplacesExistingState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	first := &State{ServerURL: "https://security.example.com", DeviceID: "device-1", DeviceToken: "nxa_first", EnrolledAt: time.Now()}
	if err := Save(dir, first); err != nil {
		t.Fatal(err)
	}
	second := *first
	second.DeviceToken = "nxa_second"
	second.HeartbeatIntervalMinutes = 17
	if err := Save(dir, &second); err != nil {
		t.Fatalf("replace existing state: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DeviceToken != "nxa_second" || loaded.HeartbeatIntervalMinutes != 17 {
		t.Fatalf("state replacement was not persisted: %#v", loaded.Redacted())
	}
}
