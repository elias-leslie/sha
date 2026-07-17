//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateStorePersistsPrivateValidatedStateAtomically(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent-state.json")
	store, err := newStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	state := testCompletedDeviceState()
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode=%04o, want 0600", info.Mode().Perm())
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.InstallationID != state.InstallationID ||
		loaded.EndpointID != state.EndpointID ||
		loaded.Credential != state.Credential {
		t.Fatal("loaded state did not match saved state")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "agent-state.json" {
		t.Fatalf("atomic save left unexpected files: %#v", entries)
	}

	invalid := *state
	invalid.EndpointID = "invalid"
	if err := store.Save(&invalid); err == nil {
		t.Fatal("invalid replacement unexpectedly succeeded")
	}
	reloaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.EndpointID != state.EndpointID {
		t.Fatal("failed replacement changed durable state")
	}
}

func TestStateStoreRejectsPermissiveDirectoryAndSymlinks(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "agent-state.json")
	store, err := newStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(testCompletedDeviceState()); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("permissive directory error=%v, want 0700 refusal", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	realDirectory := filepath.Join(directory, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkDirectory := filepath.Join(directory, "link")
	if err := os.Symlink(realDirectory, symlinkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := newStateStore(filepath.Join(symlinkDirectory, "state.json")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink directory error=%v, want refusal", err)
	}

	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkFile := filepath.Join(directory, "state-link.json")
	if err := os.Symlink(target, symlinkFile); err != nil {
		t.Fatal(err)
	}
	if _, err := newStateStore(symlinkFile); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink file error=%v, want refusal", err)
	}
}

func TestStateStoreRejectsPermissiveFileAndOversizedContent(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent-state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := newStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("permissive file error=%v, want 0600 refusal", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, maximumStateFileBytes+1)
	if err := os.WriteFile(path, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized file error=%v, want bounded-read refusal", err)
	}
}

func TestClearBootstrapCredentialsRewritesPrivateConfigWithoutSecrets(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent-config.json")
	token := testEnrollmentToken()
	content, err := json.Marshal(map[string]any{
		"control_plane_url": "https://sha.example.test",
		"enrollment_token":  token,
		"api_token":         "legacy-shared-agent-token",
		"profile_id":        "linux-prod",
		"unknown_setting":   map[string]any{"preserved": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := clearBootstrapCredentialsFromConfig(path); err != nil {
		t.Fatal(err)
	}
	rewritten, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rewritten), token) ||
		strings.Contains(string(rewritten), "enrollment_token") ||
		strings.Contains(string(rewritten), "legacy-shared-agent-token") ||
		strings.Contains(string(rewritten), "api_token") {
		t.Fatal("bootstrap credential remains in rewritten config")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rewritten, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["unknown_setting"]; !ok {
		t.Fatal("config rewrite dropped an unknown setting")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("rewritten config mode=%04o, want 0600", info.Mode().Perm())
	}
}

func TestMissingStatePreservesNotExistClassification(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := newStateStore(filepath.Join(directory, "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing state error=%v, want os.ErrNotExist", err)
	}
}
