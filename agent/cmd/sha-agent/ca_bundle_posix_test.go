//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCABundleRejectsSymlinkAndNonRegularPath(t *testing.T) {
	directory := t.TempDir()
	bundlePath := filepath.Join(directory, "private-ca.pem")
	if err := os.WriteFile(bundlePath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "private-ca-link.pem")
	if err := os.Symlink(bundlePath, symlinkPath); err != nil {
		t.Fatal(err)
	}

	if _, err := readValidatedCABundle(symlinkPath); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("unexpected symlink error: %v", err)
	}
	if _, err := readValidatedCABundle(directory); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("unexpected directory error: %v", err)
	}
}

func TestCABundleRejectsGroupOrWorldWritableFile(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "private-ca.pem")
	if err := os.WriteFile(bundlePath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bundlePath, 0o620); err != nil {
		t.Fatal(err)
	}

	if _, err := readValidatedCABundle(bundlePath); err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("unexpected writable-file error: %v", err)
	}
}

func TestCABundleRejectsUntrustedOwnerWhenRunningAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires root")
	}
	bundlePath := filepath.Join(t.TempDir(), "private-ca.pem")
	if err := os.WriteFile(bundlePath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(bundlePath, 1, -1); err != nil {
		t.Fatal(err)
	}

	if _, err := readValidatedCABundle(bundlePath); err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Fatalf("unexpected owner error: %v", err)
	}
}
