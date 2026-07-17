//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func encodeStatePayload(content []byte) ([]byte, error) {
	return append([]byte(nil), content...), nil
}

func decodeStatePayload(content []byte) ([]byte, error) {
	return append([]byte(nil), content...), nil
}

func platformValidatePrivateDirectory(_ string, info os.FileInfo) error {
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("private directory permissions must be 0700, found %04o", info.Mode().Perm())
	}
	return validatePrivateOwner(info, "directory")
}

func platformValidatePrivateFile(_ string, info os.FileInfo) error {
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("private file permissions must be 0600, found %04o", info.Mode().Perm())
	}
	return validatePrivateOwner(info, "file")
}

func validatePrivateOwner(info os.FileInfo, label string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("private %s ownership could not be verified", label)
	}
	ownerUID := int(stat.Uid)
	effectiveUID := os.Geteuid()
	if ownerUID != 0 && ownerUID != effectiveUID {
		return fmt.Errorf(
			"private %s must be owned by root or the agent effective user (owner uid %d, effective uid %d)",
			label,
			ownerUID,
			effectiveUID,
		)
	}
	return nil
}

func platformProtectPrivateDirectory(_ string) error {
	// The installer creates and owns the dedicated 0700 directory. Validation
	// above intentionally refuses to chmod an arbitrary configured directory.
	return nil
}

func platformProtectPrivateFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set private file permissions: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect protected private file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("protected private file is not a regular, non-symlink file")
	}
	return platformValidatePrivateFile(path, info)
}

func platformReplacePrivateFile(source, destination string) error {
	return os.Rename(source, destination)
}

func platformSyncPrivateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open private directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync private directory: %w", err)
	}
	return nil
}

func platformRejectReparsePathComponents(_ string) error {
	return nil
}
