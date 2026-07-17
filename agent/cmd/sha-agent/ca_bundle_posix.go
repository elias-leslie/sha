//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func validateCABundleFileSecurity(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("ca_bundle_path must not be group- or world-writable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("ca_bundle_path ownership could not be verified")
	}
	ownerUID := int(stat.Uid)
	effectiveUID := os.Geteuid()
	if ownerUID != 0 && ownerUID != effectiveUID {
		return fmt.Errorf(
			"ca_bundle_path must be owned by root or the agent effective user (owner uid %d, effective uid %d)",
			ownerUID,
			effectiveUID,
		)
	}
	return nil
}
