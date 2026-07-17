//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris || windows)

package main

import "os"

func validateCABundleFileSecurity(_ string, _ os.FileInfo) error {
	return nil
}
