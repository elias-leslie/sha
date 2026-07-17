//go:build windows

package main

import "os"

func validateCABundleFileSecurity(path string, _ os.FileInfo) error {
	return validateWindowsPrivateACL(path, false)
}
