//go:build !windows

package main

import "os"

func currentPrivilegeContext() string {
	if os.Geteuid() == 0 {
		return "elevated"
	}
	return "user"
}
