//go:build windows

package main

import "golang.org/x/sys/windows"

func currentPrivilegeContext() string {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "unknown"
	}
	defer token.Close()
	if token.IsElevated() {
		return "elevated"
	}
	return "user"
}
