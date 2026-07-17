//go:build !windows

package main

import (
	"strings"
	"testing"
	"time"
)

func TestWindowsServiceActionRefusesNonWindowsRuntime(t *testing.T) {
	err := runWindowsService(&Agent{}, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "Windows Service Control Manager") {
		t.Fatalf("non-Windows service action returned %v", err)
	}
}
