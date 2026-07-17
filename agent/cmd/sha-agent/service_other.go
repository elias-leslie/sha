//go:build !windows

package main

import (
	"errors"
	"time"
)

func runWindowsService(_ *Agent, _ time.Duration) error {
	return errors.New("service action is available only under the Windows Service Control Manager; use -action run interactively")
}
