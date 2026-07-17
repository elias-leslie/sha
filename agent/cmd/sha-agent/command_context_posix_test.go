//go:build !windows

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunCommandWithContextCancelsInFlightCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancelled := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
		close(cancelled)
	}()
	startedAt := time.Now()
	_, err := runCommandWithContext(ctx, "sh", "-c", "exec sleep 30")
	<-cancelled
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled command returned %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 5*time.Second {
		t.Fatalf("cancelled command took %s", elapsed)
	}
}
