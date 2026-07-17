package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDispatchAgentActionPreservesInteractiveRunArguments(t *testing.T) {
	testContext := context.WithValue(context.Background(), struct{}{}, "dispatch-test")
	interval := 23 * time.Minute
	called := false
	err := dispatchAgentAction(
		testContext,
		"run",
		true,
		interval,
		agentActionHandlers{run: func(ctx context.Context, loop bool, receivedInterval time.Duration) error {
			called = true
			if ctx != testContext || !loop || receivedInterval != interval {
				t.Fatalf("run dispatch got ctx=%v loop=%t interval=%s", ctx, loop, receivedInterval)
			}
			return nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("run handler was not called")
	}
}

func TestDispatchAgentActionRoutesStatusAndCredentialRotation(t *testing.T) {
	testContext := context.WithValue(context.Background(), struct{}{}, "dispatch-test")
	for _, action := range []string{"status", "rotate-credential"} {
		t.Run(action, func(t *testing.T) {
			called := false
			handler := func(ctx context.Context) error {
				called = true
				if ctx != testContext {
					t.Fatal("dispatch replaced command context")
				}
				return nil
			}
			handlers := agentActionHandlers{status: handler, rotateCredential: handler}
			if err := dispatchAgentAction(testContext, action, false, time.Minute, handlers); err != nil {
				t.Fatal(err)
			}
			if !called {
				t.Fatalf("%s handler was not called", action)
			}
		})
	}
}

func TestDispatchAgentActionRoutesServiceWithoutInteractiveLoopFlag(t *testing.T) {
	interval := 11 * time.Minute
	called := false
	handlers := agentActionHandlers{service: func(receivedInterval time.Duration) error {
		called = true
		if receivedInterval != interval {
			t.Fatalf("service interval=%s, want %s", receivedInterval, interval)
		}
		return nil
	}}
	if err := dispatchAgentAction(context.Background(), "service", false, interval, handlers); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("service handler was not called")
	}

	called = false
	err := dispatchAgentAction(context.Background(), "service", true, interval, handlers)
	if err == nil || !strings.Contains(err.Error(), "does not accept -loop") {
		t.Fatalf("service with -loop returned %v", err)
	}
	if called {
		t.Fatal("service handler ran despite ambiguous -loop flag")
	}
}

func TestDispatchAgentActionRejectsInvalidActionAndIntervals(t *testing.T) {
	handlers := agentActionHandlers{
		run:     func(context.Context, bool, time.Duration) error { return nil },
		service: func(time.Duration) error { return nil },
	}
	for _, action := range []string{"run", "service"} {
		if err := dispatchAgentAction(context.Background(), action, false, 0, handlers); err == nil || !strings.Contains(err.Error(), "interval") {
			t.Fatalf("%s with invalid interval returned %v", action, err)
		}
	}
	if err := dispatchAgentAction(context.Background(), "shell", false, time.Minute, handlers); err == nil || !strings.Contains(err.Error(), "service") {
		t.Fatalf("invalid action returned %v", err)
	}
}

func TestRunAgentCancellationStopsWithoutRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	retried := false
	waited := false
	err := runAgent(
		ctx,
		true,
		time.Minute,
		func() error {
			cancel()
			return errors.New("cycle interrupted")
		},
		func(context.Context, time.Duration) error {
			waited = true
			return nil
		},
		func(error) { retried = true },
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled loop returned %v", err)
	}
	if retried || waited {
		t.Fatalf("cancelled loop retried=%t waited=%t", retried, waited)
	}
}
