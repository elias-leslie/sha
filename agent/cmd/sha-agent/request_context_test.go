package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAgentRequestContextCancelsInFlightHTTP(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		select {
		case <-request.Context().Done():
		case <-releaseHandler:
		}
	}))
	t.Cleanup(func() {
		close(releaseHandler)
		server.CloseClientConnections()
		server.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	agent := Agent{
		config: Config{ControlPlaneURL: server.URL},
		client: server.Client(),
	}
	result := make(chan error, 1)
	go func() {
		result <- agent.runWithContext(ctx, func() error {
			return agent.doJSON(http.MethodPost, "/cancel", map[string]string{"status": "test"}, nil)
		})
	}()

	select {
	case <-requestStarted:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP request did not reach test server")
	}

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled HTTP request returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP request did not stop after context cancellation")
	}
}
