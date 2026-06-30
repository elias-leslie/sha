package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentRunOnceCompletesApprovedSSHAction(t *testing.T) {
	tmp := t.TempDir()
	hardeningPath := filepath.Join(tmp, "99-sha-hardening.conf")
	completed := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agent-token" {
			t.Fatalf("missing auth header on %s", r.URL.Path)
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/endpoints/enroll":
			writeJSON(w, endpointResponse{EndpointID: "ep_test"})
		case r.Method == "POST" && r.URL.Path == "/api/endpoints/ep_test/heartbeat":
			writeJSON(w, map[string]any{"pending_action_count": 1})
		case r.Method == "POST" && r.URL.Path == "/api/posture-snapshots":
			writeJSON(w, map[string]any{"accepted_result_count": 2})
		case r.Method == "GET" && r.URL.Path == "/api/endpoints/ep_test/response-actions":
			controlID := "linux.ssh.password-authentication-disabled"
			writeJSON(w, actionList{Items: []responseAction{{ResponseActionID: "act_test", Action: "apply_control", ControlID: &controlID}}})
		case r.Method == "POST" && r.URL.Path == "/api/response-actions/act_test/result":
			var payload struct {
				Status string `json:"status"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload.Status != "succeeded" {
				t.Fatalf("unexpected result status %q", payload.Status)
			}
			completed = true
			writeJSON(w, map[string]any{"status": "succeeded"})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	agent := Agent{
		config: Config{ControlPlaneURL: server.URL, APIToken: "agent-token", ProfileID: "test", SSHDHardeningPath: hardeningPath},
		client: &http.Client{Timeout: 5 * time.Second},
	}
	if err := agent.RunOnce(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(hardeningPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "# Managed by SHA Go agent\nPasswordAuthentication no\n" {
		t.Fatalf("unexpected hardening file: %q", content)
	}
	if !completed {
		t.Fatal("action result was not posted")
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(err)
	}
}
