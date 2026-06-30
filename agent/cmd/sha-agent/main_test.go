package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestAgentCompletesWindowsFirewallAction(t *testing.T) {
	restorePlatform := currentPlatformName
	restoreRunCommand := runCommand
	currentPlatformName = func() string { return "windows" }
	var commands []string
	runCommand = func(name string, args ...string) (string, error) {
		commands = append(commands, name+" "+args[len(args)-1])
		return "", nil
	}
	t.Cleanup(func() {
		currentPlatformName = restorePlatform
		runCommand = restoreRunCommand
	})

	controlID := "control.windows.firewall-all-profiles"
	agent := Agent{config: Config{WindowsFirewallRollbackPath: `C:\ProgramData\SHA\firewall.json`}}
	status, summary := agent.executeAction(responseAction{Action: "apply_control", ControlID: &controlID})
	if status != "succeeded" {
		t.Fatalf("unexpected status %q: %s", status, summary)
	}
	if len(commands) != 1 || !strings.Contains(commands[0], "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True") {
		t.Fatalf("unexpected apply command: %#v", commands)
	}

	status, summary = agent.executeAction(responseAction{Action: "rollback_control", ControlID: &controlID})
	if status != "succeeded" {
		t.Fatalf("unexpected rollback status %q: %s", status, summary)
	}
	if len(commands) != 2 || !strings.Contains(commands[1], "Set-NetFirewallProfile -Profile ([string]$profile.Name) -Enabled ([bool]$profile.Enabled)") {
		t.Fatalf("unexpected rollback command: %#v", commands)
	}
}

func TestWindowsPostureReportsFirewallState(t *testing.T) {
	restorePlatform := currentPlatformName
	restoreRunCommand := runCommand
	currentPlatformName = func() string { return "windows" }
	runCommand = func(name string, args ...string) (string, error) {
		return "enabled\n", nil
	}
	t.Cleanup(func() {
		currentPlatformName = restorePlatform
		runCommand = restoreRunCommand
	})

	results := (Agent{}).postureResults()
	if results[0].ControlKey != "windows.firewall.all-profiles-enabled" || results[0].Status != "pass" {
		t.Fatalf("unexpected windows posture: %#v", results)
	}
}

func TestMacOSAgentDeclaresObserveOnlyCapabilities(t *testing.T) {
	restorePlatform := currentPlatformName
	currentPlatformName = func() string { return "macos" }
	t.Cleanup(func() { currentPlatformName = restorePlatform })

	for _, capability := range declaredCapabilities() {
		if capability == "apply_control" || capability == "rollback_control" {
			t.Fatalf("macOS Go agent must not declare hardening mutation capability: %#v", declaredCapabilities())
		}
	}
	if executionHooks()["captures_rollback_artifacts"] {
		t.Fatal("macOS observe-only agent must not claim rollback artifacts")
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(err)
	}
}
