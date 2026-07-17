package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunAgentLoopRetriesWithBoundedBackoffAndRecovers(t *testing.T) {
	cycleError := errors.New("control plane unavailable")
	stopError := errors.New("test loop complete")
	attempts := 0
	reported := 0
	interval := 17 * time.Minute
	var waits []time.Duration
	intervalWaits := 0

	err := runAgent(
		context.Background(),
		true,
		interval,
		func() error {
			attempts++
			if attempts == 9 || attempts == 11 {
				return nil
			}
			return cycleError
		},
		func(_ context.Context, delay time.Duration) error {
			waits = append(waits, delay)
			if delay == interval {
				intervalWaits++
				if intervalWaits == 2 {
					return stopError
				}
			}
			return nil
		},
		func(err error) {
			if !errors.Is(err, cycleError) {
				t.Fatalf("unexpected reported error: %v", err)
			}
			reported++
		},
	)
	if !errors.Is(err, stopError) {
		t.Fatalf("loop returned %v, want test stop error", err)
	}
	if attempts != 11 || reported != 9 {
		t.Fatalf("attempts=%d reported=%d, want attempts=11 reported=9", attempts, reported)
	}
	wantWaits := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		maximumLoopRetryDelay,
		maximumLoopRetryDelay,
		interval,
		initialLoopRetryDelay,
		interval,
	}
	if len(waits) != len(wantWaits) {
		t.Fatalf("waits=%v, want %v", waits, wantWaits)
	}
	for index := range wantWaits {
		if waits[index] != wantWaits[index] {
			t.Fatalf("wait %d=%s, want %s; all waits=%v", index, waits[index], wantWaits[index], waits)
		}
	}
}

func TestRunAgentOneShotReturnsCycleFailureWithoutRetry(t *testing.T) {
	cycleError := errors.New("control plane unavailable")
	waited := false
	reported := false
	err := runAgent(
		context.Background(),
		false,
		time.Minute,
		func() error { return cycleError },
		func(context.Context, time.Duration) error {
			waited = true
			return nil
		},
		func(error) { reported = true },
	)
	if !errors.Is(err, cycleError) {
		t.Fatalf("one-shot returned %v, want cycle failure", err)
	}
	if waited || reported {
		t.Fatalf("one-shot retried or reported retry: waited=%t reported=%t", waited, reported)
	}
}

func TestLinuxAgentRejectsStaleMutationWithoutFilesystemOrCommandChanges(t *testing.T) {
	tmp := t.TempDir()
	hardeningPath := filepath.Join(tmp, "99-sha-hardening.conf")
	completed := false
	restorePlatform := currentPlatformName
	restoreRunCommand := runCommand
	currentPlatformName = func() string { return "linux" }
	runCommand = func(name string, args ...string) (string, error) {
		t.Fatalf("unsupported Linux mutation invoked command %s %#v", name, args)
		return "", nil
	}
	t.Cleanup(func() {
		currentPlatformName = restorePlatform
		runCommand = restoreRunCommand
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agent-token" {
			t.Fatalf("missing auth header on %s", r.URL.Path)
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/endpoints/enroll":
			writeJSON(w, endpointResponse{EndpointID: "ep_test"})
		case r.Method == "POST" && r.URL.Path == "/api/endpoints/ep_test/heartbeat":
			var payload struct {
				DeclaredCapabilities []string        `json:"declared_capabilities"`
				ExecutionHooks       map[string]bool `json:"execution_hooks"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if strings.Join(payload.DeclaredCapabilities, ",") != "enroll,heartbeat,collect_posture_snapshot,rollback_control:linux.ssh.password-authentication-disabled" {
				t.Fatalf("unexpected Linux capabilities: %#v", payload.DeclaredCapabilities)
			}
			if payload.ExecutionHooks["supports_dry_run"] || payload.ExecutionHooks["captures_rollback_artifacts"] {
				t.Fatalf("dishonest Linux execution hooks: %#v", payload.ExecutionHooks)
			}
			writeJSON(w, map[string]any{"pending_action_count": 1})
		case r.Method == "POST" && r.URL.Path == "/api/posture-snapshots":
			writeJSON(w, map[string]any{"accepted_result_count": 2})
		case r.Method == "POST" && r.URL.Path == "/api/endpoints/ep_test/response-actions/claim":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if len(payload) != 0 {
				t.Fatalf("unexpected claim payload: %#v", payload)
			}
			controlID := "linux.ssh.password-authentication-disabled"
			writeJSON(w, actionList{Items: []responseAction{{ResponseActionID: "act_test", Action: "apply_control", ControlID: &controlID, LeaseToken: "lease-token-with-at-least-thirty-two-bytes"}}})
		case r.Method == "POST" && r.URL.Path == "/api/response-actions/act_test/result":
			var payload struct {
				Status     string `json:"status"`
				Summary    string `json:"result_summary"`
				LeaseToken string `json:"lease_token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload.Status != "failed" || !strings.Contains(payload.Summary, "no mutation was attempted") || payload.LeaseToken != "lease-token-with-at-least-thirty-two-bytes" {
				t.Fatalf("unexpected result: %#v", payload)
			}
			completed = true
			writeJSON(w, map[string]any{"status": "failed"})
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
	if _, err := os.Stat(hardeningPath); !os.IsNotExist(err) {
		t.Fatalf("unsupported Linux mutation touched hardening path: %v", err)
	}
	if !completed {
		t.Fatal("failed action result was not posted")
	}
}

func TestLinuxLegacySSHRollbackRemovesOnlyExactHistoricalPayload(t *testing.T) {
	restorePlatform := currentPlatformName
	currentPlatformName = func() string { return "linux" }
	t.Cleanup(func() { currentPlatformName = restorePlatform })

	path := filepath.Join(t.TempDir(), "99-sha-hardening.conf")
	if err := os.WriteFile(path, []byte(legacyGoSSHHardeningPayload), 0o644); err != nil {
		t.Fatal(err)
	}
	controlID := linuxLegacySSHControlID
	status, summary := (Agent{config: Config{SSHDHardeningPath: path}}).executeAction(
		responseAction{Action: "rollback_control", ControlID: &controlID},
	)
	if status != "succeeded" || !strings.Contains(summary, "exact legacy") {
		t.Fatalf("unexpected rollback result: %q %q", status, summary)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("exact legacy payload was not removed: %v", err)
	}
}

func TestLinuxLegacySSHRollbackRefusesAlteredPayloadWithoutMutation(t *testing.T) {
	restorePlatform := currentPlatformName
	restoreRunCommand := runCommand
	currentPlatformName = func() string { return "linux" }
	runCommand = func(name string, args ...string) (string, error) {
		t.Fatalf("legacy rollback invoked command %s %#v", name, args)
		return "", nil
	}
	t.Cleanup(func() {
		currentPlatformName = restorePlatform
		runCommand = restoreRunCommand
	})

	path := filepath.Join(t.TempDir(), "99-sha-hardening.conf")
	altered := legacyGoSSHHardeningPayload + "PermitRootLogin no\n"
	if err := os.WriteFile(path, []byte(altered), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	controlID := linuxLegacySSHControlID
	status, summary := (Agent{config: Config{SSHDHardeningPath: path}}).executeAction(
		responseAction{Action: "rollback_control", ControlID: &controlID},
	)
	if status != "failed" || !strings.Contains(summary, "does not exactly match") {
		t.Fatalf("unexpected refusal result: %q %q", status, summary)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != altered {
		t.Fatalf("refused rollback mutated content: %q", content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("refused rollback mutated mode: %o", info.Mode().Perm())
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
	if len(commands) != 1 || !strings.Contains(commands[0], "icacls.exe") || !strings.Contains(commands[0], "Refusing to overwrite existing SHA firewall rollback artifact") || !strings.Contains(commands[0], "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True") {
		t.Fatalf("unexpected apply command: %#v", commands)
	}

	status, summary = agent.executeAction(responseAction{Action: "rollback_control", ControlID: &controlID})
	if status != "succeeded" {
		t.Fatalf("unexpected rollback status %q: %s", status, summary)
	}
	if len(commands) != 2 || !strings.Contains(commands[1], "SHA firewall rollback artifact has an untrusted owner") || !strings.Contains(commands[1], "$profile.Enabled -isnot [bool]") {
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
	if results[0].ControlKey != windowsFirewallControlID || results[0].Status != "pass" {
		t.Fatalf("unexpected windows posture: %#v", results)
	}
}

func TestPlatformCapabilitiesAndExecutionHooksAreTruthful(t *testing.T) {
	restorePlatform := currentPlatformName
	t.Cleanup(func() { currentPlatformName = restorePlatform })

	tests := []struct {
		platform     string
		capabilities string
		rollback     bool
	}{
		{platform: "linux", capabilities: "enroll,heartbeat,collect_posture_snapshot,rollback_control:linux.ssh.password-authentication-disabled", rollback: false},
		{platform: "macos", capabilities: "enroll,heartbeat,collect_posture_snapshot", rollback: false},
		{platform: "windows", capabilities: "enroll,heartbeat,collect_posture_snapshot,apply_control:control.windows.firewall-all-profiles,rollback_control:control.windows.firewall-all-profiles", rollback: true},
	}
	for _, test := range tests {
		t.Run(test.platform, func(t *testing.T) {
			currentPlatformName = func() string { return test.platform }
			if got := strings.Join(declaredCapabilities(), ","); got != test.capabilities {
				t.Fatalf("unexpected capabilities %q", got)
			}
			hooks := executionHooks()
			if hooks["supports_dry_run"] {
				t.Fatal("Go agent must not claim dry-run support")
			}
			if hooks["captures_rollback_artifacts"] != test.rollback {
				t.Fatalf("unexpected rollback-artifact hook: %#v", hooks)
			}
			if !hooks["reports_execution_results"] {
				t.Fatalf("unexpected execution-result hook: %#v", hooks)
			}
		})
	}
}

func TestStaleEvidenceActionFailsWithoutCollectingEvidence(t *testing.T) {
	restorePlatform := currentPlatformName
	restoreRunCommand := runCommand
	currentPlatformName = func() string { return "macos" }
	runCommand = func(name string, args ...string) (string, error) {
		t.Fatalf("unsupported evidence action invoked command %s %#v", name, args)
		return "", nil
	}
	t.Cleanup(func() {
		currentPlatformName = restorePlatform
		runCommand = restoreRunCommand
	})

	for _, action := range []string{"collect_security_context", "collect_remediation_evidence", "inspect_control"} {
		status, summary := (Agent{}).executeAction(responseAction{Action: action})
		if status != "failed" || !strings.Contains(summary, "no evidence was collected") {
			t.Fatalf("unexpected stale %s result: %q %q", action, status, summary)
		}
	}
}

func TestMacOSPostureReportsCoreObserveChecks(t *testing.T) {
	restorePlatform := currentPlatformName
	restoreRunCommand := runCommand
	currentPlatformName = func() string { return "macos" }
	runCommand = func(name string, args ...string) (string, error) {
		switch name {
		case "/usr/libexec/ApplicationFirewall/socketfilterfw":
			return "Firewall is enabled. (State = 1)\n", nil
		case "fdesetup":
			return "FileVault is On.\n", nil
		case "spctl":
			return "assessments enabled\n", nil
		default:
			t.Fatalf("unexpected command %s %#v", name, args)
			return "", nil
		}
	}
	t.Cleanup(func() {
		currentPlatformName = restorePlatform
		runCommand = restoreRunCommand
	})

	results := (Agent{}).postureResults()
	want := []string{
		"macos.firewall.application-firewall-enabled",
		"macos.disk.filevault-enabled",
		"macos.gatekeeper.assessments-enabled",
		"macos.agent.present",
	}
	if len(results) != len(want) {
		t.Fatalf("unexpected macOS result count: %#v", results)
	}
	for i, controlKey := range want {
		if results[i].ControlKey != controlKey || results[i].Status != "pass" {
			t.Fatalf("unexpected macOS result %d: %#v", i, results[i])
		}
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(err)
	}
}
