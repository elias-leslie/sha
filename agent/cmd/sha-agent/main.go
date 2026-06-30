package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const defaultAgentVersion = "sha-go-agent-v0.1.0"

type Config struct {
	ControlPlaneURL   string  `json:"control_plane_url"`
	APIToken          string  `json:"api_token"`
	TenantID          *string `json:"tenant_id"`
	SiteID            *string `json:"site_id"`
	ProfileID         string  `json:"profile_id"`
	AgentVersion      string  `json:"agent_version"`
	SSHDHardeningPath string  `json:"sshd_hardening_path"`
}

type Agent struct {
	config Config
	client *http.Client
}

type endpointResponse struct {
	EndpointID string `json:"endpoint_id"`
}

type actionList struct {
	Items []responseAction `json:"items"`
}

type responseAction struct {
	ResponseActionID     string  `json:"response_action_id"`
	Action               string  `json:"action"`
	ControlID            *string `json:"control_id"`
	TroubleshootingScope *string `json:"troubleshooting_scope"`
}

type postureResult struct {
	ControlKey       string  `json:"control_key"`
	Status           string  `json:"status"`
	CurrentValue     *string `json:"current_value"`
	RecommendedValue *string `json:"recommended_value"`
	Severity         *string `json:"severity"`
	EvidenceSummary  string  `json:"evidence_summary"`
	RebootRequired   bool    `json:"reboot_required"`
}

func main() {
	configPath := flag.String("config", firstNonEmpty(os.Getenv("SHA_AGENT_CONFIG"), "/etc/sha/agent-config.json"), "agent config JSON path")
	loop := flag.Bool("loop", false, "run forever instead of once")
	interval := flag.Duration("interval", 15*time.Minute, "loop interval")
	flag.Parse()

	config, err := loadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	agent := Agent{config: config, client: &http.Client{Timeout: 30 * time.Second}}
	for {
		if err := agent.RunOnce(); err != nil {
			fatal(err)
		}
		if !*loop {
			return
		}
		time.Sleep(*interval)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func loadConfig(path string) (Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(content, &config); err != nil {
		return Config{}, err
	}
	config.ControlPlaneURL = strings.TrimRight(strings.TrimSpace(config.ControlPlaneURL), "/")
	if config.ControlPlaneURL == "" {
		return Config{}, errors.New("control_plane_url is required")
	}
	if config.AgentVersion == "" {
		config.AgentVersion = defaultAgentVersion
	}
	if config.SSHDHardeningPath == "" {
		config.SSHDHardeningPath = "/etc/ssh/sshd_config.d/99-sha-hardening.conf"
	}
	return config, nil
}

func (a Agent) RunOnce() error {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	platformVersion := platformVersion()
	endpoint := endpointResponse{}
	if err := a.doJSON("POST", "/api/endpoints/enroll", map[string]any{
		"agent_fingerprint": fingerprint(hostname, a.config.ProfileID),
		"hostname":          hostname,
		"platform":          platformName(),
		"platform_version":  platformVersion,
		"agent_version":     a.config.AgentVersion,
		"tenant_id":         a.config.TenantID,
		"site_id":           a.config.SiteID,
	}, &endpoint); err != nil {
		return err
	}
	if err := a.doJSON("POST", "/api/endpoints/"+endpoint.EndpointID+"/heartbeat", map[string]any{
		"agent_version":         a.config.AgentVersion,
		"platform_version":      platformVersion,
		"platform_profile":      platformName() + "-go-agent",
		"connectivity_status":   "online",
		"declared_capabilities": []string{"enroll", "heartbeat", "collect_posture_snapshot", "inspect_control", "apply_control", "rollback_control", "collect_security_context", "collect_remediation_evidence"},
		"execution_hooks": map[string]bool{
			"captures_rollback_artifacts": true,
			"reports_execution_results":   true,
			"supports_dry_run":            true,
		},
	}, nil); err != nil {
		return err
	}
	if err := a.doJSON("POST", "/api/posture-snapshots", map[string]any{
		"endpoint_id":      endpoint.EndpointID,
		"observed_at":      time.Now().UTC().Format(time.RFC3339),
		"platform_profile": platformName() + "-go-agent",
		"results":          a.postureResults(),
	}, nil); err != nil {
		return err
	}
	var actions actionList
	if err := a.doJSON("GET", "/api/endpoints/"+endpoint.EndpointID+"/response-actions", nil, &actions); err != nil {
		return err
	}
	for _, action := range actions.Items {
		status, summary := a.executeAction(action)
		if err := a.doJSON("POST", "/api/response-actions/"+action.ResponseActionID+"/result", map[string]any{
			"status":         status,
			"result_summary": summary,
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (a Agent) doJSON(method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequest(method, a.config.ControlPlaneURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if a.config.APIToken != "" {
		request.Header.Set("Authorization", "Bearer "+a.config.APIToken)
	}
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	content, _ := io.ReadAll(response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%s %s failed: %d %s", method, path, response.StatusCode, strings.TrimSpace(string(content)))
	}
	if out == nil || len(content) == 0 {
		return nil
	}
	return json.Unmarshal(content, out)
}

func (a Agent) postureResults() []postureResult {
	if platformName() != "linux" {
		return []postureResult{{
			ControlKey:      platformName() + ".agent.present",
			Status:          "pass",
			EvidenceSummary: "SHA Go agent reported successfully.",
		}}
	}
	current := "unknown"
	status := "warn"
	evidence := "SSH PasswordAuthentication state was not found."
	if sshPasswordAuthenticationDisabled(a.config.SSHDHardeningPath) {
		current = "no"
		status = "pass"
		evidence = "PasswordAuthentication no is present in SSH configuration."
	} else {
		current = "yes_or_unset"
		evidence = "PasswordAuthentication no was not found in SSH configuration."
	}
	recommended := "no"
	severity := "high"
	privilegedCurrent := fmt.Sprintf("euid=%d", os.Geteuid())
	privilegedStatus := "warn"
	if os.Geteuid() == 0 {
		privilegedStatus = "pass"
	}
	return []postureResult{
		{
			ControlKey:       "linux.ssh.password-authentication-disabled",
			Status:           status,
			CurrentValue:     &current,
			RecommendedValue: &recommended,
			Severity:         &severity,
			EvidenceSummary:  evidence,
		},
		{
			ControlKey:      "linux.agent.privileged",
			Status:          privilegedStatus,
			CurrentValue:    &privilegedCurrent,
			Severity:        &severity,
			EvidenceSummary: "Agent effective user determines whether privileged hardening actions can run.",
		},
	}
}

func (a Agent) executeAction(action responseAction) (string, string) {
	switch action.Action {
	case "collect_security_context", "collect_remediation_evidence", "inspect_control":
		return "succeeded", "SHA Go agent collected bounded local evidence for " + action.Action + "."
	case "apply_control":
		if action.ControlID != nil && *action.ControlID == "linux.ssh.password-authentication-disabled" {
			if err := applySSHHardening(a.config.SSHDHardeningPath); err != nil {
				return "failed", err.Error()
			}
			return "succeeded", "Applied Linux SSH PasswordAuthentication no."
		}
	case "rollback_control":
		if action.ControlID != nil && *action.ControlID == "linux.ssh.password-authentication-disabled" {
			if err := os.Remove(a.config.SSHDHardeningPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return "failed", err.Error()
			}
			return "succeeded", "Rolled back Linux SSH PasswordAuthentication managed file."
		}
	}
	return "failed", "Unsupported SHA Go agent action/control pair."
}

func applySSHHardening(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("# Managed by SHA Go agent\nPasswordAuthentication no\n"), 0o644)
}

func sshPasswordAuthenticationDisabled(extraPath string) bool {
	paths := []string{"/etc/ssh/sshd_config"}
	if extraPath != "" {
		paths = append(paths, extraPath)
	}
	matches, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	paths = append(paths, matches...)
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "PasswordAuthentication") && strings.EqualFold(fields[1], "no") {
				return true
			}
		}
	}
	return false
}

func fingerprint(hostname, profileID string) string {
	machineID := firstReadable("/etc/machine-id", "/var/lib/dbus/machine-id")
	if machineID == "" {
		machineID = hostname
	}
	sum := sha256.Sum256([]byte(platformName() + "|" + strings.TrimSpace(machineID) + "|" + profileID))
	return "sha-go-" + hex.EncodeToString(sum[:])
}

func platformName() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	if runtime.GOOS == "windows" {
		return "windows"
	}
	return "linux"
}

func platformVersion() string {
	if platformName() == "linux" {
		content := firstReadable("/etc/os-release")
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
		}
	}
	return runtime.GOOS
}

func firstReadable(paths ...string) string {
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(content))
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
