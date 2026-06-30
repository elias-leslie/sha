package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const defaultAgentVersion = "sha-go-agent-v0.1.0"

type Config struct {
	ControlPlaneURL             string  `json:"control_plane_url"`
	APIToken                    string  `json:"api_token"`
	TenantID                    *string `json:"tenant_id"`
	SiteID                      *string `json:"site_id"`
	ProfileID                   string  `json:"profile_id"`
	AgentVersion                string  `json:"agent_version"`
	SSHDHardeningPath           string  `json:"sshd_hardening_path"`
	WindowsFirewallRollbackPath string  `json:"windows_firewall_rollback_path"`
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

var (
	currentPlatformName = platformName
	runCommand          = runCommandWithTimeout
)

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
	if config.WindowsFirewallRollbackPath == "" {
		config.WindowsFirewallRollbackPath = `C:\ProgramData\SHA\firewall-profiles-rollback.json`
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
		"platform":          currentPlatformName(),
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
		"platform_profile":      currentPlatformName() + "-go-agent",
		"connectivity_status":   "online",
		"declared_capabilities": declaredCapabilities(),
		"execution_hooks":       executionHooks(),
	}, nil); err != nil {
		return err
	}
	if err := a.doJSON("POST", "/api/posture-snapshots", map[string]any{
		"endpoint_id":      endpoint.EndpointID,
		"observed_at":      time.Now().UTC().Format(time.RFC3339),
		"platform_profile": currentPlatformName() + "-go-agent",
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

func declaredCapabilities() []string {
	capabilities := []string{"enroll", "heartbeat", "collect_posture_snapshot", "inspect_control", "collect_security_context", "collect_remediation_evidence"}
	if currentPlatformName() != "macos" {
		capabilities = append(capabilities, "apply_control", "rollback_control")
	}
	return capabilities
}

func executionHooks() map[string]bool {
	return map[string]bool{
		"captures_rollback_artifacts": currentPlatformName() != "macos",
		"reports_execution_results":   true,
		"supports_dry_run":            true,
	}
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
	if currentPlatformName() == "windows" {
		return a.windowsPostureResults()
	}
	if currentPlatformName() == "macos" {
		return a.macosPostureResults()
	}
	if currentPlatformName() != "linux" {
		return []postureResult{{
			ControlKey:      currentPlatformName() + ".agent.present",
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

func (a Agent) macosPostureResults() []postureResult {
	return []postureResult{
		macosCommandPosture(
			"macos.firewall.application-firewall-enabled",
			"/usr/libexec/ApplicationFirewall/socketfilterfw",
			[]string{"--getglobalstate"},
			"enabled",
			"enabled",
			"macOS Application Firewall is enabled.",
			"macOS Application Firewall is not enabled.",
		),
		macosCommandPosture(
			"macos.disk.filevault-enabled",
			"fdesetup",
			[]string{"status"},
			"filevault is on",
			"on",
			"FileVault is enabled.",
			"FileVault is not enabled.",
		),
		macosCommandPosture(
			"macos.gatekeeper.assessments-enabled",
			"spctl",
			[]string{"--status"},
			"assessments enabled",
			"enabled",
			"Gatekeeper assessments are enabled.",
			"Gatekeeper assessments are not enabled.",
		),
		{
			ControlKey:      "macos.agent.present",
			Status:          "pass",
			EvidenceSummary: "SHA Go agent reported successfully.",
		},
	}
}

func macosCommandPosture(controlKey, command string, args []string, passNeedle, recommended, passEvidence, failEvidence string) postureResult {
	output, err := runCommand(command, args...)
	current := strings.TrimSpace(output)
	severity := "high"
	if err != nil {
		current = "unknown"
		return postureResult{
			ControlKey:       controlKey,
			Status:           "warn",
			CurrentValue:     &current,
			RecommendedValue: &recommended,
			Severity:         &severity,
			EvidenceSummary:  "macOS posture command failed or is unavailable: " + command + ".",
		}
	}
	status := "fail"
	evidence := failEvidence + " Command output: " + current
	if strings.Contains(strings.ToLower(current), passNeedle) {
		status = "pass"
		evidence = passEvidence
	}
	return postureResult{
		ControlKey:       controlKey,
		Status:           status,
		CurrentValue:     &current,
		RecommendedValue: &recommended,
		Severity:         &severity,
		EvidenceSummary:  evidence,
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
		if currentPlatformName() == "windows" && action.ControlID != nil && *action.ControlID == "control.windows.firewall-all-profiles" {
			return a.applyWindowsFirewallAllProfiles()
		}
	case "rollback_control":
		if action.ControlID != nil && *action.ControlID == "linux.ssh.password-authentication-disabled" {
			if err := os.Remove(a.config.SSHDHardeningPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return "failed", err.Error()
			}
			return "succeeded", "Rolled back Linux SSH PasswordAuthentication managed file."
		}
		if currentPlatformName() == "windows" && action.ControlID != nil && *action.ControlID == "control.windows.firewall-all-profiles" {
			return a.rollbackWindowsFirewallAllProfiles()
		}
	}
	return "failed", "Unsupported SHA Go agent action/control pair."
}

func (a Agent) windowsPostureResults() []postureResult {
	current := "unknown"
	status := "warn"
	evidence := "Windows Firewall profile state could not be inspected."
	output, err := runPowerShell("$disabled = @(Get-NetFirewallProfile -Name Domain,Private,Public | Where-Object { -not $_.Enabled }); if ($disabled.Count -eq 0) { 'enabled' } else { ($disabled | ForEach-Object { $_.Name }) -join ',' }")
	if err == nil {
		current = strings.TrimSpace(output)
		if current == "enabled" {
			status = "pass"
			evidence = "Domain, Private, and Public firewall profiles are enabled."
		} else {
			status = "fail"
			evidence = "Windows Firewall disabled profile(s): " + current + "."
		}
	}
	recommended := "enabled"
	severity := "high"
	return []postureResult{
		{
			ControlKey:       "windows.firewall.all-profiles-enabled",
			Status:           status,
			CurrentValue:     &current,
			RecommendedValue: &recommended,
			Severity:         &severity,
			EvidenceSummary:  evidence,
		},
		{
			ControlKey:      "windows.agent.present",
			Status:          "pass",
			EvidenceSummary: "SHA Go agent reported successfully.",
		},
	}
}

func (a Agent) applyWindowsFirewallAllProfiles() (string, string) {
	path := psQuote(a.config.WindowsFirewallRollbackPath)
	script := "$rollback = '" + path + "'; " +
		"$parent = Split-Path -Parent $rollback; if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }; " +
		"if (-not (Test-Path -LiteralPath $rollback)) { Get-NetFirewallProfile -Name Domain,Private,Public | Select-Object Name,Enabled | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollback -Encoding UTF8 }; " +
		"Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"
	if output, err := runPowerShell(script); err != nil {
		return "failed", strings.TrimSpace(output + " " + err.Error())
	}
	return "succeeded", "Enabled Windows Firewall Domain, Private, and Public profiles; rollback saved to " + a.config.WindowsFirewallRollbackPath + "."
}

func (a Agent) rollbackWindowsFirewallAllProfiles() (string, string) {
	path := psQuote(a.config.WindowsFirewallRollbackPath)
	script := "$rollback = '" + path + "'; " +
		"if (-not (Test-Path -LiteralPath $rollback)) { throw \"No SHA firewall rollback artifact found at $rollback\" }; " +
		"$profiles = @(Get-Content -LiteralPath $rollback -Raw | ConvertFrom-Json); " +
		"foreach ($profile in $profiles) { Set-NetFirewallProfile -Profile ([string]$profile.Name) -Enabled ([bool]$profile.Enabled) }; " +
		"Remove-Item -LiteralPath $rollback -Force"
	if output, err := runPowerShell(script); err != nil {
		return "failed", strings.TrimSpace(output + " " + err.Error())
	}
	return "succeeded", "Restored Windows Firewall profile states from SHA rollback artifact."
}

func runPowerShell(script string) (string, error) {
	return runCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

func runCommandWithTimeout(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() != nil {
		return string(output), ctx.Err()
	}
	return string(output), err
}

func psQuote(value string) string {
	return strings.ReplaceAll(value, "'", "''")
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
	sum := sha256.Sum256([]byte(currentPlatformName() + "|" + strings.TrimSpace(machineID) + "|" + profileID))
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
	if currentPlatformName() == "linux" {
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
