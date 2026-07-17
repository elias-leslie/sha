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

const (
	defaultAgentVersion         = "sha-go-agent-v0.1.0"
	legacyGoSSHHardeningPayload = "# Managed by SHA Go agent\nPasswordAuthentication no\n"
	linuxLegacySSHControlID     = "linux.ssh.password-authentication-disabled"
	windowsFirewallControlID    = "control.windows.firewall-all-profiles"
	initialLoopRetryDelay       = 5 * time.Second
	maximumLoopRetryDelay       = 5 * time.Minute
)

var utf8ByteOrderMark = []byte{0xef, 0xbb, 0xbf}

type Config struct {
	ControlPlaneURL             string  `json:"control_plane_url"`
	APIToken                    string  `json:"api_token"`
	EnrollmentToken             string  `json:"enrollment_token"`
	StatePath                   string  `json:"state_path"`
	AllowInsecureLoopback       bool    `json:"allow_insecure_loopback"`
	CABundlePath                string  `json:"ca_bundle_path"`
	TenantID                    *string `json:"tenant_id"`
	SiteID                      *string `json:"site_id"`
	ProfileID                   string  `json:"profile_id"`
	AgentVersion                string  `json:"agent_version"`
	ServiceContext              string  `json:"service_context"`
	SSHDHardeningPath           string  `json:"sshd_hardening_path"`
	WindowsFirewallRollbackPath string  `json:"windows_firewall_rollback_path"`
}

type Agent struct {
	config         Config
	client         *http.Client
	configPath     string
	stateStore     *stateStore
	requestContext context.Context
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
	LeaseToken           string  `json:"lease_token"`
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
	action := flag.String("action", "run", "agent action: run, service, status, or rotate-credential")
	loop := flag.Bool("loop", false, "run forever instead of once")
	interval := flag.Duration("interval", 15*time.Minute, "loop interval")
	flag.Parse()

	absoluteConfigPath, err := filepath.Abs(*configPath)
	if err != nil {
		fatal(fmt.Errorf("resolve config path: %w", err))
	}
	config, err := loadConfig(absoluteConfigPath)
	if err != nil {
		fatal(err)
	}
	if config.StatePath == "" {
		config.StatePath, err = defaultStatePath(absoluteConfigPath)
		if err != nil {
			fatal(err)
		}
	}
	store, err := newStateStore(config.StatePath)
	if err != nil {
		fatal(err)
	}
	client, err := newHTTPClient(config)
	if err != nil {
		fatal(err)
	}
	agent := Agent{config: config, client: client, configPath: absoluteConfigPath, stateStore: store}
	if err := dispatchAgentAction(
		context.Background(),
		*action,
		*loop,
		*interval,
		newAgentActionHandlers(&agent, os.Stdout, os.Stderr),
	); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func loadConfig(path string) (Config, error) {
	content, err := readPrivateFile(path, maximumConfigFileBytes)
	if err != nil {
		return Config{}, err
	}
	content = bytes.TrimPrefix(content, utf8ByteOrderMark)
	var config Config
	if err := json.Unmarshal(content, &config); err != nil {
		return Config{}, err
	}
	normalizedURL, err := normalizeControlPlaneURL(config.ControlPlaneURL, config.AllowInsecureLoopback)
	if err != nil {
		return Config{}, err
	}
	config.ControlPlaneURL = normalizedURL
	config.CABundlePath = strings.TrimSpace(config.CABundlePath)
	config.EnrollmentToken = strings.TrimSpace(config.EnrollmentToken)
	config.StatePath = strings.TrimSpace(config.StatePath)
	if config.AgentVersion == "" {
		config.AgentVersion = defaultAgentVersion
	}
	if config.ServiceContext == "" {
		config.ServiceContext = "unknown"
	}
	if config.ServiceContext != "unknown" && config.ServiceContext != "system_service" && config.ServiceContext != "interactive" {
		return Config{}, errors.New("service_context must be unknown, system_service, or interactive")
	}
	if config.SSHDHardeningPath == "" {
		config.SSHDHardeningPath = "/etc/ssh/sshd_config.d/99-sha-hardening.conf"
	}
	if config.WindowsFirewallRollbackPath == "" {
		config.WindowsFirewallRollbackPath = `C:\ProgramData\SHA\firewall-profiles-rollback.json`
	}
	return config, nil
}

func runAgent(
	ctx context.Context,
	loop bool,
	interval time.Duration,
	runOnce func() error,
	wait func(context.Context, time.Duration) error,
	reportRetry func(error),
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	retryDelay := initialLoopRetryDelay
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := runOnce()
		if err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			if !loop {
				return err
			}
			if reportRetry != nil {
				reportRetry(err)
			}
			if err := wait(ctx, retryDelay); err != nil {
				return err
			}
			retryDelay = nextLoopRetryDelay(retryDelay)
			continue
		}

		if !loop {
			return nil
		}
		retryDelay = initialLoopRetryDelay
		if err := wait(ctx, interval); err != nil {
			return err
		}
	}
}

func nextLoopRetryDelay(current time.Duration) time.Duration {
	if current >= maximumLoopRetryDelay/2 {
		return maximumLoopRetryDelay
	}
	return current * 2
}

func waitForAgentInterval(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (a *Agent) RunOnce() error {
	return a.RunOnceContext(context.Background())
}

func (a *Agent) RunOnceContext(ctx context.Context) error {
	return a.runWithContext(ctx, a.runOnce)
}

func (a *Agent) runWithContext(ctx context.Context, operation func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	previous := a.requestContext
	a.requestContext = ctx
	defer func() { a.requestContext = previous }()
	return operation()
}

func (a Agent) context() context.Context {
	if a.requestContext != nil {
		return a.requestContext
	}
	return context.Background()
}

func (a *Agent) runOnce() error {
	hostname, platformVersion := localIdentityFacts()
	useDeviceIdentity, err := a.shouldUseDeviceIdentity()
	if err != nil {
		return err
	}
	if useDeviceIdentity {
		session, err := a.ensureDeviceIdentity(hostname, platformVersion)
		if err != nil {
			return err
		}
		return a.runEndpointCycle(
			session.identity.Endpoint.EndpointID,
			platformVersion,
			session.state.Credential.bearer(),
			true,
			session.identity.Endpoint.Status,
		)
	}
	return a.runLegacyCycle(hostname, platformVersion)
}

func localIdentityFacts() (string, string) {
	hostname, _ := os.Hostname()
	if strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	return hostname, platformVersion()
}

func (a *Agent) runLegacyCycle(hostname, platformVersion string) error {
	if strings.TrimSpace(a.config.APIToken) == "" {
		return errors.New("api_token or enrollment_token/device state is required")
	}
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
	return a.runEndpointCycle(endpoint.EndpointID, platformVersion, a.config.APIToken, false, "active")
}

func (a *Agent) runEndpointCycle(
	endpointID string,
	platformVersion string,
	bearer string,
	deviceIdentity bool,
	endpointStatus string,
) error {
	heartbeat := map[string]any{
		"agent_version":         a.config.AgentVersion,
		"platform_version":      platformVersion,
		"platform_profile":      currentPlatformName() + "-go-agent",
		"connectivity_status":   "online",
		"declared_capabilities": declaredCapabilities(),
		"execution_hooks":       executionHooks(),
	}
	if deviceIdentity {
		heartbeat["protocol_version"] = agentProtocolVersion
		heartbeat["architecture"] = runtime.GOARCH
		heartbeat["capability_manifest"] = buildCapabilityManifest(a.config.ServiceContext)
	}
	if err := a.doJSONWithBearer("POST", "/api/endpoints/"+endpointID+"/heartbeat", heartbeat, nil, bearer); err != nil {
		return err
	}
	if deviceIdentity && endpointStatus == "pending" {
		return nil
	}
	if err := a.doJSONWithBearer("POST", "/api/posture-snapshots", map[string]any{
		"endpoint_id":      endpointID,
		"observed_at":      time.Now().UTC().Format(time.RFC3339),
		"platform_profile": currentPlatformName() + "-go-agent",
		"results":          a.postureResults(),
	}, nil, bearer); err != nil {
		return err
	}
	var actions actionList
	if err := a.doJSONWithBearer("POST", "/api/endpoints/"+endpointID+"/response-actions/claim", map[string]any{}, &actions, bearer); err != nil {
		return err
	}
	for _, action := range actions.Items {
		if strings.TrimSpace(action.LeaseToken) == "" {
			return fmt.Errorf("response action %s claim is missing lease_token", action.ResponseActionID)
		}
		status, summary := a.executeAction(action)
		if err := a.doJSONWithBearer("POST", "/api/response-actions/"+action.ResponseActionID+"/result", map[string]any{
			"status":         status,
			"result_summary": summary,
			"lease_token":    action.LeaseToken,
		}, nil, bearer); err != nil {
			return err
		}
	}
	return nil
}

func declaredCapabilities() []string {
	capabilities := []string{"enroll", "heartbeat", "collect_posture_snapshot"}
	switch currentPlatformName() {
	case "linux":
		capabilities = append(capabilities, "rollback_control:"+linuxLegacySSHControlID)
	case "windows":
		capabilities = append(
			capabilities,
			"apply_control:"+windowsFirewallControlID,
			"rollback_control:"+windowsFirewallControlID,
		)
	}
	return capabilities
}

func executionHooks() map[string]bool {
	return map[string]bool{
		"captures_rollback_artifacts": currentPlatformName() == "windows",
		"reports_execution_results":   true,
		"supports_dry_run":            false,
	}
}

func (a Agent) doJSON(method, path string, body any, out any) error {
	return a.doJSONWithBearer(method, path, body, out, a.config.APIToken)
}

func (a Agent) doJSONWithBearer(method, path string, body any, out any, bearer string) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(a.context(), method, a.config.ControlPlaneURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	content, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if readErr != nil {
		return fmt.Errorf("read %s %s response: %w", method, path, readErr)
	}
	if len(content) > 64*1024 {
		return fmt.Errorf("%s %s response exceeds size limit", method, path)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &HTTPStatusError{
			Method:     method,
			Path:       path,
			StatusCode: response.StatusCode,
			Detail:     sanitizedHTTPErrorDetail(content),
		}
	}
	if out == nil || len(content) == 0 {
		return nil
	}
	return json.Unmarshal(content, out)
}

func sanitizedHTTPErrorDetail(content []byte) string {
	// Server-generated error bodies are deliberately not reflected. A proxy or
	// future endpoint could echo request material, including enrollment or
	// device secrets. Method, path, and status remain sufficient for diagnosis.
	_ = content
	return "control plane rejected the request"
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
		return "failed", "Unsupported SHA Go agent evidence action; no evidence was collected."
	case "rollback_control":
		if currentPlatformName() == "linux" && action.ControlID != nil && *action.ControlID == linuxLegacySSHControlID {
			if err := rollbackLegacyGoSSHHardening(a.config.SSHDHardeningPath); err != nil {
				return "failed", err.Error()
			}
			return "succeeded", "Removed exact legacy SHA Go SSH hardening file."
		}
		if currentPlatformName() == "windows" && action.ControlID != nil && *action.ControlID == windowsFirewallControlID {
			return a.rollbackWindowsFirewallAllProfiles()
		}
	case "apply_control":
		if currentPlatformName() == "windows" && action.ControlID != nil && *action.ControlID == windowsFirewallControlID {
			return a.applyWindowsFirewallAllProfiles()
		}
	}
	return "failed", "Unsupported SHA Go agent action/control pair; no mutation was attempted."
}

func rollbackLegacyGoSSHHardening(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("refusing legacy SSH rollback: managed file could not be read: %w", err)
	}
	if string(content) != legacyGoSSHHardeningPayload {
		return errors.New("refusing legacy SSH rollback: managed file content does not exactly match the historical SHA Go payload")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("legacy SSH rollback failed: %w", err)
	}
	return nil
}

func (a Agent) windowsPostureResults() []postureResult {
	current := "unknown"
	status := "warn"
	evidence := "Windows Firewall profile state could not be inspected."
	output, err := a.runPowerShell("$disabled = @(Get-NetFirewallProfile -Name Domain,Private,Public | Where-Object { -not $_.Enabled }); if ($disabled.Count -eq 0) { 'enabled' } else { ($disabled | ForEach-Object { $_.Name }) -join ',' }")
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
			ControlKey:       windowsFirewallControlID,
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
		"$parent = Split-Path -Parent $rollback; if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null; & icacls.exe $parent /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Unable to secure SHA rollback directory' } }; " +
		"if (Test-Path -LiteralPath $rollback) { throw \"Refusing to overwrite existing SHA firewall rollback artifact at $rollback\" }; " +
		"Get-NetFirewallProfile -Name Domain,Private,Public | Select-Object Name,Enabled | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rollback -Encoding UTF8; " +
		"Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"
	if output, err := a.runPowerShell(script); err != nil {
		return "failed", strings.TrimSpace(output + " " + err.Error())
	}
	return "succeeded", "Enabled Windows Firewall Domain, Private, and Public profiles; rollback saved to " + a.config.WindowsFirewallRollbackPath + "."
}

func (a Agent) rollbackWindowsFirewallAllProfiles() (string, string) {
	path := psQuote(a.config.WindowsFirewallRollbackPath)
	script := "$rollback = '" + path + "'; " +
		"if (-not (Test-Path -LiteralPath $rollback)) { throw \"No SHA firewall rollback artifact found at $rollback\" }; " +
		"$acl = Get-Acl -LiteralPath $rollback; $ownerSid = [System.Security.Principal.NTAccount]::new($acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value; if (@('S-1-5-18','S-1-5-32-544') -notcontains $ownerSid) { throw 'SHA firewall rollback artifact has an untrusted owner' }; " +
		"$profiles = @(Get-Content -LiteralPath $rollback -Raw | ConvertFrom-Json); $expected = @('Domain','Private','Public'); " +
		"if ($profiles.Count -ne 3 -or @($profiles.Name | Sort-Object -Unique).Count -ne 3) { throw 'SHA firewall rollback artifact has an invalid profile set' }; " +
		"foreach ($profile in $profiles) { if ($expected -notcontains [string]$profile.Name -or $profile.Enabled -isnot [bool]) { throw 'SHA firewall rollback artifact has invalid data' }; $enabled = if ($profile.Enabled) { 'True' } else { 'False' }; Set-NetFirewallProfile -Profile ([string]$profile.Name) -Enabled $enabled }; " +
		"Remove-Item -LiteralPath $rollback -Force"
	if output, err := a.runPowerShell(script); err != nil {
		return "failed", strings.TrimSpace(output + " " + err.Error())
	}
	return "succeeded", "Restored Windows Firewall profile states from SHA rollback artifact."
}

func runPowerShell(script string) (string, error) {
	return runCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

func (a Agent) runPowerShell(script string) (string, error) {
	if a.requestContext == nil {
		return runPowerShell(script)
	}
	return runCommandWithContext(a.requestContext, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

func runCommandWithTimeout(name string, args ...string) (string, error) {
	return runCommandWithContext(context.Background(), name, args...)
}

func runCommandWithContext(parent context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
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
