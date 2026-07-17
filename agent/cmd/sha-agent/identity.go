package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
)

const (
	deviceStateVersion   = 1
	agentProtocolVersion = "sha-agent-v1"
)

var (
	installationIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)
	credentialIDPattern    = regexp.MustCompile(`^dc_[A-Za-z0-9_-]{16,64}$`)
	endpointIDPattern      = regexp.MustCompile(`^ep_[A-Za-z0-9_-]{16,64}$`)
	protocolValuePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	enrollmentTokenPattern = regexp.MustCompile(
		`^sha_enroll\.et_[0-9a-f]{32}\.[A-Za-z0-9_-]{43,128}$`,
	)
)

type deviceCredentialMaterial struct {
	CredentialID     string `json:"credential_id"`
	CredentialSecret string `json:"credential_secret"`
}

func (material deviceCredentialMaterial) bearer() string {
	return "sha_device." + material.CredentialID + "." + material.CredentialSecret
}

type enrollmentExchangeRequest struct {
	InstallationID   string `json:"installation_id"`
	CredentialID     string `json:"credential_id"`
	CredentialSecret string `json:"credential_secret"`
	AgentFingerprint string `json:"agent_fingerprint"`
	Hostname         string `json:"hostname"`
	Platform         string `json:"platform"`
	PlatformVersion  string `json:"platform_version"`
	AgentVersion     string `json:"agent_version"`
	ProtocolVersion  string `json:"protocol_version"`
	Architecture     string `json:"architecture"`
}

type deviceState struct {
	Version           int                        `json:"version"`
	InstallationID    string                     `json:"installation_id"`
	EndpointID        string                     `json:"endpoint_id,omitempty"`
	Credential        deviceCredentialMaterial   `json:"credential"`
	PendingEnrollment *enrollmentExchangeRequest `json:"pending_enrollment,omitempty"`
	PendingRotation   *deviceCredentialMaterial  `json:"pending_rotation,omitempty"`
}

type deviceEndpointResponse struct {
	EndpointID        string `json:"endpoint_id"`
	InstallationID    string `json:"installation_id"`
	CredentialMode    string `json:"credential_mode"`
	EnrollmentTokenID string `json:"enrollment_token_id"`
	Status            string `json:"status"`
	ProtocolVersion   string `json:"protocol_version"`
	Architecture      string `json:"architecture"`
}

type deviceCredentialResponse struct {
	CredentialID           string  `json:"credential_id"`
	EndpointID             string  `json:"endpoint_id"`
	Status                 string  `json:"status"`
	ReplacedByCredentialID *string `json:"replaced_by_credential_id"`
}

type agentIdentityResponse struct {
	Endpoint   deviceEndpointResponse   `json:"endpoint"`
	Credential deviceCredentialResponse `json:"credential"`
	Replayed   bool                     `json:"replayed"`
}

type deviceSession struct {
	state    *deviceState
	identity agentIdentityResponse
}

type HTTPStatusError struct {
	Method     string
	Path       string
	StatusCode int
	Detail     string
}

func (err *HTTPStatusError) Error() string {
	if err.Detail == "" {
		return fmt.Sprintf("%s %s failed with HTTP %d", err.Method, err.Path, err.StatusCode)
	}
	return fmt.Sprintf("%s %s failed with HTTP %d: %s", err.Method, err.Path, err.StatusCode, err.Detail)
}

func isHTTPStatus(err error, statusCode int) bool {
	var statusErr *HTTPStatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == statusCode
}

func (a *Agent) shouldUseDeviceIdentity() (bool, error) {
	if a.stateStore == nil {
		return strings.TrimSpace(a.config.EnrollmentToken) != "", nil
	}
	_, err := a.stateStore.Load()
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return strings.TrimSpace(a.config.EnrollmentToken) != "", nil
}

func (a *Agent) ensureDeviceIdentity(hostname, platformVersion string) (*deviceSession, error) {
	if a.stateStore == nil {
		return nil, errors.New("device state store is not configured")
	}
	state, err := a.stateStore.Load()
	if errors.Is(err, os.ErrNotExist) {
		state, err = newPendingEnrollmentState(a.config, hostname, platformVersion)
		if err != nil {
			return nil, err
		}
		if err := a.stateStore.Save(state); err != nil {
			return nil, fmt.Errorf("persist enrollment candidate before exchange: %w", err)
		}
	} else if err != nil {
		return nil, err
	}

	if state.PendingRotation != nil {
		if err := a.reconcilePendingRotation(state); err != nil {
			return nil, err
		}
	}

	if state.EndpointID == "" {
		identity, err := a.fetchAgentIdentity(state.Credential)
		if err == nil {
			if err := validateIdentityResponse(identity, state, state.Credential); err != nil {
				return nil, err
			}
			if err := a.promoteEnrollment(state, identity); err != nil {
				return nil, err
			}
			return &deviceSession{state: state, identity: *identity}, nil
		}
		if !isHTTPStatus(err, http.StatusUnauthorized) {
			return nil, fmt.Errorf("recover enrollment identity: %w", err)
		}
		if state.PendingEnrollment == nil {
			return nil, errors.New("device state has no completed endpoint or pending enrollment")
		}
		token := strings.TrimSpace(a.config.EnrollmentToken)
		if !validEnrollmentToken(token) {
			return nil, errors.New("a valid enrollment_token is required to finish device enrollment")
		}
		identity = &agentIdentityResponse{}
		err = a.doJSONWithBearer(
			http.MethodPost,
			"/api/agent/bootstrap",
			state.PendingEnrollment,
			identity,
			token,
		)
		if err != nil {
			if isHTTPStatus(err, http.StatusConflict) {
				recovered, recoveryErr := a.fetchAgentIdentity(state.Credential)
				if recoveryErr == nil {
					identity = recovered
					err = nil
				}
			}
			if err != nil {
				return nil, fmt.Errorf("exchange enrollment token: %w", err)
			}
		}
		if err := validateIdentityResponse(identity, state, state.Credential); err != nil {
			return nil, err
		}
		if err := a.promoteEnrollment(state, identity); err != nil {
			return nil, err
		}
		return &deviceSession{state: state, identity: *identity}, nil
	}

	identity, err := a.fetchAgentIdentity(state.Credential)
	if err != nil {
		return nil, fmt.Errorf("validate device identity: %w", err)
	}
	if err := validateIdentityResponse(identity, state, state.Credential); err != nil {
		return nil, err
	}
	if err := a.clearPersistedBootstrapCredentials(); err != nil {
		return nil, err
	}
	return &deviceSession{state: state, identity: *identity}, nil
}

func newPendingEnrollmentState(config Config, hostname, platformVersion string) (*deviceState, error) {
	token := strings.TrimSpace(config.EnrollmentToken)
	if !validEnrollmentToken(token) {
		return nil, errors.New("a valid enrollment_token is required to create device identity")
	}
	installationID, err := generatePublicID("si_", 24)
	if err != nil {
		return nil, err
	}
	credential, err := generateCredentialMaterial()
	if err != nil {
		return nil, err
	}
	platform := currentPlatformName()
	request := &enrollmentExchangeRequest{
		InstallationID:   installationID,
		CredentialID:     credential.CredentialID,
		CredentialSecret: credential.CredentialSecret,
		AgentFingerprint: fingerprint(hostname, config.ProfileID),
		Hostname:         hostname,
		Platform:         platform,
		PlatformVersion:  platformVersion,
		AgentVersion:     config.AgentVersion,
		ProtocolVersion:  agentProtocolVersion,
		Architecture:     runtime.GOARCH,
	}
	state := &deviceState{
		Version:           deviceStateVersion,
		InstallationID:    installationID,
		Credential:        credential,
		PendingEnrollment: request,
	}
	if err := validateDeviceState(state); err != nil {
		return nil, err
	}
	return state, nil
}

func (a *Agent) promoteEnrollment(state *deviceState, identity *agentIdentityResponse) error {
	state.EndpointID = identity.Endpoint.EndpointID
	state.PendingEnrollment = nil
	if err := a.stateStore.Save(state); err != nil {
		return fmt.Errorf("persist enrolled device identity: %w", err)
	}
	if err := a.clearPersistedBootstrapCredentials(); err != nil {
		return err
	}
	return nil
}

func (a *Agent) clearPersistedBootstrapCredentials() error {
	if strings.TrimSpace(a.config.EnrollmentToken) == "" && strings.TrimSpace(a.config.APIToken) == "" {
		return nil
	}
	if a.configPath == "" {
		a.config.EnrollmentToken = ""
		a.config.APIToken = ""
		return nil
	}
	if err := clearBootstrapCredentialsFromConfig(a.configPath); err != nil {
		return fmt.Errorf("remove bootstrap credentials from config: %w", err)
	}
	a.config.EnrollmentToken = ""
	a.config.APIToken = ""
	return nil
}

func (a *Agent) fetchAgentIdentity(material deviceCredentialMaterial) (*agentIdentityResponse, error) {
	identity := &agentIdentityResponse{}
	if err := a.doJSONWithBearer(
		http.MethodGet,
		"/api/agent/me",
		nil,
		identity,
		material.bearer(),
	); err != nil {
		return nil, err
	}
	return identity, nil
}

func (a *Agent) rotateDeviceCredential(hostname, platformVersion string) (*deviceCredentialResponse, error) {
	session, err := a.ensureDeviceIdentity(hostname, platformVersion)
	if err != nil {
		return nil, err
	}
	state := session.state
	if state.PendingRotation == nil {
		candidate, err := generateCredentialMaterial()
		if err != nil {
			return nil, err
		}
		state.PendingRotation = &candidate
		if err := a.stateStore.Save(state); err != nil {
			return nil, fmt.Errorf("persist rotation candidate before request: %w", err)
		}
	}
	if err := a.reconcilePendingRotation(state); err != nil {
		return nil, err
	}
	identity, err := a.fetchAgentIdentity(state.Credential)
	if err != nil {
		return nil, fmt.Errorf("validate rotated credential: %w", err)
	}
	if err := validateIdentityResponse(identity, state, state.Credential); err != nil {
		return nil, err
	}
	return &identity.Credential, nil
}

func (a *Agent) reconcilePendingRotation(state *deviceState) error {
	if state.PendingRotation == nil {
		return nil
	}
	candidate := *state.PendingRotation
	currentIdentity, currentErr := a.fetchAgentIdentity(state.Credential)
	if currentErr == nil {
		if err := validateIdentityResponse(currentIdentity, state, state.Credential); err != nil {
			return err
		}
		response := &deviceCredentialResponse{}
		err := a.doJSONWithBearer(
			http.MethodPost,
			"/api/agent/credentials/rotate",
			candidate,
			response,
			state.Credential.bearer(),
		)
		if err == nil {
			if err := validateRotationResponse(response, state.EndpointID, candidate); err != nil {
				return err
			}
			return a.promoteRotation(state, candidate)
		}
		if isHTTPStatus(err, http.StatusConflict) {
			state.PendingRotation = nil
			if saveErr := a.stateStore.Save(state); saveErr != nil {
				return fmt.Errorf("discard rejected rotation candidate: %w", saveErr)
			}
			return errors.New("control plane rejected the rotation candidate; retry rotation to generate a new candidate")
		}
		if !isHTTPStatus(err, http.StatusUnauthorized) {
			return fmt.Errorf("rotate device credential: %w", err)
		}
	} else if !isHTTPStatus(currentErr, http.StatusUnauthorized) {
		return fmt.Errorf("check current credential before rotation recovery: %w", currentErr)
	}

	recovered, err := a.fetchAgentIdentity(candidate)
	if err != nil {
		return fmt.Errorf("recover rotated credential: %w", err)
	}
	if err := validateIdentityResponse(recovered, state, candidate); err != nil {
		return err
	}
	return a.promoteRotation(state, candidate)
}

func (a *Agent) promoteRotation(state *deviceState, candidate deviceCredentialMaterial) error {
	state.Credential = candidate
	state.PendingRotation = nil
	if err := a.stateStore.Save(state); err != nil {
		return fmt.Errorf("persist rotated device credential: %w", err)
	}
	return nil
}

func validateRotationResponse(
	response *deviceCredentialResponse,
	endpointID string,
	candidate deviceCredentialMaterial,
) error {
	if response.CredentialID != candidate.CredentialID ||
		response.EndpointID != endpointID ||
		response.Status != "active" {
		return errors.New("control plane returned mismatched rotated credential metadata")
	}
	return nil
}

func validateIdentityResponse(
	identity *agentIdentityResponse,
	state *deviceState,
	material deviceCredentialMaterial,
) error {
	if identity.Endpoint.EndpointID == "" ||
		identity.Endpoint.InstallationID != state.InstallationID ||
		identity.Endpoint.CredentialMode != "device" ||
		identity.Endpoint.ProtocolVersion != agentProtocolVersion ||
		identity.Endpoint.Architecture != runtime.GOARCH ||
		identity.Credential.CredentialID != material.CredentialID ||
		identity.Credential.EndpointID != identity.Endpoint.EndpointID ||
		identity.Credential.Status != "active" {
		return errors.New("control plane returned mismatched device identity metadata")
	}
	if state.EndpointID != "" && identity.Endpoint.EndpointID != state.EndpointID {
		return errors.New("control plane returned an endpoint that does not match local device state")
	}
	switch identity.Endpoint.Status {
	case "pending", "active", "stale":
	default:
		return errors.New("control plane returned an invalid endpoint status")
	}
	return nil
}

func validateDeviceState(state *deviceState) error {
	if state == nil || state.Version != deviceStateVersion {
		return errors.New("device state has an unsupported version")
	}
	if !installationIDPattern.MatchString(state.InstallationID) {
		return errors.New("device state has an invalid installation_id")
	}
	if err := validateCredentialMaterial(state.Credential); err != nil {
		return fmt.Errorf("device state credential is invalid: %w", err)
	}
	if state.EndpointID == "" {
		if state.PendingEnrollment == nil {
			return errors.New("device state is missing pending enrollment data")
		}
	} else {
		if !endpointIDPattern.MatchString(state.EndpointID) {
			return errors.New("device state has an invalid endpoint_id")
		}
		if state.PendingEnrollment != nil {
			return errors.New("completed device state still contains pending enrollment data")
		}
	}
	if state.PendingEnrollment != nil {
		pending := state.PendingEnrollment
		if pending.InstallationID != state.InstallationID ||
			pending.CredentialID != state.Credential.CredentialID ||
			pending.CredentialSecret != state.Credential.CredentialSecret ||
			strings.TrimSpace(pending.AgentFingerprint) == "" ||
			strings.TrimSpace(pending.Hostname) == "" ||
			!validPlatform(pending.Platform) ||
			strings.TrimSpace(pending.AgentVersion) == "" ||
			pending.ProtocolVersion != agentProtocolVersion ||
			!protocolValuePattern.MatchString(pending.Architecture) {
			return errors.New("device state pending enrollment data is invalid")
		}
	}
	if state.PendingRotation != nil {
		if state.EndpointID == "" {
			return errors.New("device state cannot rotate before enrollment completes")
		}
		if err := validateCredentialMaterial(*state.PendingRotation); err != nil {
			return fmt.Errorf("device state rotation candidate is invalid: %w", err)
		}
		if state.PendingRotation.CredentialID == state.Credential.CredentialID {
			return errors.New("device state rotation candidate duplicates the active credential")
		}
	}
	return nil
}

func validateCredentialMaterial(material deviceCredentialMaterial) error {
	if !credentialIDPattern.MatchString(material.CredentialID) {
		return errors.New("credential_id has an invalid format")
	}
	if !validCanonicalSecret(material.CredentialSecret) {
		return errors.New("credential_secret has an invalid format")
	}
	return nil
}

func validEnrollmentToken(token string) bool {
	if !enrollmentTokenPattern.MatchString(token) {
		return false
	}
	parts := strings.Split(token, ".")
	return len(parts) == 3 && validCanonicalSecret(parts[2])
}

func validCanonicalSecret(value string) bool {
	if len(value) < 43 || len(value) > 128 || strings.Contains(value, "=") {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < 32 {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(raw) == value
}

func validPlatform(value string) bool {
	return value == "linux" || value == "windows" || value == "macos"
}

func generateCredentialMaterial() (deviceCredentialMaterial, error) {
	credentialID, err := generatePublicID("dc_", 24)
	if err != nil {
		return deviceCredentialMaterial{}, err
	}
	secret, err := randomBase64URL(32)
	if err != nil {
		return deviceCredentialMaterial{}, fmt.Errorf("generate credential secret: %w", err)
	}
	return deviceCredentialMaterial{CredentialID: credentialID, CredentialSecret: secret}, nil
}

func generatePublicID(prefix string, randomBytes int) (string, error) {
	suffix, err := randomBase64URL(randomBytes)
	if err != nil {
		return "", fmt.Errorf("generate public identifier: %w", err)
	}
	return prefix + suffix, nil
}

func randomBase64URL(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func printAgentStatus(identity agentIdentityResponse) error {
	return printAgentStatusTo(os.Stdout, identity)
}

func printAgentStatusTo(writer io.Writer, identity agentIdentityResponse) error {
	return json.NewEncoder(writer).Encode(map[string]string{
		"endpoint_id":       identity.Endpoint.EndpointID,
		"endpoint_status":   identity.Endpoint.Status,
		"credential_id":     identity.Credential.CredentialID,
		"credential_status": identity.Credential.Status,
		"protocol_version":  identity.Endpoint.ProtocolVersion,
		"architecture":      identity.Endpoint.Architecture,
	})
}
