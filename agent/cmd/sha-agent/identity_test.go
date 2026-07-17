package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestDeviceEnrollmentPersistsIdentityClearsTokenAndUsesDeviceBearer(t *testing.T) {
	restorePlatform := currentPlatformName
	currentPlatformName = func() string { return "linux" }
	t.Cleanup(func() { currentPlatformName = restorePlatform })

	enrollmentToken := testEnrollmentToken()
	endpointID := "ep_0123456789abcdef0123456789abcdef"
	var enrolled enrollmentExchangeRequest
	var deviceBearer string
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/agent/me":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer sha_device.dc_") {
				t.Fatalf("unexpected recovery auth header shape")
			}
			writeHTTPError(w, http.StatusUnauthorized)
		case r.Method == http.MethodPost && r.URL.Path == "/api/agent/bootstrap":
			if r.Header.Get("Authorization") != "Bearer "+enrollmentToken {
				t.Fatal("bootstrap did not use enrollment bearer")
			}
			if err := json.NewDecoder(r.Body).Decode(&enrolled); err != nil {
				t.Fatal(err)
			}
			if enrolled.ProtocolVersion != agentProtocolVersion ||
				enrolled.Architecture != runtime.GOARCH ||
				enrolled.Platform != "linux" ||
				!installationIDPattern.MatchString(enrolled.InstallationID) ||
				!credentialIDPattern.MatchString(enrolled.CredentialID) ||
				!validCanonicalSecret(enrolled.CredentialSecret) {
				t.Fatal("bootstrap request metadata was invalid")
			}
			deviceBearer = deviceCredentialMaterial{
				CredentialID: enrolled.CredentialID, CredentialSecret: enrolled.CredentialSecret,
			}.bearer()
			writeIdentity(w, http.StatusCreated, endpointID, enrolled.InstallationID, enrolled.CredentialID, "active")
		case r.Method == http.MethodPost && r.URL.Path == "/api/endpoints/"+endpointID+"/heartbeat":
			assertDeviceBearer(t, r, deviceBearer)
			var heartbeat struct {
				ProtocolVersion string `json:"protocol_version"`
				Architecture    string `json:"architecture"`
			}
			if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
				t.Fatal(err)
			}
			if heartbeat.ProtocolVersion != agentProtocolVersion || heartbeat.Architecture != runtime.GOARCH {
				t.Fatalf("unexpected heartbeat identity metadata: %#v", heartbeat)
			}
			writeJSON(w, map[string]any{"endpoint_id": endpointID, "status": "active"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/posture-snapshots":
			assertDeviceBearer(t, r, deviceBearer)
			writeJSON(w, map[string]any{"accepted_result_count": 2})
		case r.Method == http.MethodPost && r.URL.Path == "/api/endpoints/"+endpointID+"/response-actions/claim":
			assertDeviceBearer(t, r, deviceBearer)
			writeJSON(w, actionList{})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	agent, store, configPath := newTestDeviceAgent(t, server, enrollmentToken)
	if err := agent.RunOnce(); err != nil {
		t.Fatal(err)
	}
	if agent.config.EnrollmentToken != "" || agent.config.APIToken != "" {
		t.Fatal("used bootstrap credential remains in agent memory after enrollment")
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.EndpointID != endpointID || state.PendingEnrollment != nil || state.Credential.CredentialID != enrolled.CredentialID {
		t.Fatal("durable enrolled state did not match the exchange response")
	}
	configContent, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(configContent), enrollmentToken) || strings.Contains(string(configContent), "enrollment_token") {
		t.Fatal("used enrollment token remains persisted")
	}
	if strings.Contains(string(configContent), "legacy-agent-token") || strings.Contains(string(configContent), "api_token") {
		t.Fatal("legacy shared agent token remains after device enrollment")
	}
	wantPaths := []string{
		"GET /api/agent/me",
		"POST /api/agent/bootstrap",
		"POST /api/endpoints/" + endpointID + "/heartbeat",
		"POST /api/posture-snapshots",
		"POST /api/endpoints/" + endpointID + "/response-actions/claim",
	}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("paths=%#v, want %#v", paths, wantPaths)
	}
}

func TestPendingDeviceEnrollmentRunsHeartbeatOnly(t *testing.T) {
	restorePlatform := currentPlatformName
	currentPlatformName = func() string { return "linux" }
	t.Cleanup(func() { currentPlatformName = restorePlatform })

	enrollmentToken := testEnrollmentToken()
	endpointID := "ep_11111111111111111111111111111111"
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch requestCount {
		case 1:
			writeHTTPError(w, http.StatusUnauthorized)
		case 2:
			var payload enrollmentExchangeRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			writeIdentity(w, http.StatusCreated, endpointID, payload.InstallationID, payload.CredentialID, "pending")
		case 3:
			if r.URL.Path != "/api/endpoints/"+endpointID+"/heartbeat" {
				t.Fatalf("pending endpoint attempted unexpected path %s", r.URL.Path)
			}
			writeJSON(w, map[string]any{"endpoint_id": endpointID, "status": "pending"})
		default:
			t.Fatalf("pending endpoint made extra request %s", r.URL.Path)
		}
	}))
	defer server.Close()

	agent, _, _ := newTestDeviceAgent(t, server, enrollmentToken)
	if err := agent.RunOnce(); err != nil {
		t.Fatal(err)
	}
	if requestCount != 3 {
		t.Fatalf("request count=%d, want 3", requestCount)
	}
}

func TestEnrollmentRecoversFromLostBootstrapResponseThroughAgentMe(t *testing.T) {
	enrollmentToken := testEnrollmentToken()
	endpointID := "ep_22222222222222222222222222222222"
	var committed *enrollmentExchangeRequest
	bootstrapCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/me":
			if committed == nil {
				writeHTTPError(w, http.StatusUnauthorized)
				return
			}
			wantBearer := deviceCredentialMaterial{
				CredentialID: committed.CredentialID, CredentialSecret: committed.CredentialSecret,
			}.bearer()
			assertDeviceBearer(t, r, wantBearer)
			writeIdentity(w, http.StatusOK, endpointID, committed.InstallationID, committed.CredentialID, "active")
		case "/api/agent/bootstrap":
			bootstrapCalls++
			var payload enrollmentExchangeRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			committed = &payload
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"endpoint":`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	agent, store, configPath := newTestDeviceAgent(t, server, enrollmentToken)
	if _, err := agent.ensureDeviceIdentity("host-before-loss", "version-before-loss"); err == nil {
		t.Fatal("truncated bootstrap response unexpectedly succeeded")
	}
	pending, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if pending.EndpointID != "" || pending.PendingEnrollment == nil {
		t.Fatal("lost response did not preserve enrollment candidate")
	}
	session, err := agent.ensureDeviceIdentity("changed-hostname", "changed-version")
	if err != nil {
		t.Fatal(err)
	}
	if session.state.EndpointID != endpointID || bootstrapCalls != 1 {
		t.Fatalf("recovery endpoint=%q bootstrapCalls=%d", session.state.EndpointID, bootstrapCalls)
	}
	configContent, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(configContent), enrollmentToken) ||
		strings.Contains(string(configContent), "legacy-agent-token") ||
		strings.Contains(string(configContent), "api_token") {
		t.Fatal("recovered enrollment left a bootstrap credential persisted")
	}
}

func TestEnrollmentRetryUsesExactPersistedRequest(t *testing.T) {
	enrollmentToken := testEnrollmentToken()
	endpointID := "ep_33333333333333333333333333333333"
	var first enrollmentExchangeRequest
	bootstrapCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/me" {
			writeHTTPError(w, http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/agent/bootstrap" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		bootstrapCalls++
		var payload enrollmentExchangeRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if bootstrapCalls == 1 {
			first = payload
			writeHTTPError(w, http.StatusServiceUnavailable)
			return
		}
		if !reflect.DeepEqual(payload, first) {
			t.Fatal("retry payload changed from the persisted bootstrap request")
		}
		writeIdentity(w, http.StatusCreated, endpointID, payload.InstallationID, payload.CredentialID, "active")
	}))
	defer server.Close()

	agent, _, _ := newTestDeviceAgent(t, server, enrollmentToken)
	if _, err := agent.ensureDeviceIdentity("first-host", "first-version"); err == nil {
		t.Fatal("service-unavailable bootstrap unexpectedly succeeded")
	}
	if _, err := agent.ensureDeviceIdentity("different-host", "different-version"); err != nil {
		t.Fatal(err)
	}
	if bootstrapCalls != 2 {
		t.Fatalf("bootstrap calls=%d, want 2", bootstrapCalls)
	}
}

func TestRotationRecoversWhenServerCommitsButResponseIsLost(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := newStateStore(filepath.Join(directory, "agent-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	initial := testCompletedDeviceState()
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	active := initial.Credential
	rotateCalls := 0
	var lock sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		switch r.URL.Path {
		case "/api/agent/me":
			if r.Header.Get("Authorization") != "Bearer "+active.bearer() {
				writeHTTPError(w, http.StatusUnauthorized)
				return
			}
			writeIdentity(w, http.StatusOK, initial.EndpointID, initial.InstallationID, active.CredentialID, "active")
		case "/api/agent/credentials/rotate":
			if r.Header.Get("Authorization") != "Bearer "+active.bearer() {
				writeHTTPError(w, http.StatusUnauthorized)
				return
			}
			var candidate deviceCredentialMaterial
			if err := json.NewDecoder(r.Body).Decode(&candidate); err != nil {
				t.Fatal(err)
			}
			rotateCalls++
			active = candidate
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"credential_id":`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	agent := Agent{
		config:     Config{ControlPlaneURL: server.URL, AgentVersion: defaultAgentVersion},
		client:     server.Client(),
		stateStore: store,
	}
	if _, err := agent.rotateDeviceCredential("host", "version"); err == nil {
		t.Fatal("lost rotation response unexpectedly succeeded")
	}
	pending, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if pending.PendingRotation == nil {
		t.Fatal("lost rotation response did not preserve candidate")
	}
	if _, err := agent.ensureDeviceIdentity("host", "version"); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if recovered.PendingRotation != nil || recovered.Credential != active || recovered.Credential == initial.Credential {
		t.Fatal("rotation recovery state did not promote the committed candidate")
	}
	if rotateCalls != 1 {
		t.Fatalf("rotation calls=%d, want 1", rotateCalls)
	}
}

func TestHTTPStatusErrorsNeverReflectResponseSecrets(t *testing.T) {
	secret := testCanonicalSecret()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"echoed ` + secret + `"}`))
	}))
	defer server.Close()
	agent := Agent{config: Config{ControlPlaneURL: server.URL}, client: server.Client()}
	err := agent.doJSONWithBearer(http.MethodPost, "/test", map[string]string{"secret": secret}, nil, "bearer-"+secret)
	if err == nil {
		t.Fatal("rejected request unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) || !isHTTPStatus(err, http.StatusBadRequest) {
		t.Fatalf("unsafe or unclassified HTTP error: %v", err)
	}
}

func newTestDeviceAgent(
	t *testing.T,
	server *httptest.Server,
	enrollmentToken string,
) (*Agent, *stateStore, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "agent-config.json")
	configContent, err := json.Marshal(map[string]any{
		"control_plane_url": server.URL,
		"enrollment_token":  enrollmentToken,
		"api_token":         "legacy-agent-token",
		"profile_id":        "test-profile",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configContent, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newStateStore(filepath.Join(directory, "agent-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		config: Config{
			ControlPlaneURL: server.URL,
			EnrollmentToken: enrollmentToken,
			APIToken:        "legacy-agent-token",
			ProfileID:       "test-profile",
			AgentVersion:    defaultAgentVersion,
		},
		client:     server.Client(),
		configPath: configPath,
		stateStore: store,
	}
	return agent, store, configPath
}

func writeIdentity(
	w http.ResponseWriter,
	statusCode int,
	endpointID string,
	installationID string,
	credentialID string,
	endpointStatus string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(agentIdentityResponse{
		Endpoint: deviceEndpointResponse{
			EndpointID:        endpointID,
			InstallationID:    installationID,
			CredentialMode:    "device",
			EnrollmentTokenID: "et_0123456789abcdef0123456789abcdef",
			Status:            endpointStatus,
			ProtocolVersion:   agentProtocolVersion,
			Architecture:      runtime.GOARCH,
		},
		Credential: deviceCredentialResponse{
			CredentialID: credentialID,
			EndpointID:   endpointID,
			Status:       "active",
		},
	})
}

func writeHTTPError(w http.ResponseWriter, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(`{"detail":"request rejected"}`))
}

func assertDeviceBearer(t *testing.T, request *http.Request, bearer string) {
	t.Helper()
	if request.Header.Get("Authorization") != "Bearer "+bearer {
		t.Fatal("request did not use the endpoint-bound device bearer")
	}
}

func TestGeneratedCredentialMaterialIsCanonicalAndUnique(t *testing.T) {
	first, err := generateCredentialMaterial()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateCredentialMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCredentialMaterial(first); err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("independent credential generations matched")
	}
}

func TestInvalidEnrollmentTokenErrorDoesNotEchoToken(t *testing.T) {
	invalid := "sha_enroll.invalid.super-secret"
	_, err := newPendingEnrollmentState(
		Config{EnrollmentToken: invalid, AgentVersion: defaultAgentVersion},
		"host",
		"version",
	)
	if err == nil {
		t.Fatal("invalid token unexpectedly accepted")
	}
	if strings.Contains(err.Error(), invalid) {
		t.Fatal("invalid token was reflected in an error")
	}
}

func TestHTTPStatusClassificationUsesTypedError(t *testing.T) {
	err := &HTTPStatusError{Method: "GET", Path: "/api/agent/me", StatusCode: http.StatusUnauthorized}
	if !isHTTPStatus(err, http.StatusUnauthorized) || isHTTPStatus(err, http.StatusForbidden) {
		t.Fatal("HTTP status classification failed")
	}
	if isHTTPStatus(errors.New("401"), http.StatusUnauthorized) {
		t.Fatal("untyped error was misclassified")
	}
}

func testCompletedDeviceState() *deviceState {
	return &deviceState{
		Version:        deviceStateVersion,
		InstallationID: "si_0123456789abcdefghijklmnopqrstuv",
		EndpointID:     "ep_0123456789abcdef0123456789abcdef",
		Credential: deviceCredentialMaterial{
			CredentialID:     "dc_0123456789abcdefghijklmnopqrstuv",
			CredentialSecret: testCanonicalSecret(),
		},
	}
}

func testCanonicalSecret() string {
	return "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"
}

func testEnrollmentToken() string {
	return "sha_enroll.et_0123456789abcdef0123456789abcdef." + testCanonicalSecret()
}
