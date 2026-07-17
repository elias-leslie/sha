package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeControlPlaneURLRequiresHTTPS(t *testing.T) {
	tests := []struct {
		name                  string
		rawURL                string
		allowInsecureLoopback bool
		want                  string
		wantError             string
	}{
		{name: "https", rawURL: " https://sha.example.test/control/ ", want: "https://sha.example.test/control"},
		{name: "localhost", rawURL: "http://localhost:8010/", allowInsecureLoopback: true, want: "http://localhost:8010"},
		{name: "ipv4 loopback", rawURL: "http://127.0.0.1:8010", allowInsecureLoopback: true, want: "http://127.0.0.1:8010"},
		{name: "ipv6 loopback", rawURL: "http://[::1]:8010/", allowInsecureLoopback: true, want: "http://[::1]:8010"},
		{name: "http disabled", rawURL: "http://127.0.0.1:8010", wantError: "requires HTTPS"},
		{name: "non-loopback http", rawURL: "http://sha.example.test", allowInsecureLoopback: true, wantError: "requires HTTPS"},
		{name: "other loopback", rawURL: "http://127.0.0.2", allowInsecureLoopback: true, wantError: "requires HTTPS"},
		{name: "lookalike hostname", rawURL: "http://localhost.example.test", allowInsecureLoopback: true, wantError: "requires HTTPS"},
		{name: "userinfo", rawURL: "https://agent:secret@sha.example.test", wantError: "user information"},
		{name: "query", rawURL: "https://sha.example.test?token=secret", wantError: "query"},
		{name: "empty query", rawURL: "https://sha.example.test?", wantError: "query"},
		{name: "fragment", rawURL: "https://sha.example.test/#secret", wantError: "fragment"},
		{name: "empty fragment", rawURL: "https://sha.example.test#", wantError: "fragment"},
		{name: "relative", rawURL: "/control", wantError: "absolute URL"},
		{name: "port without hostname", rawURL: "https://:443", wantError: "absolute URL"},
		{name: "ftp", rawURL: "ftp://sha.example.test", wantError: "https scheme"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeControlPlaneURL(test.rawURL, test.allowInsecureLoopback)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("expected error containing %q, got %v", test.wantError, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("normalized URL = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLoadConfigToleratesExactlyOneLeadingUTF8BOM(t *testing.T) {
	payload, err := json.Marshal(Config{ControlPlaneURL: "https://sha.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	oneBOM := append(append([]byte{}, utf8ByteOrderMark...), payload...)
	oneBOMDirectory := privateTestDirectory(t)
	oneBOMPath := filepath.Join(oneBOMDirectory, "one-bom.json")
	if err := os.WriteFile(oneBOMPath, oneBOM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(oneBOMPath); err != nil {
		t.Fatalf("one legacy UTF-8 BOM was not tolerated: %v", err)
	}

	twoBOMs := append(append(append([]byte{}, utf8ByteOrderMark...), utf8ByteOrderMark...), payload...)
	twoBOMDirectory := privateTestDirectory(t)
	twoBOMPath := filepath.Join(twoBOMDirectory, "two-boms.json")
	if err := os.WriteFile(twoBOMPath, twoBOMs, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(twoBOMPath); err == nil {
		t.Fatal("multiple UTF-8 BOMs were accepted")
	}
}

func TestLoadConfigAppliesTransportPolicy(t *testing.T) {
	path := filepath.Join(privateTestDirectory(t), "agent-config.json")
	content, err := json.Marshal(Config{
		ControlPlaneURL:       "http://localhost:8010/",
		AllowInsecureLoopback: true,
		CABundlePath:          " /etc/sha/private-ca.pem ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.ControlPlaneURL != "http://localhost:8010" {
		t.Fatalf("unexpected normalized URL %q", config.ControlPlaneURL)
	}
	if config.CABundlePath != "/etc/sha/private-ca.pem" {
		t.Fatalf("unexpected CA bundle path %q", config.CABundlePath)
	}
}

func TestLoadConfigRequiresBoundedPrivateRegularFile(t *testing.T) {
	directory := privateTestDirectory(t)
	path := filepath.Join(directory, "agent-config.json")
	payload := []byte(`{"control_plane_url":"https://sha.example.test","api_token":"sensitive"}`)
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("permissive config error=%v, want 0600 refusal", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "agent-config-link.json")
	if err := os.Symlink(path, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(symlinkPath); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked config error=%v, want refusal", err)
	}
	oversizedPath := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversizedPath, make([]byte, maximumConfigFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(oversizedPath); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized config error=%v, want bounded-read refusal", err)
	}
}

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestHTTPClientAppendsPrivateCAAndKeepsVerificationEnabled(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	bundlePath := writeTestServerCertificateBundle(t, server)
	client, err := newHTTPClient(Config{CABundlePath: bundlePath})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("agent transport disabled certificate verification")
	}

	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("private CA request failed: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status %d", response.StatusCode)
	}
}

func TestHTTPClientRejectsUntrustedCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := newHTTPClient(Config{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("expected unknown-authority rejection, got %v", err)
	}
}

func TestHTTPClientRejectsWrongHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := newHTTPClient(Config{CABundlePath: writeTestServerCertificateBundle(t, server)})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	serverAddress := server.Listener.Addr().String()
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, serverAddress)
	}

	response, err := client.Get("https://wrong-hostname.invalid/")
	if response != nil {
		response.Body.Close()
	}
	var hostnameError x509.HostnameError
	if !errors.As(err, &hostnameError) {
		t.Fatalf("expected hostname-verification rejection, got %v", err)
	}
}

func TestHTTPClientRejectsExpiredLeafCertificate(t *testing.T) {
	now := time.Now().UTC()
	root := issueTestCertificate(t, testCertificateOptions{
		commonName: "SHA test root",
		notBefore:  now.Add(-24 * time.Hour),
		notAfter:   now.Add(24 * time.Hour),
		isCA:       true,
	})
	leaf := issueTestCertificate(t, testCertificateOptions{
		commonName: "localhost",
		notBefore:  now.Add(-2 * time.Hour),
		notAfter:   now.Add(-time.Hour),
		parent:     &root,
		server:     true,
	})
	server := startTestTLSServer(t, leaf)
	defer server.Close()

	client, err := newHTTPClient(Config{CABundlePath: writeTestCertificateBundle(t, root)})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	var invalidCertificate x509.CertificateInvalidError
	if !errors.As(err, &invalidCertificate) || invalidCertificate.Reason != x509.Expired {
		t.Fatalf("expected expired-certificate rejection, got %v", err)
	}
}

func TestHTTPClientRejectsMissingIntermediateCertificate(t *testing.T) {
	now := time.Now().UTC()
	root := issueTestCertificate(t, testCertificateOptions{
		commonName: "SHA test root",
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(24 * time.Hour),
		isCA:       true,
	})
	intermediate := issueTestCertificate(t, testCertificateOptions{
		commonName: "SHA test intermediate",
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(12 * time.Hour),
		isCA:       true,
		parent:     &root,
	})
	leaf := issueTestCertificate(t, testCertificateOptions{
		commonName: "localhost",
		notBefore:  now.Add(-time.Hour),
		notAfter:   now.Add(time.Hour),
		parent:     &intermediate,
		server:     true,
	})
	server := startTestTLSServer(t, leaf)
	defer server.Close()

	client, err := newHTTPClient(Config{CABundlePath: writeTestCertificateBundle(t, root)})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("expected missing-intermediate rejection, got %v", err)
	}
}

func TestHTTPClientRejectsTLSBeforeVersion12(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MaxVersion: tls.VersionTLS11}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	client, err := newHTTPClient(Config{CABundlePath: writeTestServerCertificateBundle(t, server)})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("TLS 1.1 server was accepted")
	}
}

func TestHTTPClientRejectsInvalidCABundle(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(bundlePath, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newHTTPClient(Config{CABundlePath: bundlePath}); err == nil || !strings.Contains(err.Error(), "no valid PEM certificates") {
		t.Fatalf("unexpected invalid-bundle error: %v", err)
	}
	if _, err := newHTTPClient(Config{CABundlePath: "relative.pem"}); err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("unexpected relative-path error: %v", err)
	}
}

func TestHTTPClientRefusesRedirectBeforeCredentialForwarding(t *testing.T) {
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		targetCalls++
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client, err := newHTTPClient(Config{CABundlePath: writeTestServerCertificateBundle(t, source)})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, source.URL+"/api/endpoints/enroll", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer must-not-forward")
	response, err := client.Do(request)
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, errRedirectRefused) {
		t.Fatalf("expected redirect refusal, got %v", err)
	}
	if targetCalls != 0 {
		t.Fatalf("redirect target received %d request(s)", targetCalls)
	}
}

func writeTestServerCertificateBundle(t *testing.T, server *httptest.Server) string {
	t.Helper()
	bundlePath := filepath.Join(t.TempDir(), "private-ca.pem")
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	return bundlePath
}

type testCertificateOptions struct {
	commonName string
	notBefore  time.Time
	notAfter   time.Time
	isCA       bool
	parent     *testCertificate
	server     bool
}

type testCertificate struct {
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	raw         []byte
}

func issueTestCertificate(t *testing.T, options testCertificateOptions) testCertificate {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: options.commonName},
		NotBefore:             options.notBefore,
		NotAfter:              options.notAfter,
		BasicConstraintsValid: true,
		IsCA:                  options.isCA,
	}
	if options.isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if options.server {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	parentCertificate := template
	parentKey := privateKey
	if options.parent != nil {
		parentCertificate = options.parent.certificate
		parentKey = options.parent.privateKey
	}
	raw, err := x509.CreateCertificate(
		rand.Reader,
		template,
		parentCertificate,
		&privateKey.PublicKey,
		parentKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificate{certificate: certificate, privateKey: privateKey, raw: raw}
}

func startTestTLSServer(t *testing.T, leaf testCertificate) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.raw},
			PrivateKey:  leaf.privateKey,
			Leaf:        leaf.certificate,
		}},
		MinVersion: tls.VersionTLS12,
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	return server
}

func writeTestCertificateBundle(t *testing.T, certificate testCertificate) string {
	t.Helper()
	bundlePath := filepath.Join(t.TempDir(), "private-ca.pem")
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.raw})
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	return bundlePath
}
