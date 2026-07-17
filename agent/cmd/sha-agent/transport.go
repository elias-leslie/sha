package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var errRedirectRefused = errors.New("SHA agent refuses HTTP redirects")

func normalizeControlPlaneURL(rawURL string, allowInsecureLoopback bool) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", errors.New("control_plane_url is required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("control_plane_url is invalid: %w", err)
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("control_plane_url must be an absolute URL with a host")
	}
	if parsed.User != nil {
		return "", errors.New("control_plane_url must not contain user information")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return "", errors.New("control_plane_url must not contain a query")
	}
	if parsed.Fragment != "" || strings.Contains(rawURL, "#") {
		return "", errors.New("control_plane_url must not contain a fragment")
	}

	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "https":
	case "http":
		hostname := strings.ToLower(parsed.Hostname())
		loopback := hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
		if !allowInsecureLoopback || !loopback {
			return "", errors.New(
				"control_plane_url requires HTTPS; insecure HTTP is allowed only for explicit localhost, 127.0.0.1, or ::1 development",
			)
		}
	default:
		return "", errors.New("control_plane_url requires the https scheme")
	}

	parsed.Scheme = scheme
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = strings.TrimRight(parsed.RawPath, "/")
	return parsed.String(), nil
}

func newHTTPClient(config Config) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.CABundlePath != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA roots: %w", err)
		}
		bundle, err := readValidatedCABundle(config.CABundlePath)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(bundle) {
			return nil, errors.New("ca_bundle_path contains no valid PEM certificates")
		}
		tlsConfig.RootCAs = roots
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport has an unexpected type")
	}
	clonedTransport := transport.Clone()
	clonedTransport.TLSClientConfig = tlsConfig
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: clonedTransport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirectRefused
		},
	}, nil
}

func readValidatedCABundle(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("ca_bundle_path must be absolute")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect ca_bundle_path: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, errors.New("ca_bundle_path must be a regular, non-symlink file")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ca_bundle_path: %w", err)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened ca_bundle_path: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, errors.New("ca_bundle_path changed while it was being opened")
	}
	if err := validateCABundleFileSecurity(path, openedInfo); err != nil {
		return nil, err
	}
	bundle, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read ca_bundle_path: %w", err)
	}
	return bundle, nil
}
