package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maximumStateFileBytes  = 64 * 1024
	maximumConfigFileBytes = 1024 * 1024
)

type stateStore struct {
	path string
}

func newStateStore(path string) (*stateStore, error) {
	normalized, err := normalizePrivateFilePath(path)
	if err != nil {
		return nil, err
	}
	return &stateStore{path: normalized}, nil
}

func defaultStatePath(configPath string) (string, error) {
	absoluteConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return "", fmt.Errorf("resolve config path: %w", err)
	}
	return filepath.Join(filepath.Dir(absoluteConfigPath), "agent-state.json"), nil
}

func (store *stateStore) Load() (*deviceState, error) {
	content, err := readPrivateFile(store.path, maximumStateFileBytes)
	if err != nil {
		return nil, err
	}
	content, err = decodeStatePayload(content)
	if err != nil {
		return nil, fmt.Errorf("decrypt device state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var state deviceState
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("decode device state: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode device state: %w", err)
	}
	if err := validateDeviceState(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (store *stateStore) Save(state *deviceState) error {
	if err := validateDeviceState(state); err != nil {
		return err
	}
	content, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode device state: %w", err)
	}
	content, err = encodeStatePayload(content)
	if err != nil {
		return fmt.Errorf("encrypt device state: %w", err)
	}
	if len(content) > maximumStateFileBytes {
		return errors.New("encoded device state exceeds the size limit")
	}
	return writeAtomicPrivateFile(store.path, content)
}

func clearBootstrapCredentialsFromConfig(path string) error {
	normalized, err := normalizePrivateFilePath(path)
	if err != nil {
		return err
	}
	content, err := readPrivateFile(normalized, maximumConfigFileBytes)
	if err != nil {
		return err
	}
	content = bytes.TrimPrefix(content, utf8ByteOrderMark)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		return fmt.Errorf("decode agent config: %w", err)
	}
	_, hasEnrollmentToken := fields["enrollment_token"]
	_, hasLegacyAPIToken := fields["api_token"]
	if !hasEnrollmentToken && !hasLegacyAPIToken {
		return nil
	}
	delete(fields, "enrollment_token")
	delete(fields, "api_token")
	rewritten, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agent config without enrollment token: %w", err)
	}
	rewritten = append(rewritten, '\n')
	return writeAtomicPrivateFile(normalized, rewritten)
}

func readPrivateFile(path string, maximumBytes int64) ([]byte, error) {
	normalized, err := normalizePrivateFilePath(path)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateDirectory(filepath.Dir(normalized)); err != nil {
		return nil, err
	}
	pathInfo, err := os.Lstat(normalized)
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, errors.New("private file must be a regular, non-symlink file")
	}
	file, err := os.Open(normalized)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened private file: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, errors.New("private file changed while it was being opened")
	}
	if err := platformValidatePrivateFile(normalized, openedInfo); err != nil {
		return nil, err
	}
	reader := io.LimitReader(file, maximumBytes+1)
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read private file: %w", err)
	}
	if int64(len(content)) > maximumBytes {
		return nil, errors.New("private file exceeds the size limit")
	}
	return content, nil
}

func writeAtomicPrivateFile(path string, content []byte) (returnErr error) {
	normalized, err := normalizePrivateFilePath(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(normalized)
	if err := validatePrivateDirectory(directory); err != nil {
		return err
	}
	if err := platformProtectPrivateDirectory(directory); err != nil {
		return err
	}
	if targetInfo, err := os.Lstat(normalized); err == nil {
		if targetInfo.Mode()&os.ModeSymlink != 0 || !targetInfo.Mode().IsRegular() {
			return errors.New("refusing to replace a non-regular or symlinked private file")
		}
		if err := platformValidatePrivateFile(normalized, targetInfo); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	temporary, err := os.CreateTemp(directory, ".sha-agent-private-*.tmp")
	if err != nil {
		return fmt.Errorf("create private temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	temporaryClosed := false
	defer func() {
		if !temporaryClosed {
			if closeErr := temporary.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict private temporary file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write private temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync private temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close private temporary file: %w", err)
	}
	temporaryClosed = true
	if err := platformProtectPrivateFile(temporaryPath); err != nil {
		return err
	}
	if err := platformReplacePrivateFile(temporaryPath, normalized); err != nil {
		return fmt.Errorf("atomically replace private file: %w", err)
	}
	removeTemporary = false
	if err := platformProtectPrivateFile(normalized); err != nil {
		return err
	}
	if err := platformSyncPrivateDirectory(directory); err != nil {
		return err
	}
	return nil
}

func normalizePrivateFilePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("private file path is required")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("private file path must be absolute")
	}
	cleaned := filepath.Clean(path)
	if cleaned != path {
		return "", errors.New("private file path must be normalized")
	}
	directory := filepath.Dir(cleaned)
	if directory == cleaned || filepath.Base(cleaned) == "." || filepath.Base(cleaned) == string(filepath.Separator) {
		return "", errors.New("private file path must name a file below a directory")
	}
	if err := rejectSymlinkPathComponents(cleaned); err != nil {
		return "", err
	}
	if err := platformRejectReparsePathComponents(cleaned); err != nil {
		return "", err
	}
	return cleaned, nil
}

func rejectSymlinkPathComponents(path string) error {
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume)
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(remainder, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect private path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("private path contains a symlink component: %s", current)
		}
	}
	return nil
}

func validatePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("private file parent must be a regular, non-symlink directory")
	}
	if err := platformValidatePrivateDirectory(path, info); err != nil {
		return err
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("unexpected trailing JSON data")
}
