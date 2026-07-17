//go:build windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	cryptProtectLocalMachine        = 0x4
	moveFileReplaceExisting         = 0x1
	moveFileWriteThrough            = 0x8
	fileAttributeReparsePoint       = 0x400
	seFileObject                    = 1
	ownerSecurityInformation        = 0x00000001
	daclSecurityInformation         = 0x00000004
	protectedDACLInformation        = 0x80000000
	securityDescriptorDACLProtected = 0x1000
	accessAllowedACEType            = 0x00
	objectInheritACE                = 0x01
	containerInheritACE             = 0x02
	inheritedACE                    = 0x10
	aclRevision                     = 2
	fileAllAccess                   = 0x001f01ff
)

var (
	stateDPAPIPrefix             = []byte("SHA-DPAPI-LOCAL-MACHINE-v1\x00")
	crypt32DLL                   = syscall.NewLazyDLL("crypt32.dll")
	kernel32DLL                  = syscall.NewLazyDLL("kernel32.dll")
	advapi32DLL                  = syscall.NewLazyDLL("advapi32.dll")
	cryptProtectDataProc         = crypt32DLL.NewProc("CryptProtectData")
	cryptUnprotectDataProc       = crypt32DLL.NewProc("CryptUnprotectData")
	localFreeProc                = kernel32DLL.NewProc("LocalFree")
	moveFileExProc               = kernel32DLL.NewProc("MoveFileExW")
	getNamedSecurityInfoProc     = advapi32DLL.NewProc("GetNamedSecurityInfoW")
	setNamedSecurityInfoProc     = advapi32DLL.NewProc("SetNamedSecurityInfoW")
	getSecurityDescriptorCtlProc = advapi32DLL.NewProc("GetSecurityDescriptorControl")
	getACEProc                   = advapi32DLL.NewProc("GetAce")
	convertStringSIDProc         = advapi32DLL.NewProc("ConvertStringSidToSidW")
	convertSIDToStringProc       = advapi32DLL.NewProc("ConvertSidToStringSidW")
	getLengthSIDProc             = advapi32DLL.NewProc("GetLengthSid")
	initializeACLProc            = advapi32DLL.NewProc("InitializeAcl")
	addAllowedACEProc            = advapi32DLL.NewProc("AddAccessAllowedAceEx")
)

type windowsDataBlob struct {
	length uint32
	data   *byte
}

type windowsACLHeader struct {
	revision  byte
	reserved  byte
	size      uint16
	aceCount  uint16
	reserved2 uint16
}

type windowsACEHeader struct {
	typeValue byte
	flags     byte
	size      uint16
}

type windowsAllowedACE struct {
	header   windowsACEHeader
	mask     uint32
	sidStart uint32
}

func encodeStatePayload(content []byte) ([]byte, error) {
	encrypted, err := protectDataForLocalMachine(content)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(stateDPAPIPrefix)+len(encrypted))
	result = append(result, stateDPAPIPrefix...)
	result = append(result, encrypted...)
	return result, nil
}

func decodeStatePayload(content []byte) ([]byte, error) {
	if !bytes.HasPrefix(content, stateDPAPIPrefix) {
		return nil, errors.New("device state is not protected with SHA DPAPI LocalMachine format")
	}
	return unprotectDataForLocalMachine(content[len(stateDPAPIPrefix):])
}

func protectDataForLocalMachine(content []byte) ([]byte, error) {
	input := dataBlob(content)
	var output windowsDataBlob
	success, _, callErr := cryptProtectDataProc.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		0,
		0,
		0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&output)),
	)
	runtime.KeepAlive(content)
	if success == 0 {
		return nil, fmt.Errorf("CryptProtectData failed: %w", callErr)
	}
	return copyAndFreeWindowsBlob(output), nil
}

func unprotectDataForLocalMachine(content []byte) ([]byte, error) {
	if len(content) == 0 {
		return nil, errors.New("DPAPI payload is empty")
	}
	input := dataBlob(content)
	var output windowsDataBlob
	success, _, callErr := cryptUnprotectDataProc.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&output)),
	)
	runtime.KeepAlive(content)
	if success == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", callErr)
	}
	return copyAndFreeWindowsBlob(output), nil
}

func dataBlob(content []byte) windowsDataBlob {
	blob := windowsDataBlob{length: uint32(len(content))}
	if len(content) > 0 {
		blob.data = &content[0]
	}
	return blob
}

func copyAndFreeWindowsBlob(blob windowsDataBlob) []byte {
	if blob.data == nil || blob.length == 0 {
		return []byte{}
	}
	defer localFreeProc.Call(uintptr(unsafe.Pointer(blob.data)))
	return append([]byte(nil), unsafe.Slice(blob.data, int(blob.length))...)
}

func platformValidatePrivateDirectory(path string, _ os.FileInfo) error {
	return validateWindowsPrivateACL(path, true)
}

func platformValidatePrivateFile(path string, _ os.FileInfo) error {
	return validateWindowsPrivateACL(path, false)
}

func platformProtectPrivateDirectory(path string) error {
	return setWindowsPrivateACL(path, true)
}

func platformProtectPrivateFile(path string) error {
	return setWindowsPrivateACL(path, false)
}

func setWindowsPrivateACL(path string, directory bool) error {
	systemSID, err := windowsSIDFromString("S-1-5-18")
	if err != nil {
		return err
	}
	defer localFreeProc.Call(uintptr(systemSID))
	administratorsSID, err := windowsSIDFromString("S-1-5-32-544")
	if err != nil {
		return err
	}
	defer localFreeProc.Call(uintptr(administratorsSID))

	systemSIDLength, err := windowsSIDLength(systemSID)
	if err != nil {
		return err
	}
	administratorsSIDLength, err := windowsSIDLength(administratorsSID)
	if err != nil {
		return err
	}
	aclSize := int(unsafe.Sizeof(windowsACLHeader{})) +
		8 + alignWindowsACLSize(systemSIDLength) +
		8 + alignWindowsACLSize(administratorsSIDLength)
	aclStorage := make([]byte, aclSize)
	aclPointer := unsafe.Pointer(&aclStorage[0])
	initialized, _, callErr := initializeACLProc.Call(
		uintptr(aclPointer),
		uintptr(len(aclStorage)),
		aclRevision,
	)
	if initialized == 0 {
		return fmt.Errorf("InitializeAcl failed: %w", callErr)
	}
	aceFlags := uintptr(0)
	if directory {
		aceFlags = objectInheritACE | containerInheritACE
	}
	for _, sid := range []unsafe.Pointer{systemSID, administratorsSID} {
		added, _, addErr := addAllowedACEProc.Call(
			uintptr(aclPointer),
			aclRevision,
			aceFlags,
			fileAllAccess,
			uintptr(sid),
		)
		if added == 0 {
			return fmt.Errorf("AddAccessAllowedAceEx failed: %w", addErr)
		}
	}

	pathPointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	result, _, _ := setNamedSecurityInfoProc.Call(
		uintptr(unsafe.Pointer(pathPointer)),
		seFileObject,
		ownerSecurityInformation|daclSecurityInformation|protectedDACLInformation,
		uintptr(administratorsSID),
		0,
		uintptr(aclPointer),
		0,
	)
	runtime.KeepAlive(aclStorage)
	if result != 0 {
		return fmt.Errorf("SetNamedSecurityInfoW failed: %w", syscall.Errno(result))
	}
	return validateWindowsPrivateACL(path, directory)
}

func validateWindowsPrivateACL(path string, directory bool) error {
	pathPointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var ownerSID unsafe.Pointer
	var daclPointer unsafe.Pointer
	var descriptorPointer unsafe.Pointer
	result, _, _ := getNamedSecurityInfoProc.Call(
		uintptr(unsafe.Pointer(pathPointer)),
		seFileObject,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&ownerSID)),
		0,
		uintptr(unsafe.Pointer(&daclPointer)),
		0,
		uintptr(unsafe.Pointer(&descriptorPointer)),
	)
	if result != 0 {
		return fmt.Errorf("GetNamedSecurityInfoW failed: %w", syscall.Errno(result))
	}
	if descriptorPointer == nil {
		return errors.New("Windows private path has no security descriptor")
	}
	defer localFreeProc.Call(uintptr(descriptorPointer))

	owner, err := windowsSIDString(ownerSID)
	if err != nil {
		return fmt.Errorf("inspect Windows private path owner: %w", err)
	}
	if owner != "S-1-5-18" && owner != "S-1-5-32-544" {
		return errors.New("Windows private path owner is not SYSTEM or Administrators")
	}
	if daclPointer == nil {
		return errors.New("Windows private path has a null DACL")
	}
	var descriptorControl uint16
	var revision uint32
	validControl, _, callErr := getSecurityDescriptorCtlProc.Call(
		uintptr(descriptorPointer),
		uintptr(unsafe.Pointer(&descriptorControl)),
		uintptr(unsafe.Pointer(&revision)),
	)
	if validControl == 0 {
		return fmt.Errorf("GetSecurityDescriptorControl failed: %w", callErr)
	}
	if descriptorControl&securityDescriptorDACLProtected == 0 {
		return errors.New("Windows private path DACL inherits permissions")
	}

	acl := (*windowsACLHeader)(daclPointer)
	if acl.aceCount != 2 {
		return fmt.Errorf("Windows private path DACL must contain exactly two ACEs, found %d", acl.aceCount)
	}
	expectedFlags := byte(0)
	if directory {
		expectedFlags = objectInheritACE | containerInheritACE
	}
	seen := map[string]bool{}
	for index := uint16(0); index < acl.aceCount; index++ {
		var acePointer unsafe.Pointer
		gotACE, _, aceErr := getACEProc.Call(
			uintptr(daclPointer),
			uintptr(index),
			uintptr(unsafe.Pointer(&acePointer)),
		)
		if gotACE == 0 {
			return fmt.Errorf("GetAce failed: %w", aceErr)
		}
		if acePointer == nil {
			return errors.New("Windows private path DACL contains a null ACE")
		}
		ace := (*windowsAllowedACE)(acePointer)
		if ace.header.typeValue != accessAllowedACEType ||
			ace.header.size < uint16(unsafe.Sizeof(windowsAllowedACE{})) ||
			ace.header.flags&inheritedACE != 0 ||
			ace.header.flags != expectedFlags ||
			ace.mask != fileAllAccess {
			return errors.New("Windows private path DACL contains an unexpected ACE")
		}
		sidPointer := unsafe.Pointer(uintptr(acePointer) + unsafe.Offsetof(ace.sidStart))
		sid, err := windowsSIDString(sidPointer)
		if err != nil {
			return fmt.Errorf("inspect Windows private path ACE SID: %w", err)
		}
		if (sid != "S-1-5-18" && sid != "S-1-5-32-544") || seen[sid] {
			return errors.New("Windows private path DACL grants an unexpected or duplicate principal")
		}
		seen[sid] = true
	}
	if !seen["S-1-5-18"] || !seen["S-1-5-32-544"] {
		return errors.New("Windows private path DACL is missing SYSTEM or Administrators")
	}
	return nil
}

func windowsSIDFromString(value string) (unsafe.Pointer, error) {
	valuePointer, err := syscall.UTF16PtrFromString(value)
	if err != nil {
		return nil, err
	}
	var sidPointer unsafe.Pointer
	success, _, callErr := convertStringSIDProc.Call(
		uintptr(unsafe.Pointer(valuePointer)),
		uintptr(unsafe.Pointer(&sidPointer)),
	)
	if success == 0 {
		return nil, fmt.Errorf("ConvertStringSidToSidW failed: %w", callErr)
	}
	return sidPointer, nil
}

func windowsSIDString(sid unsafe.Pointer) (string, error) {
	if sid == nil {
		return "", errors.New("SID is null")
	}
	var valuePointer *uint16
	success, _, callErr := convertSIDToStringProc.Call(
		uintptr(sid),
		uintptr(unsafe.Pointer(&valuePointer)),
	)
	if success == 0 {
		return "", fmt.Errorf("ConvertSidToStringSidW failed: %w", callErr)
	}
	defer localFreeProc.Call(uintptr(unsafe.Pointer(valuePointer)))
	return boundedWindowsUTF16String(valuePointer)
}

func boundedWindowsUTF16String(value *uint16) (string, error) {
	if value == nil {
		return "", errors.New("UTF-16 value is null")
	}
	for length := 0; length < 256; length++ {
		character := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(value)) + uintptr(length)*2))
		if character == 0 {
			return syscall.UTF16ToString(unsafe.Slice(value, length)), nil
		}
	}
	return "", errors.New("UTF-16 value exceeds the size limit")
}

func windowsSIDLength(sid unsafe.Pointer) (int, error) {
	length, _, callErr := getLengthSIDProc.Call(uintptr(sid))
	if length == 0 {
		return 0, fmt.Errorf("GetLengthSid failed: %w", callErr)
	}
	return int(length), nil
}

func alignWindowsACLSize(value int) int {
	return (value + 3) &^ 3
}

func platformReplacePrivateFile(source, destination string) error {
	sourcePointer, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPointer, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	success, _, callErr := moveFileExProc.Call(
		uintptr(unsafe.Pointer(sourcePointer)),
		uintptr(unsafe.Pointer(destinationPointer)),
		moveFileReplaceExisting|moveFileWriteThrough,
	)
	if success == 0 {
		return callErr
	}
	return nil
}

func platformSyncPrivateDirectory(_ string) error {
	// MoveFileExW with MOVEFILE_WRITE_THROUGH provides the Windows durability
	// boundary; opening a directory for fsync is not supported by os.File.
	return nil
}

func platformRejectReparsePathComponents(path string) error {
	if strings.HasPrefix(path, `\\`) {
		return errors.New("Windows private path must not use UNC storage")
	}
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume)
	if strings.ContainsAny(remainder, `:*?"<>|`) || strings.ContainsAny(remainder, "\x00\r\n") {
		return errors.New("Windows private path contains invalid or alternate-stream characters")
	}
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(remainder, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		pointer, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attributes, callErr := syscall.GetFileAttributes(pointer)
		if callErr != nil {
			if errors.Is(callErr, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(callErr, syscall.ERROR_PATH_NOT_FOUND) {
				continue
			}
			return fmt.Errorf("inspect Windows private path component: %w", callErr)
		}
		if attributes&fileAttributeReparsePoint != 0 {
			return fmt.Errorf("private path contains a Windows reparse point: %s", current)
		}
	}
	return nil
}
