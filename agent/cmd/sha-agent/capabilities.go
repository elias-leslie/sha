package main

import "strings"

const capabilityManifestSchemaVersion = "sha-agent-capabilities-v1"

type capabilityDescriptor struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Versions []string `json:"versions"`
}

type capabilityRuntime struct {
	Privilege      string `json:"privilege"`
	ServiceContext string `json:"service_context"`
}

type capabilityFeatures struct {
	EvidenceUpload bool `json:"evidence_upload"`
	Terminal       bool `json:"terminal"`
}

type capabilityResourceLimits struct {
	MaxConcurrentJobs  int `json:"max_concurrent_jobs"`
	MaxOutputBytes     int `json:"max_output_bytes"`
	MaxUploadBytes     int `json:"max_upload_bytes"`
	CommandTimeoutSecs int `json:"command_timeout_seconds"`
}

type capabilityHealth struct {
	State   string   `json:"state"`
	Reasons []string `json:"reasons"`
}

type agentCapabilityManifest struct {
	SchemaVersion  string                   `json:"schema_version"`
	Capabilities   []capabilityDescriptor   `json:"capabilities"`
	Runtime        capabilityRuntime        `json:"runtime"`
	Features       capabilityFeatures       `json:"features"`
	ResourceLimits capabilityResourceLimits `json:"resource_limits"`
	Health         capabilityHealth         `json:"health"`
}

func buildCapabilityManifest(serviceContext string) agentCapabilityManifest {
	capabilities := make([]capabilityDescriptor, 0, len(declaredCapabilities()))
	for _, id := range declaredCapabilities() {
		kind := "core"
		switch {
		case id == "collect_posture_snapshot":
			kind = "collector"
		case strings.HasPrefix(id, "apply_control:") || strings.HasPrefix(id, "rollback_control:"):
			kind = "action"
		}
		capabilities = append(capabilities, capabilityDescriptor{
			ID:       id,
			Kind:     kind,
			Versions: []string{"1"},
		})
	}
	return agentCapabilityManifest{
		SchemaVersion: capabilityManifestSchemaVersion,
		Capabilities:  capabilities,
		Runtime: capabilityRuntime{
			Privilege:      currentPrivilegeContext(),
			ServiceContext: serviceContext,
		},
		Features: capabilityFeatures{
			EvidenceUpload: false,
			Terminal:       false,
		},
		ResourceLimits: capabilityResourceLimits{
			MaxConcurrentJobs:  1,
			MaxOutputBytes:     64 * 1024,
			MaxUploadBytes:     0,
			CommandTimeoutSecs: 30,
		},
		Health: capabilityHealth{State: "healthy", Reasons: []string{}},
	}
}
