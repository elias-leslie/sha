package main

import (
	"reflect"
	"testing"
)

func TestCapabilityManifestVersionsOnlyTruthfulPlatformCapabilities(t *testing.T) {
	originalPlatform := currentPlatformName
	t.Cleanup(func() { currentPlatformName = originalPlatform })

	tests := []struct {
		platform string
		wantIDs  []string
	}{
		{
			platform: "linux",
			wantIDs: []string{
				"enroll",
				"heartbeat",
				"collect_posture_snapshot",
				"rollback_control:" + linuxLegacySSHControlID,
			},
		},
		{
			platform: "macos",
			wantIDs:  []string{"enroll", "heartbeat", "collect_posture_snapshot"},
		},
		{
			platform: "windows",
			wantIDs: []string{
				"enroll",
				"heartbeat",
				"collect_posture_snapshot",
				"apply_control:" + windowsFirewallControlID,
				"rollback_control:" + windowsFirewallControlID,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.platform, func(t *testing.T) {
			currentPlatformName = func() string { return test.platform }
			manifest := buildCapabilityManifest("system_service")
			if manifest.SchemaVersion != capabilityManifestSchemaVersion {
				t.Fatalf("unexpected schema: %s", manifest.SchemaVersion)
			}
			gotIDs := make([]string, 0, len(manifest.Capabilities))
			for _, capability := range manifest.Capabilities {
				gotIDs = append(gotIDs, capability.ID)
				if !reflect.DeepEqual(capability.Versions, []string{"1"}) {
					t.Fatalf("capability %s has unversioned declaration: %#v", capability.ID, capability.Versions)
				}
			}
			if !reflect.DeepEqual(gotIDs, test.wantIDs) {
				t.Fatalf("unexpected %s capabilities: %#v", test.platform, gotIDs)
			}
			if manifest.Features.Terminal || manifest.Features.EvidenceUpload {
				t.Fatal("unfinished terminal/evidence features must not be advertised")
			}
			if manifest.Runtime.ServiceContext != "system_service" {
				t.Fatalf("unexpected service context: %s", manifest.Runtime.ServiceContext)
			}
		})
	}
}
