import {
  actionableControlsForEndpoint,
  type ControlRegistryItem,
} from "../lib/api"

describe("control registry action filtering", () => {
  it("never presents operational observations as executable controls", () => {
    const controls: ControlRegistryItem[] = [
      {
        control_id: "control.windows.firewall-all-profiles",
        title: "Windows firewall all profiles",
        platform: "windows",
        kind: "benchmark_control",
        observation_aliases: [],
        supported_actions: ["apply_control"],
      },
      {
        control_id: "windows.telemetry.process-inventory",
        title: "Windows process inventory",
        platform: "windows",
        kind: "operational_observation",
        observation_aliases: [],
        supported_actions: ["apply_control"],
      },
    ]

    expect(
      actionableControlsForEndpoint(
        controls,
        "windows",
        "apply_control",
        [
          "apply_control:control.windows.firewall-all-profiles",
          "apply_control:windows.telemetry.process-inventory",
        ],
      ).map((control) => control.control_id),
    ).toEqual(["control.windows.firewall-all-profiles"])
  })
})
