from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import cast


_SAFE_RELEASE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_ARTIFACT_ID = re.compile(r"^ipa_[0-9a-f]{32}$")
_MAX_PACKAGE_BYTES = 512 * 1024 * 1024


class AgentPackageError(RuntimeError):
    pass


@dataclass(frozen=True)
class PublishedAgentPackage:
    platform: str
    architecture: str
    filename: str
    sha256: str
    size: int
    version: str
    signing_identity: str
    signing_key_id: str


def _secure_directory(path_text: str, label: str) -> Path:
    path = Path(path_text)
    if not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
        info = path.lstat()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} could not be resolved") from exc
    if resolved != path or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{label} must be a canonical non-symlink directory")
    if os.name == "posix":
        if info.st_mode & 0o077:
            raise ValueError(f"{label} must not grant group or world permissions")
        if info.st_uid not in {0, os.geteuid()}:
            raise ValueError(f"{label} has an untrusted owner")
    return resolved


@dataclass(frozen=True)
class AgentPackageProvider:
    release_root: Path
    trust_policy_file: Path
    profile_signing_key_file: Path
    profile_signing_identity: str
    profile_signing_key_id: str
    spool_root: Path
    profile_package_tool: Path
    ca_bundle_file: Path | None = None

    @classmethod
    def from_paths(
        cls,
        *,
        release_root: str,
        trust_policy_file: str,
        profile_signing_key_file: str,
        profile_signing_identity: str,
        profile_signing_key_id: str,
        spool_root: str,
        profile_package_tool: str,
        ca_bundle_file: str | None = None,
    ) -> "AgentPackageProvider":
        root = _secure_directory(release_root, "agent release root")
        spool = _secure_directory(spool_root, "agent package spool")
        trust = Path(trust_policy_file)
        signing_key = Path(profile_signing_key_file)
        tool = Path(profile_package_tool)
        for path, label in (
            (trust, "agent release trust policy"),
            (signing_key, "agent profile signing key"),
            (tool, "agent profile package tool"),
        ):
            if not path.is_absolute() or not path.is_file() or path.is_symlink():
                raise ValueError(f"{label} must be an absolute regular non-symlink file")
        if not os.access(tool, os.X_OK):
            raise ValueError("agent profile package tool must be executable")
        ca = Path(ca_bundle_file) if ca_bundle_file else None
        if ca is not None and (not ca.is_absolute() or not ca.is_file() or ca.is_symlink()):
            raise ValueError("agent profile CA bundle must be an absolute regular non-symlink file")
        if not profile_signing_identity or not profile_signing_key_id:
            raise ValueError("agent profile signing identity and key ID are required")
        return cls(
            release_root=root,
            trust_policy_file=trust.resolve(strict=True),
            profile_signing_key_file=signing_key.resolve(strict=True),
            profile_signing_identity=profile_signing_identity,
            profile_signing_key_id=profile_signing_key_id,
            spool_root=spool,
            profile_package_tool=tool.resolve(strict=True),
            ca_bundle_file=ca.resolve(strict=True) if ca is not None else None,
        )

    def _verified_index(self) -> dict[str, object]:
        verifier = self.release_root / "verify-release-index.sh"
        index = self.release_root / "release-index.json"
        signature = self.release_root / "release-index.json.sig"
        if not verifier.is_file() or verifier.is_symlink() or not os.access(verifier, os.X_OK):
            raise AgentPackageError("signed agent release catalog is not available")
        try:
            subprocess.run(
                [
                    str(verifier),
                    "--index",
                    str(index),
                    "--signature",
                    str(signature),
                    "--trust-policy",
                    str(self.trust_policy_file),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )
            payload = json.loads(index.read_text(encoding="utf-8"))
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            raise AgentPackageError("signed agent release catalog verification failed") from exc
        if not isinstance(payload, dict):
            raise AgentPackageError("signed agent release catalog is invalid")
        return payload

    def list_packages(self) -> list[PublishedAgentPackage]:
        payload = self._verified_index()
        version = payload.get("version")
        signing = payload.get("signing")
        rows = payload.get("packages")
        if (
            not isinstance(version, str)
            or _SAFE_RELEASE_VALUE.fullmatch(version) is None
            or not isinstance(signing, dict)
            or not isinstance(rows, list)
        ):
            raise AgentPackageError("signed agent release catalog metadata is invalid")
        signing_values = cast(dict[str, object], signing)
        identity = signing_values.get("identity")
        key_id = signing_values.get("key_id")
        if not isinstance(identity, str) or not isinstance(key_id, str):
            raise AgentPackageError("signed agent release identity is invalid")
        packages: list[PublishedAgentPackage] = []
        for row in rows:
            if not isinstance(row, dict):
                raise AgentPackageError("signed agent release package row is invalid")
            values = cast(dict[str, object], row)
            try:
                package = PublishedAgentPackage(
                    platform=str(values["platform"]),
                    architecture=str(values["architecture"]),
                    filename=str(values["file"]),
                    sha256=str(values["sha256"]),
                    size=int(cast(int | str, values["size"])),
                    version=version,
                    signing_identity=identity,
                    signing_key_id=key_id,
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise AgentPackageError("signed agent release package row is invalid") from exc
            packages.append(package)
        return packages

    def package(self, platform: str, architecture: str) -> PublishedAgentPackage:
        matches = [
            package
            for package in self.list_packages()
            if package.platform == platform and package.architecture == architecture
        ]
        if len(matches) != 1:
            raise AgentPackageError("requested signed agent package is not published")
        return matches[0]

    def read_generic(self, package: PublishedAgentPackage) -> bytes:
        path = self.release_root / package.filename
        if path.parent != self.release_root or not path.is_file() or path.is_symlink():
            raise AgentPackageError("signed agent package file is unavailable")
        if package.size > _MAX_PACKAGE_BYTES:
            raise AgentPackageError("signed agent package exceeds service size limit")
        content = path.read_bytes()
        if len(content) != package.size:
            raise AgentPackageError("signed agent package changed after verification")
        return content

    def create_personalized(
        self,
        *,
        artifact_id: str,
        package: PublishedAgentPackage,
        control_plane_url: str,
        enrollment_token: str,
        profile_id: str,
        client_id: str,
        location_id: str,
        approval_policy: str,
        max_uses: int,
        expires_at: str,
    ) -> tuple[str, Path]:
        if _SAFE_ARTIFACT_ID.fullmatch(artifact_id) is None:
            raise AgentPackageError("agent package artifact ID is invalid")
        suffix = ".zip" if package.platform == "windows" else ".tar.gz"
        filename = artifact_id + suffix
        output = self.spool_root / filename
        if output.exists() or output.is_symlink():
            raise AgentPackageError("agent package artifact already exists")
        stage = self.release_root / (
            f"sha-agent-{package.version}-{package.platform}-{package.architecture}"
        )
        arguments = [
            str(self.profile_package_tool),
            "--release-dir",
            str(stage),
            "--output",
            str(output),
            "--trust-policy",
            str(self.trust_policy_file),
            "--signing-key-file",
            str(self.profile_signing_key_file),
            "--signing-identity",
            self.profile_signing_identity,
            "--signing-key-id",
            self.profile_signing_key_id,
            "--control-plane-url",
            control_plane_url,
            "--enrollment-token-stdin",
            "--profile-id",
            profile_id,
            "--client-id",
            client_id,
            "--location-id",
            location_id,
            "--approval-policy",
            approval_policy,
            "--max-uses",
            str(max_uses),
            "--expires-at",
            expires_at,
        ]
        if self.ca_bundle_file is not None:
            arguments.extend(("--ca-bundle", str(self.ca_bundle_file)))
        try:
            subprocess.run(
                arguments,
                input=enrollment_token + "\n",
                text=True,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=90,
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "TMPDIR": str(self.spool_root),
                },
            )
            info = output.lstat()
        except (OSError, subprocess.SubprocessError) as exc:
            output.unlink(missing_ok=True)
            raise AgentPackageError("signed personalized agent package generation failed") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            output.unlink(missing_ok=True)
            raise AgentPackageError("signed personalized agent package output is unsafe")
        output.chmod(0o600)
        return filename, output

    def artifact_path(self, artifact_id: str, filename: str) -> Path:
        if _SAFE_ARTIFACT_ID.fullmatch(artifact_id) is None:
            raise AgentPackageError("agent package artifact ID is invalid")
        if filename not in {artifact_id + ".zip", artifact_id + ".tar.gz"}:
            raise AgentPackageError("agent package artifact filename is invalid")
        return self.spool_root / filename
