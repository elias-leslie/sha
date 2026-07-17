#!/usr/bin/env python3
"""Create and validate SHA agent release and bootstrap manifests.

Only Python's standard library is used. Cryptographic signing and signature
verification stay in OpenSSL (POSIX) or .NET (Windows); this helper owns the
strict JSON/path/digest contract shared by release tooling and installers.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit


RELEASE_SCHEMA = "sha-agent-release-manifest-v1"
INDEX_SCHEMA = "sha-agent-release-index-v1"
BOOTSTRAP_SCHEMA = "sha-agent-bootstrap-manifest-v1"
TRUST_POLICY_SCHEMA = "sha-agent-trust-policy-v1"
SIGNATURE_ALGORITHM = "rsa-pkcs1v15-sha256"
TOKEN_RE = re.compile(r"sha_enroll\.(et_[0-9a-f]{32})\.([A-Za-z0-9_-]{43,128})")
SAFE_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@:/+-]{0,255}")
ALLOWED_BOOTSTRAP_EXTRAS = {
    "bootstrap-manifest.json",
    "bootstrap-manifest.json.sig",
    "bootstrap-ca.pem",
}


class ContractError(ValueError):
    pass


def fail(message: str) -> None:
    raise ContractError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def public_key_fingerprint(path: Path) -> str:
    strict_file(path, "public key")
    text = path.read_text(encoding="ascii")
    match = re.fullmatch(
        r"\s*-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END PUBLIC KEY-----\s*",
        text,
    )
    if match is None:
        fail("public key must use SubjectPublicKeyInfo PUBLIC KEY PEM format")
    try:
        der = base64.b64decode(re.sub(r"\s", "", match.group(1)), validate=True)
    except (ValueError, binascii.Error):
        fail("public key PEM base64 is invalid")
    return "sha256:" + hashlib.sha256(der).hexdigest()


def canonical_token(value: str) -> tuple[str, str]:
    match = TOKEN_RE.fullmatch(value)
    if match is None:
        fail("enrollment token has an invalid format")
    secret = match.group(2)
    try:
        raw = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
    except (ValueError, binascii.Error):
        fail("enrollment token secret is invalid base64url")
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if len(raw) < 32 or canonical != secret:
        fail("enrollment token secret is not canonical or is too short")
    return match.group(1), value


def strict_file(path: Path, label: str, *, secret: bool = False) -> Path:
    absolute = path.absolute()
    for parent in (absolute, *absolute.parents):
        try:
            if stat.S_ISLNK(parent.lstat().st_mode):
                fail(f"{label} path contains a symlink: {parent}")
        except FileNotFoundError:
            continue
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is missing: {path}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail(f"{label} must be a regular non-symlink file: {path}")
    if secret and info.st_mode & 0o077:
        fail(f"{label} must not grant group or other permissions: {path}")
    if secret and hasattr(os, "geteuid") and info.st_uid not in {0, os.geteuid()}:
        fail(f"{label} must be owned by root or the current effective user: {path}")
    return path


def safe_value(value: str, label: str) -> str:
    value = value.strip()
    if not SAFE_VALUE_RE.fullmatch(value):
        fail(f"{label} contains unsupported characters or has an unsafe length")
    return value


def write_json(path: Path, payload: object, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} must be an RFC3339 timestamp")
    if parsed.tzinfo is None:
        fail(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def normalized_https_url(value: str, allow_insecure_loopback: bool = False) -> str:
    value = value.strip()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        fail("control-plane URL is invalid")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        fail("control-plane URL must have a host and no user info, query, or fragment")
    if parsed.path not in ("", "/"):
        fail("control-plane URL must not contain a path")
    hostname = parsed.hostname.lower()
    if parsed.scheme == "https":
        pass
    elif not (
        parsed.scheme == "http"
        and allow_insecure_loopback
        and hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        fail("control-plane URL must use HTTPS (HTTP requires explicit loopback mode)")
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


def load_json(path: Path, label: str, maximum_bytes: int = 1024 * 1024) -> dict[str, object]:
    strict_file(path, label)
    if path.stat().st_size > maximum_bytes:
        fail(f"{label} is too large")
    try:
        raw = path.read_text(encoding="utf-8")
        def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    fail(f"{label} contains duplicate JSON key: {key}")
                result[key] = value
            return result

        payload = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    if not isinstance(payload, dict):
        fail(f"{label} must be a JSON object")
    return payload


def signing_block(identity: str, key_id: str, public_key: Path) -> dict[str, str]:
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "identity": safe_value(identity, "signing identity"),
        "key_id": safe_value(key_id, "signing key ID"),
        "public_key_fingerprint": public_key_fingerprint(public_key),
    }


def artifact_rows(root: Path, excluded: set[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            fail(f"release staging directory contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            fail(f"release staging directory contains a non-regular file: {relative}")
        if relative in excluded:
            continue
        rows.append({"path": relative, "sha256": sha256_file(path), "size": info.st_size})
    return rows


def create_release(args: argparse.Namespace) -> None:
    stage = Path(args.stage).resolve()
    if not stage.is_dir() or stage.is_symlink():
        fail("release stage must be a non-symlink directory")
    created_at = parse_timestamp(args.created_at, "release creation time")
    manifest = {
        "architecture": safe_value(args.architecture, "architecture"),
        "artifacts": artifact_rows(
            stage,
            {"release-manifest.json", "release-manifest.json.sig"} | ALLOWED_BOOTSTRAP_EXTRAS,
        ),
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "platform": safe_value(args.platform, "platform"),
        "product": "sha-agent",
        "schema_version": RELEASE_SCHEMA,
        "signing": signing_block(args.signing_identity, args.key_id, Path(args.public_key)),
        "version": safe_value(args.version, "version"),
    }
    write_json(Path(args.output), manifest)


def validate_signing(
    payload: dict[str, object], expected_identity: str, expected_key_id: str, public_key: Path
) -> None:
    signing = payload.get("signing")
    if not isinstance(signing, dict):
        fail("manifest signing metadata is missing")
    if signing.get("algorithm") != SIGNATURE_ALGORITHM:
        fail("manifest signature algorithm is unsupported")
    if signing.get("identity") != expected_identity:
        fail("manifest signing identity does not match the pinned identity")
    if signing.get("key_id") != expected_key_id:
        fail("manifest signing key ID does not match the selected trusted key")
    if signing.get("public_key_fingerprint") != public_key_fingerprint(public_key):
        fail("manifest public key fingerprint does not match the trusted public key")


def resolve_trust_values(manifest_path: Path, policy_path: Path) -> dict[str, str]:
    policy_file = strict_file(policy_path, "trust policy")
    policy_info = policy_file.stat()
    if policy_info.st_mode & 0o022:
        fail("trust policy must not be group- or world-writable")
    if hasattr(os, "geteuid") and policy_info.st_uid not in {0, os.geteuid()}:
        fail("trust policy must be owned by root or the current effective user")
    if hasattr(os, "geteuid"):
        for parent in policy_file.absolute().parents:
            try:
                parent_info = parent.stat()
            except FileNotFoundError:
                continue
            if parent_info.st_uid not in {0, os.geteuid()}:
                fail(f"trust policy parent has an untrusted owner: {parent}")
            if parent_info.st_mode & 0o022 and not parent_info.st_mode & stat.S_ISVTX:
                fail(f"trust policy parent is replaceable by group or other users: {parent}")
    manifest = load_json(manifest_path, "signed manifest")
    signing = manifest.get("signing")
    if not isinstance(signing, dict):
        fail("signed manifest has no signing metadata")
    policy = load_json(policy_file, "trust policy", 128 * 1024)
    if policy.get("schema_version") != TRUST_POLICY_SCHEMA:
        fail("trust policy schema is unsupported")
    identity = safe_value(str(policy.get("expected_signing_identity", "")), "expected signing identity")
    if signing.get("identity") != identity:
        fail("manifest signing identity is not allowed by trust policy")
    fingerprint = str(signing.get("public_key_fingerprint", ""))
    revoked = policy.get("revoked_fingerprints", [])
    if not isinstance(revoked, list) or not all(isinstance(item, str) for item in revoked):
        fail("trust policy revoked_fingerprints must be a string list")
    if fingerprint in revoked:
        fail("manifest signing key is explicitly revoked")
    keys = policy.get("trusted_keys")
    if not isinstance(keys, list) or not keys:
        fail("trust policy trusted_keys must be a non-empty list")
    matches: list[dict[str, object]] = []
    for key in keys:
        if not isinstance(key, dict):
            fail("trust policy contains an invalid trusted key")
        if key.get("key_id") == signing.get("key_id") and key.get("fingerprint") == fingerprint:
            matches.append(key)
    if len(matches) != 1:
        fail("manifest signing key is not uniquely allowlisted by key ID and fingerprint")
    relative = matches[0].get("public_key_file")
    if not isinstance(relative, str):
        fail("trusted key public_key_file is invalid")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or relative != pure.as_posix() or ".." in pure.parts or "." in pure.parts:
        fail("trusted key public_key_file is unsafe")
    public_key = policy_file.resolve().parent.joinpath(*pure.parts)
    strict_file(public_key, "allowlisted public key")
    actual_fingerprint = public_key_fingerprint(public_key)
    if actual_fingerprint != fingerprint or matches[0].get("fingerprint") != actual_fingerprint:
        fail("allowlisted public key fingerprint does not match key bytes")
    return {
        "expected_identity": identity,
        "fingerprint": fingerprint,
        "key_id": str(signing.get("key_id", "")),
        "public_key": str(public_key.resolve()),
    }


def resolve_trust(args: argparse.Namespace) -> None:
    values = resolve_trust_values(Path(args.manifest), Path(args.trust_policy))
    print(values[args.field])


def print_fingerprint(args: argparse.Namespace) -> None:
    print(public_key_fingerprint(Path(args.public_key)))


def verify_release(args: argparse.Namespace) -> None:
    manifest_path = Path(args.manifest).resolve()
    root = manifest_path.parent
    payload = load_json(manifest_path, "release manifest")
    if payload.get("schema_version") != RELEASE_SCHEMA or payload.get("product") != "sha-agent":
        fail("release manifest schema or product is unsupported")
    validate_signing(payload, args.expected_identity, args.expected_key_id, Path(args.public_key))
    rows = payload.get("artifacts")
    if not isinstance(rows, list) or not rows:
        fail("release manifest artifact list is empty or invalid")
    expected_paths: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            fail("release manifest contains an invalid artifact row")
        relative = row.get("path")
        if not isinstance(relative, str):
            fail("release manifest artifact path is invalid")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or relative != pure.as_posix() or ".." in pure.parts or "." in pure.parts:
            fail("release manifest artifact path is unsafe")
        if relative in expected_paths:
            fail("release manifest contains a duplicate artifact path")
        expected_paths.add(relative)
        target = root.joinpath(*pure.parts)
        strict_file(target, f"release artifact {relative}")
        if target.stat().st_size != row.get("size") or sha256_file(target) != row.get("sha256"):
            fail(f"release artifact failed digest verification: {relative}")
    actual_paths: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            fail(f"release contains a symlink: {relative}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            fail(f"release contains a non-regular file: {relative}")
        actual_paths.add(relative)
    allowed = expected_paths | {
        "release-manifest.json",
        "release-manifest.json.sig",
    } | ALLOWED_BOOTSTRAP_EXTRAS
    unexpected = sorted(actual_paths - allowed)
    if unexpected:
        fail(f"release contains unlisted files: {', '.join(unexpected)}")


def create_index(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir).resolve()
    packages: list[dict[str, object]] = []
    for specification in args.package:
        parts = specification.split(":", 2)
        if len(parts) != 3:
            fail("release package specification must be platform:architecture:filename")
        platform, architecture, filename = parts
        pure = PurePosixPath(filename)
        if pure.is_absolute() or len(pure.parts) != 1 or filename != pure.as_posix():
            fail("release package filename must be a safe output-directory basename")
        package = strict_file(output_dir / filename, "release package")
        packages.append(
            {
                "architecture": safe_value(architecture, "architecture"),
                "file": filename,
                "platform": safe_value(platform, "platform"),
                "sha256": sha256_file(package),
                "size": package.stat().st_size,
            }
        )
    payload = {
        "created_at": parse_timestamp(args.created_at, "release creation time")
        .isoformat()
        .replace("+00:00", "Z"),
        "packages": sorted(packages, key=lambda row: (str(row["platform"]), str(row["architecture"]))),
        "product": "sha-agent",
        "schema_version": INDEX_SCHEMA,
        "signing": signing_block(args.signing_identity, args.key_id, Path(args.public_key)),
        "version": safe_value(args.version, "version"),
    }
    write_json(Path(args.output), payload)


def verify_index(args: argparse.Namespace) -> None:
    index_path = Path(args.index).resolve()
    payload = load_json(index_path, "release index")
    if payload.get("schema_version") != INDEX_SCHEMA or payload.get("product") != "sha-agent":
        fail("release index schema or product is unsupported")
    validate_signing(payload, args.expected_identity, args.expected_key_id, Path(args.public_key))
    packages = payload.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("release index package list is empty or invalid")
    seen: set[str] = set()
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("file"), str):
            fail("release index package row is invalid")
        filename = str(package["file"])
        pure = PurePosixPath(filename)
        if pure.is_absolute() or len(pure.parts) != 1 or filename != pure.as_posix() or filename in seen:
            fail("release index package filename is unsafe or duplicated")
        seen.add(filename)
        target = strict_file(index_path.parent / filename, "indexed release package")
        if target.stat().st_size != package.get("size") or sha256_file(target) != package.get("sha256"):
            fail(f"release package failed index digest verification: {filename}")


def read_token(path: Path) -> str:
    strict_file(path, "enrollment-token file", secret=True)
    if path.stat().st_size > 4096:
        fail("enrollment-token file is too large")
    token = path.read_text(encoding="utf-8").strip()
    return canonical_token(token)[1]


def create_bootstrap(args: argparse.Namespace) -> None:
    now = parse_timestamp(args.created_at, "bootstrap creation time")
    expires = parse_timestamp(args.expires_at, "bootstrap expiry time")
    lifetime = (expires - now).total_seconds()
    if lifetime <= 0 or lifetime > 24 * 60 * 60:
        fail("bootstrap expiry must be after creation and no more than 24 hours later")
    token_id, token = canonical_token(read_token(Path(args.token_file)))
    release_manifest = load_json(Path(args.release_manifest), "release manifest")
    if release_manifest.get("schema_version") != RELEASE_SCHEMA:
        fail("bootstrap release manifest has an unsupported schema")
    if release_manifest.get("platform") != args.platform or release_manifest.get("architecture") != args.architecture:
        fail("bootstrap platform/architecture does not match release manifest")
    if not 1 <= args.max_uses <= 1000:
        fail("bootstrap max uses must be between 1 and 1000")
    if args.approval_policy not in {"pending", "approved"}:
        fail("bootstrap approval policy must be pending or approved")
    payload: dict[str, object] = {
        "architecture": safe_value(args.architecture, "architecture"),
        "approval_policy": args.approval_policy,
        "client_id": safe_value(args.client_id, "client ID"),
        "control_plane_url": normalized_https_url(args.control_plane_url),
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "enrollment_token": token,
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "location_id": safe_value(args.location_id, "location ID"),
        "max_uses": args.max_uses,
        "platform": safe_value(args.platform, "platform"),
        "profile_id": safe_value(args.profile_id, "profile ID"),
        "release_manifest_sha256": sha256_file(Path(args.release_manifest)),
        "release_version": safe_value(str(release_manifest.get("version", "")), "release version"),
        "schema_version": BOOTSTRAP_SCHEMA,
        "signing": signing_block(args.signing_identity, args.key_id, Path(args.public_key)),
        "token_id": token_id,
    }
    if args.ca_bundle:
        bundle = strict_file(Path(args.ca_bundle), "bootstrap CA bundle")
        payload["ca_bundle"] = {"file": "bootstrap-ca.pem", "sha256": sha256_file(bundle)}
    write_json(Path(args.output), payload, 0o600)


def write_config(args: argparse.Namespace) -> None:
    token = read_token(Path(args.token_file))
    config: dict[str, object] = {
        "agent_version": safe_value(args.agent_version, "agent version"),
        "allow_insecure_loopback": bool(args.allow_insecure_loopback),
        "control_plane_url": normalized_https_url(args.control_plane_url, args.allow_insecure_loopback),
        "enrollment_token": token,
        "profile_id": safe_value(args.profile_id, "profile ID"),
        "service_context": "system_service",
        "state_path": args.state_path,
    }
    if args.ca_bundle_path:
        config["ca_bundle_path"] = args.ca_bundle_path
    if args.platform == "linux":
        config["sshd_hardening_path"] = "/etc/ssh/sshd_config.d/99-sha-hardening.conf"
    elif args.platform == "windows":
        config["windows_firewall_rollback_path"] = r"C:\ProgramData\SHA\firewall-profiles-rollback.json"
    write_json(Path(args.output), config, 0o600)


def validate_config(args: argparse.Namespace) -> None:
    payload = load_json(Path(args.config), "agent config", 1024 * 1024)
    if "device_credential" in payload or "credential_secret" in payload:
        fail("installer-managed config must never contain a long-lived device credential")
    normalized_https_url(
        str(payload.get("control_plane_url", "")), bool(payload.get("allow_insecure_loopback", False))
    )
    for secret_field in ("enrollment_token", "api_token"):
        value = payload.get(secret_field)
        if value not in (None, "") and not isinstance(value, str):
            fail(f"agent config {secret_field} must be a string")
    if payload.get("enrollment_token"):
        canonical_token(str(payload["enrollment_token"]))


def bootstrap_config(args: argparse.Namespace) -> None:
    payload = load_json(Path(args.manifest), "bootstrap manifest", 64 * 1024)
    if payload.get("schema_version") != BOOTSTRAP_SCHEMA:
        fail("bootstrap manifest schema is unsupported")
    validate_signing(payload, args.expected_identity, args.expected_key_id, Path(args.public_key))
    if payload.get("platform") != args.platform or payload.get("architecture") != args.architecture:
        fail("bootstrap manifest platform or architecture does not match this package")
    now = datetime.now(timezone.utc)
    created = parse_timestamp(str(payload.get("created_at", "")), "bootstrap creation time")
    expires = parse_timestamp(str(payload.get("expires_at", "")), "bootstrap expiry time")
    if expires <= now or expires <= created or (expires - created).total_seconds() > 24 * 60 * 60:
        fail("bootstrap manifest is expired or has an invalid lifetime")
    token_id, token = canonical_token(str(payload.get("enrollment_token", "")))
    if payload.get("token_id") != token_id:
        fail("bootstrap token ID does not match embedded enrollment token")
    if payload.get("approval_policy") not in {"pending", "approved"}:
        fail("bootstrap approval policy is invalid")
    if not isinstance(payload.get("max_uses"), int) or not 1 <= int(payload["max_uses"]) <= 1000:
        fail("bootstrap max uses is invalid")
    for field in ("client_id", "location_id", "release_version", "release_manifest_sha256"):
        if not isinstance(payload.get(field), str) or not payload[field]:
            fail(f"bootstrap {field} metadata is missing")
    release_manifest_path = Path(args.release_manifest)
    release_manifest = load_json(release_manifest_path, "release manifest")
    if (
        release_manifest.get("version") != payload.get("release_version")
        or sha256_file(release_manifest_path) != payload.get("release_manifest_sha256")
    ):
        fail("bootstrap manifest is bound to a different SHA agent release")
    ca = payload.get("ca_bundle")
    if ca is not None:
        if not isinstance(ca, dict) or ca.get("file") != "bootstrap-ca.pem":
            fail("bootstrap CA metadata is invalid")
        source = Path(args.manifest).resolve().parent / "bootstrap-ca.pem"
        strict_file(source, "bootstrap CA bundle")
        if sha256_file(source) != ca.get("sha256"):
            fail("bootstrap CA bundle failed digest verification")
    elif args.ca_bundle_path:
        fail("bootstrap manifest does not contain the requested CA bundle")
    write_json(Path(args.output), {
        "agent_version": safe_value(args.agent_version, "agent version"),
        "allow_insecure_loopback": False,
        "control_plane_url": normalized_https_url(str(payload.get("control_plane_url", ""))),
        "enrollment_token": token,
        "profile_id": safe_value(str(payload.get("profile_id", "")), "profile ID"),
        "service_context": "system_service",
        "state_path": args.state_path,
        **({"ca_bundle_path": args.ca_bundle_path} if args.ca_bundle_path else {}),
        **(
            {"sshd_hardening_path": "/etc/ssh/sshd_config.d/99-sha-hardening.conf"}
            if args.platform == "linux"
            else {"windows_firewall_rollback_path": r"C:\ProgramData\SHA\firewall-profiles-rollback.json"}
        ),
    }, 0o600)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    release = commands.add_parser("create-release")
    for name in ("stage", "version", "platform", "architecture", "created-at", "signing-identity", "key-id", "public-key", "output"):
        release.add_argument(f"--{name}", required=True)
    release.set_defaults(func=create_release)

    verify = commands.add_parser("verify-release")
    for name in ("manifest", "public-key", "expected-identity", "expected-key-id"):
        verify.add_argument(f"--{name}", required=True)
    verify.set_defaults(func=verify_release)

    index = commands.add_parser("create-index")
    for name in ("output-dir", "version", "created-at", "signing-identity", "key-id", "public-key", "output"):
        index.add_argument(f"--{name}", required=True)
    index.add_argument("--package", action="append", required=True)
    index.set_defaults(func=create_index)

    verify_index_parser = commands.add_parser("verify-index")
    for name in ("index", "public-key", "expected-identity", "expected-key-id"):
        verify_index_parser.add_argument(f"--{name}", required=True)
    verify_index_parser.set_defaults(func=verify_index)

    bootstrap = commands.add_parser("create-bootstrap")
    for name in (
        "control-plane-url", "token-file", "profile-id", "client-id", "location-id", "platform",
        "architecture", "created-at", "expires-at", "signing-identity", "key-id", "public-key",
        "release-manifest", "approval-policy", "output",
    ):
        bootstrap.add_argument(f"--{name}", required=True)
    bootstrap.add_argument("--ca-bundle")
    bootstrap.add_argument("--max-uses", type=int, required=True)
    bootstrap.set_defaults(func=create_bootstrap)

    config = commands.add_parser("write-config")
    for name in (
        "control-plane-url", "token-file", "profile-id", "platform", "agent-version", "state-path", "output",
    ):
        config.add_argument(f"--{name}", required=True)
    config.add_argument("--ca-bundle-path")
    config.add_argument("--allow-insecure-loopback", action="store_true")
    config.set_defaults(func=write_config)

    validate = commands.add_parser("validate-config")
    validate.add_argument("--config", required=True)
    validate.set_defaults(func=validate_config)

    embedded = commands.add_parser("bootstrap-config")
    for name in (
        "manifest", "release-manifest", "expected-identity", "expected-key-id", "public-key", "platform",
        "architecture", "agent-version", "state-path", "output",
    ):
        embedded.add_argument(f"--{name}", required=True)
    embedded.add_argument("--ca-bundle-path")
    embedded.set_defaults(func=bootstrap_config)

    trust = commands.add_parser("resolve-trust")
    for name in ("manifest", "trust-policy"):
        trust.add_argument(f"--{name}", required=True)
    trust.add_argument(
        "--field",
        required=True,
        choices=("public_key", "expected_identity", "key_id", "fingerprint"),
    )
    trust.set_defaults(func=resolve_trust)

    fingerprint = commands.add_parser("fingerprint")
    fingerprint.add_argument("--public-key", required=True)
    fingerprint.set_defaults(func=print_fingerprint)
    return root


def main() -> int:
    try:
        arguments = parser().parse_args()
        arguments.func(arguments)
    except (ContractError, OSError) as error:
        print(f"sha-agent package error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
