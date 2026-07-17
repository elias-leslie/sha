from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
import stat
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


def _open_secure_file(
    file_path: str,
    *,
    label: str,
    public_readable: bool = False,
) -> int:
    path = Path(file_path)
    if not path.is_absolute():
        raise ValueError(f"{label} file path must be absolute")
    try:
        resolved_path = path.resolve(strict=True)
        read_only_mount = bool(
            os.name == "posix"
            and os.statvfs(resolved_path).f_flag & os.ST_RDONLY
        )
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} file could not be resolved securely") from exc
    if resolved_path != path and not read_only_mount:
        raise ValueError(
            f"{label} file must use a canonical path with no symlink components; "
            "immutable read-only container mounts are the only exception"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved_path, flags)
    except OSError as exc:
        raise ValueError(f"{label} file could not be opened securely") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"{label} file must be a regular, non-symlink file")
        if os.name == "posix":
            if not public_readable and file_stat.st_mode & 0o077:
                raise ValueError(
                    f"{label} file must not grant group or world permissions"
                )
            if public_readable and file_stat.st_mode & 0o022:
                raise ValueError(f"{label} file must not be group- or world-writable")
            effective_uid = os.geteuid()
            if file_stat.st_uid not in {0, effective_uid} and not read_only_mount:
                raise ValueError(
                    f"{label} file must be owned by root or the service effective user unless mounted read-only"
                )
    except (OSError, ValueError):
        os.close(descriptor)
        raise
    return descriptor


def validate_secure_file_path(file_path: str, *, label: str) -> str:
    descriptor = _open_secure_file(file_path, label=label)
    os.close(descriptor)
    return file_path


def _read_secure_file(
    file_path: str,
    *,
    label: str,
    minimum_bytes: int,
    maximum_bytes: int,
    public_readable: bool,
) -> bytes:
    descriptor = _open_secure_file(
        file_path,
        label=label,
        public_readable=public_readable,
    )
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as secure_file:
            value = secure_file.read(maximum_bytes + 1).strip()
    finally:
        os.close(descriptor)
    if len(value) > maximum_bytes:
        raise ValueError(f"{label} file must not exceed {maximum_bytes} bytes")
    if len(value) < minimum_bytes:
        raise ValueError(f"{label} file must contain at least {minimum_bytes} bytes")
    return value


def read_secure_secret_file(
    file_path: str,
    *,
    label: str,
    minimum_bytes: int = 1,
    maximum_bytes: int = 4096,
) -> bytes:
    return _read_secure_file(
        file_path,
        label=label,
        minimum_bytes=minimum_bytes,
        maximum_bytes=maximum_bytes,
        public_readable=False,
    )


def read_secure_public_file(
    file_path: str,
    *,
    label: str,
    minimum_bytes: int = 1,
    maximum_bytes: int = 4 * 1024 * 1024,
) -> bytes:
    return _read_secure_file(
        file_path,
        label=label,
        minimum_bytes=minimum_bytes,
        maximum_bytes=maximum_bytes,
        public_readable=True,
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", env_prefix="SHA_")

    service_name: str = "sha-backend"
    version: str = "0.1.0"
    auth_mode: Literal["development_open", "protected"] = "development_open"
    database_url: str = "sqlite:///data/sha.sqlite3"
    database_url_file: str | None = None
    database_migration_mode: Literal["upgrade", "check"] = "upgrade"
    port: int = 8010
    api_token: str | None = None
    api_token_file: str | None = None
    agent_api_token: str | None = None
    agent_api_token_file: str | None = None
    readonly_api_token: str | None = None
    readonly_api_token_file: str | None = None
    external_auth_trusted_token: str | None = None
    external_auth_trusted_token_file: str | None = None
    credential_hmac_key_file: str | None = None
    public_base_url: str | None = None
    oidc_issuer: str | None = None
    oidc_metadata_url: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_client_secret_file: str | None = None
    oidc_ca_bundle_file: str | None = None
    browser_session_key_file: str | None = None
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    oidc_login_ttl_minutes: int = 10
    legacy_reporter_mode: Literal["disabled", "migration"] = "disabled"
    legacy_reporter_compatibility_until: str | None = None
    device_credential_lifetime_days: int = 90
    agent_release_root: str | None = None
    agent_release_trust_policy_file: str | None = None
    agent_profile_signing_key_file: str | None = None
    agent_profile_signing_identity: str | None = None
    agent_profile_signing_key_id: str | None = None
    agent_package_spool_root: str | None = None
    agent_profile_package_tool: str | None = None
    agent_profile_ca_bundle_file: str | None = None

    def from_file(self, value: str | None, file_path: str | None) -> str | None:
        if file_path:
            return read_secure_secret_file(
                file_path,
                label="configuration secret",
                maximum_bytes=16_384,
            ).decode("utf-8") or None
        return value or None

    def resolved_database_url(self) -> str:
        return self.from_file(self.database_url, self.database_url_file) or self.database_url

    def resolved_api_token(self) -> str | None:
        return self.from_file(self.api_token, self.api_token_file)

    def resolved_agent_api_token(self) -> str | None:
        return self.from_file(self.agent_api_token, self.agent_api_token_file)

    def resolved_readonly_api_token(self) -> str | None:
        return self.from_file(self.readonly_api_token, self.readonly_api_token_file)

    def resolved_external_auth_trusted_token(self) -> str | None:
        return self.from_file(self.external_auth_trusted_token, self.external_auth_trusted_token_file)

    def resolved_credential_hmac_key(self) -> bytes | None:
        if not self.credential_hmac_key_file:
            return None
        return read_secure_secret_file(
            self.credential_hmac_key_file,
            label="credential HMAC key",
            minimum_bytes=32,
        )

    def resolved_oidc_client_secret(self) -> str | None:
        if self.oidc_client_secret_file:
            return read_secure_secret_file(
                self.oidc_client_secret_file,
                label="OIDC client secret",
            ).decode("utf-8")
        return self.oidc_client_secret or None

    def resolved_browser_session_key(self) -> bytes | None:
        if not self.browser_session_key_file:
            return None
        return read_secure_secret_file(
            self.browser_session_key_file,
            label="browser session key",
            minimum_bytes=32,
        )


@lru_cache

def get_settings() -> Settings:
    return Settings()
