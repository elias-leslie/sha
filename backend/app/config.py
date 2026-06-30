from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", env_prefix="SHA_")

    service_name: str = "sha-backend"
    version: str = "0.1.0"
    database_url: str = "sqlite:///data/sha.sqlite3"
    database_url_file: str | None = None
    port: int = 8010
    api_token: str | None = None
    api_token_file: str | None = None
    agent_api_token: str | None = None
    agent_api_token_file: str | None = None
    readonly_api_token: str | None = None
    readonly_api_token_file: str | None = None
    external_auth_trusted_token: str | None = None
    external_auth_trusted_token_file: str | None = None

    def from_file(self, value: str | None, file_path: str | None) -> str | None:
        if file_path:
            return Path(file_path).read_text(encoding="utf-8").strip() or None
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


@lru_cache

def get_settings() -> Settings:
    return Settings()
