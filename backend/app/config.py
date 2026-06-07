from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", env_prefix="SHA_")

    service_name: str = "sha-backend"
    version: str = "0.1.0"
    database_url: str = "sqlite:///data/sha.sqlite3"
    port: int = 8010


@lru_cache

def get_settings() -> Settings:
    return Settings()
