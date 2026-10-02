"""Runtime settings: secrets from environment (.env), everything else from YAML in config/."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    tz: str = "Europe/Paris"
    log_level: str = "INFO"
    config_dir: Path = Field(Path("config"), validation_alias="CTI_CONFIG_DIR")

    postgres_db: str = "cti"
    postgres_user: str = "cti"
    postgres_password: SecretStr = SecretStr("")
    postgres_host: str = "db"
    postgres_port: int = 5432
    database_url: SecretStr = SecretStr("")

    anthropic_api_key: SecretStr = SecretStr("")
    anthropic_model: str = "claude-opus-5-5"
    anthropic_effort: str = "low"

    nvd_api_key: SecretStr = SecretStr("")
    github_token: SecretStr = SecretStr("")
    vulncheck_api_key: SecretStr = SecretStr("")

    teams_webhook_url_fr: SecretStr = SecretStr("")
    teams_webhook_url_kr: SecretStr = SecretStr("")

    web_admin_user: str = "admin"
    web_admin_password: SecretStr = SecretStr("")

    @property
    def db_url(self) -> str:
        if self.database_url.get_secret_value():
            return self.database_url.get_secret_value()
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password.get_secret_value()}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    def secret(self, name: str) -> str:
        """Return a secret value by settings field name ('' when unset)."""
        value = getattr(self, name, None)
        if isinstance(value, SecretStr):
            return value.get_secret_value()
        return value or ""

    def all_secret_values(self) -> list[str]:
        return [
            v.get_secret_value()
            for v in self.__dict__.values()
            if isinstance(v, SecretStr) and len(v.get_secret_value()) >= 6
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
