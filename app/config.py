"""Application configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SIH_", env_file=".env", extra="ignore")

    app_name: str = "SIH26 Cybersecurity Assistant API"
    app_version: str = "0.1.0"
    debug: bool = False
    api_prefix: str = "/api/v1"
    module_timeout_seconds: float = 30.0
    use_mock_modules: bool = True
    log_level: str = "INFO"


settings = Settings()
