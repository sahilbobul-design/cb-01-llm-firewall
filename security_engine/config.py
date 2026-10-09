from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class EngineSettings(BaseSettings):
    PROJECT_NAME: str = "LLM Security Analysis Engine & Threat Gateway"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"

    # Engine Host & Port (Runs on 8002 to avoid collision with dataset platform on 8001)
    ENGINE_HOST: str = "0.0.0.0"
    ENGINE_PORT: int = 8002

    # Dataset Platform API URL
    DATASET_API_URL: str = "http://localhost:8001"

    # Security Scanners Config
    BASE_DIR: Path = Path(__file__).resolve().parent
    RULES_DIR: Path = BASE_DIR / "rules"
    CLAMAV_SOCKET: str = "/var/run/clamav/clamd.ctl"
    CLAMAV_BINARY: str = "clamscan"
    YARA_BINARY: str = "yara"

    # Database for Engine Scan Logs
    DATABASE_URL: str = "sqlite:///./dataset/security_engine_logs.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


engine_settings = EngineSettings()
