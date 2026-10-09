from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    PROJECT_NAME: str = "AI Security Gateway & Linux Threat Defense"
    VERSION: str = "2.0.0"
    ENVIRONMENT: str = "development"

    # Base Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    RULES_DIR: Path = BASE_DIR / "rules"
    QUARANTINE_DIR: Path = BASE_DIR / "storage" / "quarantine"
    DATASET_DIR: Path = BASE_DIR / "dataset"

    # Database
    DATABASE_URL: str = "sqlite:///./dataset/security_research.db"

    # Linux Security Tools Configuration
    LINUX_SECURITY_ENABLED: bool = True
    YARA_ENABLED: bool = True
    CLAMAV_ENABLED: bool = True
    TSHARK_ENABLED: bool = False  # Disabled by default per requirements
    NETWORK_MONITOR_ENABLED: bool = False  # Disabled by default
    NETWORK_INTERFACE: str = "eth0"
    NETWORK_CAPTURE_SECONDS: int = 10

    # Resource & Security Limits
    MAX_FILE_SIZE_MB: int = 20
    SCANNER_TIMEOUT_SECONDS: int = 30
    MAX_EXTRACTED_TEXT_LENGTH: int = 500000

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = AppSettings()
