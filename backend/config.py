from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "LLM Security Research Dataset Platform"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"

    # Database
    # Default to PostgreSQL for Docker / production.
    # Can be overridden via .env, e.g., DATABASE_URL=postgresql://user:pass@localhost:5432/llm_security
    # or SQLite for local offline testing: sqlite:///./dataset/security_research.db
    DATABASE_URL: str = "postgresql://postgres:postgres@db:5432/llm_security"

    # API Configuration
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    PAGE_SIZE_DEFAULT: int = 50
    PAGE_SIZE_MAX: int = 200

    # Base Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    DATASET_DIR: Path = BASE_DIR / "dataset"
    RAW_DIR: Path = DATASET_DIR / "raw"
    PROCESSED_DIR: Path = DATASET_DIR / "processed"
    MANIFESTS_DIR: Path = DATASET_DIR / "manifests"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
