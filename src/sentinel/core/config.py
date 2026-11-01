"""Wardwire configuration management using pydantic-settings."""

from __future__ import annotations

from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core metadata
    PROJECT_NAME: str = "Wardwire"
    ENV: str = "development"
    DEBUG: bool = False

    # Security & Pseudonymisation
    SECRET_SALT: str = Field(
        default="wardwire-default-dev-salt-change-in-production-32b",
        description="HMAC salt used for pseudonymising IP addresses and subnets",
    )
    JWT_SECRET: str = Field(
        default="wardwire-jwt-secret-key-32bytes-long-change-me",
        description="Secret key for dashboard session tokens",
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 480
    INGEST_API_KEY: str = Field(
        default="ww_ingest_key_dev_secret_abc123",
        description="API key required for POST /v1/events",
    )
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD_HASH: str = Field(
        # Default dev bcrypt hash for 'admin123' if not explicitly configured
        default="$2b$12$eDxQf8jJekrK37Z.5G8p7e1l769bHvh9Hw4C5G/ePqNlM2kX7BhyO",
        description="Bcrypt hash of admin password",
    )

    # Persistence & Streaming
    DATABASE_URL: str = "sqlite:///./wardwire.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_STREAM_NAME: str = "sentinel:events"
    REDIS_STREAM_GROUP: str = "sentinel_workers"
    REDIS_CONSUMER_NAME: str = "worker-1"

    # Simulator & Target
    TARGET_URL: str = "http://localhost:8000"
    API_URL: str = "http://localhost:8001"
    SIM_ALLOWED_TARGETS: List[str] = [
        "localhost",
        "127.0.0.1",
        "target",
        "target:8000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://target:8000",
    ]
    SIM_MAX_RPS: int = 2000

    # Policy & Operating Mode
    OPERATING_MODE: str = Field(
        default="shadow",
        description="'shadow' (record would-have-blocked only) or 'simulated-enforce'",
    )
    ALERT_BUDGET_HOURLY: int = 20
    RATE_LIMIT_LOGIN_MAX: int = 10  # per minute
    RATE_LIMIT_INGEST_MAX: int = 5000  # batch items per sec

    # Detection Thresholds & Calibration
    VOLUMETRIC_Z_THRESHOLD: float = 3.0
    CREDENTIAL_STUFFING_FAIL_RATIO: float = 0.65
    CREDENTIAL_STUFFING_MIN_FAILURES: int = 15
    BOLA_MONOTONIC_RATIO: float = 0.60
    BOLA_MIN_OBJECTS: int = 5
    SCRAPING_MIN_RESOURCES: int = 20
    SCRAPING_CV_THRESHOLD: float = 0.25  # Low timing variance indicates bot
    PROBING_404_THRESHOLD: int = 10
    DATA_EXFIL_BYTES_Z_THRESHOLD: float = 3.0

    # Benign Discriminator weights
    BENIGN_SUPPRESSION_K: float = 0.85

    # Memory & Cardinality Limits (Detector self-protection)
    CARDINALITY_MAX_KEYS: int = 10000
    SLIDING_WINDOW_SEC_SHORT: int = 10
    SLIDING_WINDOW_SEC_MID: int = 60
    SLIDING_WINDOW_SEC_LONG: int = 300

    # LLM Settings (P1, optional, default OFF)
    LLM_PROVIDER: str = "none"  # "none", "ollama", "litellm"
    LLM_MODEL: str = "claude-sonnet-5-5"
    LLM_BASE_URL: str = "http://localhost:11434"

    # Retention
    RETENTION_DAYS_ALERTS: int = 7
    RETENTION_HOURS_RAW: int = 24


settings = Settings()

