"""Application configuration loaded from environment variables with safe defaults.

This module provides a centralized, typed configuration object for all security,
storage, and runtime settings.
"""

import os
from pathlib import Path
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Settings dataclass holding application configuration.

    PROTOTYPE LIMITATION: In production, settings would be loaded from a dedicated
    secrets manager (e.g., HashiCorp Vault or AWS Secrets Manager) and support
    automatic key rotation rather than reading flat environment variables and local files.
    """

    # Path to SQLite database file
    db_path: Path = Path(os.getenv("DB_PATH", "./intentlock.db"))

    # Directory storing Ed25519 cryptographic keypairs
    keys_dir: Path = Path(os.getenv("KEYS_DIR", "./keys"))

    # Token validity duration in seconds (default: 300s = 5 minutes)
    # Tokens expire after this duration to minimize the window for potential token abuse.
    token_ttl_seconds: int = int(os.getenv("TOKEN_TTL_SECONDS", "300"))

    # Permissible clock skew tolerance in seconds
    # Prevents legitimate requests from failing due to minor server clock drift.
    clock_skew_seconds: int = int(os.getenv("CLOCK_SKEW_SECONDS", "5"))

    # Merchant identifier for this store instance
    store_id: str = os.getenv("STORE_ID", "demo-store")

    # Flag to enable demo reset / simulation helper endpoints
    demo_mode: bool = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")


# Global singleton settings instance
settings = Settings()
