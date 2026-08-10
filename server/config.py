# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Server configuration.

Everything comes from the environment. Nothing that is a secret has a default —
a deployment that forgets to set SESSION_SECRET must fail loudly at startup
rather than silently run on a value an attacker can read in this file.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class Settings:
    db_dsn: str = field(default_factory=lambda: os.getenv("DB_DSN", ""))
    session_secret: str = field(default_factory=lambda: os.getenv("SESSION_SECRET", ""))

    #: Upload cap. A scan bundle is a set of small CSV/JSON exports; anything of
    #: this size is a mistake or an attack, and refusing early beats filling the
    #: disk and then discovering it.
    max_upload_bytes: int = field(default_factory=lambda: _int("MAX_UPLOAD_BYTES", 256 * 1024 * 1024))
    max_upload_files: int = field(default_factory=lambda: _int("MAX_UPLOAD_FILES", 500))

    session_ttl_hours: int = field(default_factory=lambda: _int("SESSION_TTL_HOURS", 12))
    upload_dir: Path = field(default_factory=lambda: Path(os.getenv("UPLOAD_DIR", str(ROOT / "var" / "uploads"))))

    #: Bound on concurrent scan jobs. A scan is CPU-bound Python; letting an
    #: impatient user queue twenty of them starves the web tier that has to
    #: render their progress.
    max_concurrent_scans: int = field(default_factory=lambda: _int("MAX_CONCURRENT_SCANS", 2))

    def validate(self) -> None:
        missing = [n for n, v in (("DB_DSN", self.db_dsn),
                                  ("SESSION_SECRET", self.session_secret)) if not v]
        if missing:
            raise RuntimeError(
                f"missing required environment variable(s): {', '.join(missing)}. "
                "See docker-compose.yml and .env.example."
            )
        if len(self.session_secret) < 32:
            raise RuntimeError(
                "SESSION_SECRET must be at least 32 characters. Generate one with: "
                "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )


settings = Settings()
