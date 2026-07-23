"""Structured logging with secret masking."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from app.config import get_settings

_SECRET_PATTERNS = [
    re.compile(r"(password[=:]\s*)([^\s,&]+)", re.I),
    re.compile(r"(token[=:]\s*)([^\s,&]+)", re.I),
    re.compile(r"(authorization[=:]\s*basic\s+)([^\s]+)", re.I),
    re.compile(r"(authorization[=:]\s*bearer\s+)([^\s]+)", re.I),
    re.compile(r"(api[_-]?key[=:]\s*)([^\s,&]+)", re.I),
    re.compile(r'("auth"\s*:\s*")([^"]+)(")', re.I),
]


def mask_secrets(text: str) -> str:
    if not text:
        return text
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(r"\1***", result)
    return result


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        settings = get_settings()
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": getattr(record, "service", settings.service_name),
            "message": mask_secrets(record.getMessage()),
        }
        for key in ("scan_id", "image", "digest", "stage"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = mask_secrets(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(service_name: str | None = None) -> None:
    settings = get_settings()
    if service_name:
        settings.service_name = service_name
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


class ScanLogAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: Any) -> tuple[str, Any]:
        extra = kwargs.setdefault("extra", {})
        for key, value in self.extra.items():
            extra.setdefault(key, value)
        return mask_secrets(str(msg)), kwargs
