"""Structured JSON logging with secret redaction.

Every log record goes through a filter that replaces any configured secret
value (API keys, webhook URLs, passwords) with '***', so a secret embedded in
an exception message or URL can never reach the logs.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime

_STD_ATTRS = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}
# Defense in depth: query-string style secrets even if not in settings.
_GENERIC_SECRET_RE = re.compile(r"(?i)((?:api[_-]?key|token|sig|secret|password)=)[^&\s\"']+")


class RedactingFilter(logging.Filter):
    def __init__(self, secrets: list[str]):
        super().__init__()
        self.secrets = sorted(set(secrets), key=len, reverse=True)

    def redact(self, text: str) -> str:
        for s in self.secrets:
            text = text.replace(s, "***")
        return _GENERIC_SECRET_RE.sub(r"\1***", text)

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.redact(record.getMessage())
        record.args = ()
        for key, value in list(record.__dict__.items()):
            if key not in _STD_ATTRS and isinstance(value, str):
                setattr(record, key, self.redact(value))
        if record.exc_info and record.exc_info[1] is not None:
            record.exc_text = self.redact(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STD_ATTRS:
                payload[key] = value
        if record.exc_text:
            payload["exc"] = record.exc_text
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(level: str = "INFO", secrets: list[str] | None = None) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter(secrets or []))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for noisy in ("httpx", "httpcore", "apscheduler.executors", "anthropic._base_client", "alembic.runtime.plugins"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
