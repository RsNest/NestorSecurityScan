"""Notifier interface for scan events.

Default implementation is a no-op logger. Concrete transports (SMTP,
Telegram, Slack) can be added in v3 by implementing Notifier.send().
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

logger = logging.getLogger(__name__)


@dataclass
class NotificationContext:
    scan_id: str
    image: str
    status: str
    critical: int
    high: int
    kev: int


class Notifier(Protocol):
    name: str

    def send(self, ctx: NotificationContext) -> bool:
        ...


class LogNotifier:
    name = "log"

    def send(self, ctx: NotificationContext) -> bool:
        logger.info(
            "scan=%s image=%s status=%s critical=%s high=%s kev=%s",
            ctx.scan_id,
            ctx.image,
            ctx.status,
            ctx.critical,
            ctx.high,
            ctx.kev,
        )
        return True


class MultiNotifier:
    def __init__(self, notifiers: list[Notifier] | None = None):
        self.notifiers: list[Notifier] = list(notifiers) if notifiers else [LogNotifier()]

    def send(self, ctx: NotificationContext) -> bool:
        ok = True
        for n in self.notifiers:
            try:
                n.send(ctx)
            except Exception:  # noqa: BLE001
                logger.exception("Notifier %s failed", getattr(n, "name", n))
                ok = False
        return ok


_default: MultiNotifier | None = None


def get_notifier() -> MultiNotifier:
    global _default
    if _default is None:
        _default = MultiNotifier()
    return _default
