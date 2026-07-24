"""Tests for notifier and posture services."""

from app.services.notifier import (
    LogNotifier,
    MultiNotifier,
    NotificationContext,
    get_notifier,
)


def test_log_notifier_succeeds():
    n = LogNotifier()
    assert n.send(
        NotificationContext(
            scan_id="x", image="alpine:3.20", status="NON_COMPLIANT",
            critical=1, high=2, kev=0,
        )
    ) is True


def test_multi_notifier_swallows_failures():
    class Bad:
        name = "bad"
        def send(self, ctx):
            raise RuntimeError("boom")

    m = MultiNotifier([Bad(), LogNotifier()])
    assert m.send(
        NotificationContext(
            scan_id="x", image="alpine:3.20", status="COMPLIANT",
            critical=0, high=0, kev=0,
        )
    ) is False


def test_get_notifier_returns_singleton():
    a = get_notifier()
    b = get_notifier()
    assert a is b
