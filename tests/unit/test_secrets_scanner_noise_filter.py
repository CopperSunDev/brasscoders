"""Unit tests for the detect-secrets stderr noise filter (Phase A, 2026-05-16).

A real-customer scan against whisperx-production produced 212 customer-
visible ``[scan] ERROR No plugins to scan with!`` lines on stderr. The
detect-secrets library installs its own stderr handler (clearing the
root logger's handlers) and logs that line every time ``scan_file``
fires before a worker thread's plugin context is fully populated. The
plugin issue is benign (subsequent calls succeed and produce real
findings); the user-visible noise is not.

The fix attaches a ``logging.Filter`` to detect-secrets's named logger
that drops just the noise line while leaving every other detect-secrets
log intact.
"""

from __future__ import annotations

import logging

import pytest

from brass.scanners.secrets_scanner import (
    _DetectSecretsNoiseFilter,
    _silence_detect_secrets_noise,
)


def _make_record(msg: str, name: str = "detect-secrets") -> logging.LogRecord:
    return logging.LogRecord(
        name=name,
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )


def test_filter_drops_no_plugins_message():
    """The exact noise line is suppressed."""
    f = _DetectSecretsNoiseFilter()
    assert f.filter(_make_record("No plugins to scan with!")) is False


def test_filter_drops_substring_match():
    """Match-by-substring tolerates surrounding context (timestamps,
    prefixes from future detect-secrets versions, etc.)."""
    f = _DetectSecretsNoiseFilter()
    record = _make_record("[scan] ERROR No plugins to scan with! (filename=foo.py)")
    assert f.filter(record) is False


def test_filter_keeps_unrelated_messages():
    """Every other detect-secrets log line passes through — including
    real errors the customer should see."""
    f = _DetectSecretsNoiseFilter()
    assert f.filter(_make_record("Unable to load plugins!")) is True
    assert f.filter(_make_record("Some other error message")) is True
    assert f.filter(_make_record("Secret detected at foo.py:42")) is True


def test_filter_does_not_raise_on_format_error():
    """Malformed records (e.g. msg with %s but no args) must not crash
    the filter pipeline — false return is safer than a logging
    handler explosion."""
    f = _DetectSecretsNoiseFilter()
    # `LogRecord.getMessage()` raises TypeError when format args are
    # missing; the filter must swallow and let the record through.
    bad = logging.LogRecord(
        name="detect-secrets", level=logging.ERROR, pathname=__file__,
        lineno=1, msg="bad %s %d", args=("only-one",), exc_info=None,
    )
    assert f.filter(bad) is True


@pytest.fixture
def detect_secrets_logger_snapshot():
    """Snapshot + restore the ``'detect-secrets'`` logger's filters AND
    handlers so tests that install/remove filters don't leak state to
    sibling tests (pytest test-order isn't guaranteed)."""
    target = logging.getLogger("detect-secrets")
    saved_filters = list(target.filters)
    saved_handler_filters = [
        (h, list(h.filters)) for h in target.handlers
    ]
    try:
        # Clean slate for the test.
        target.filters = [
            f for f in target.filters
            if not isinstance(f, _DetectSecretsNoiseFilter)
        ]
        for h in target.handlers:
            h.filters = [
                f for f in h.filters
                if not isinstance(f, _DetectSecretsNoiseFilter)
            ]
        yield target
    finally:
        target.filters = saved_filters
        for h, original_filters in saved_handler_filters:
            h.filters = list(original_filters)


def test_silence_is_idempotent(detect_secrets_logger_snapshot):
    """Calling :func:`_silence_detect_secrets_noise` more than once
    (each :class:`SecretsScanner` construction calls it) must not
    duplicate the filter on the logger — otherwise repeated calls
    would slow log handling unboundedly."""
    target = detect_secrets_logger_snapshot
    _silence_detect_secrets_noise()
    _silence_detect_secrets_noise()
    _silence_detect_secrets_noise()
    count = sum(
        1 for f in target.filters
        if isinstance(f, _DetectSecretsNoiseFilter)
    )
    assert count == 1


def test_silence_targets_named_logger_not_root(detect_secrets_logger_snapshot):
    """The filter is attached to the named ``'detect-secrets'`` logger
    so other libraries' (and brass's own) logging is unaffected."""
    target = detect_secrets_logger_snapshot
    _silence_detect_secrets_noise()
    root = logging.getLogger()
    target_has = any(
        isinstance(f, _DetectSecretsNoiseFilter) for f in target.filters
    )
    root_has = any(
        isinstance(f, _DetectSecretsNoiseFilter) for f in root.filters
    )
    assert target_has is True
    assert root_has is False


def test_silence_attaches_filter_to_handlers_too(detect_secrets_logger_snapshot):
    """Phase A hardening (post-/full-bugs): the filter is attached to
    BOTH the named logger AND its handlers, so a customer's
    ``logging.config.dictConfig(disable_existing_loggers=True)`` that
    wipes logger filters can't reopen the noise channel via the
    handler that detect-secrets installs directly on its logger."""
    target = detect_secrets_logger_snapshot
    # Inject a synthetic handler to verify handler-attach path.
    dummy_handler = logging.NullHandler()
    target.addHandler(dummy_handler)
    try:
        _silence_detect_secrets_noise()
        assert any(
            isinstance(f, _DetectSecretsNoiseFilter)
            for f in dummy_handler.filters
        )
    finally:
        target.removeHandler(dummy_handler)
