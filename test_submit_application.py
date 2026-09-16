"""Tests for the application submitter.

The first test is the important one: it checks our serialization and signing
against the worked example B12 published, so the implementation is verified
against their spec rather than against itself.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import urllib.error
from datetime import datetime, timezone

import pytest

import submit_application as app

# Straight from B12's take-home PDF.
B12_EXAMPLE_PAYLOAD = {
    "timestamp": "2026-01-06T16:59:37.571Z",
    "name": "Your name",
    "email": "you@example.com",
    "resume_link": "https://pdf-or-html-or-linkedin.example.com",
    "repository_link": "https://link-to-github-or-other-forge.example.com/your/repository",
    "action_run_link": (
        "https://link-to-github-or-another-forge.example.com"
        "/your/repository/actions/runs/run_id"
    ),
}
B12_EXAMPLE_CANONICAL = (
    '{"action_run_link":"https://link-to-github-or-another-forge.example.com/your/'
    'repository/actions/runs/run_id","email":"you@example.com","name":"Your name",'
    '"repository_link":"https://link-to-github-or-other-forge.example.com/your/'
    'repository","resume_link":"https://pdf-or-html-or-linkedin.example.com",'
    '"timestamp":"2026-01-06T16:59:37.571Z"}'
)
B12_EXAMPLE_DIGEST = "c5db257a56e3c258ec1162459c9a295280871269f4cf70146d2c9f1b52671d45"
B12_SECRET = "REDACTED"

CI_ENV = {
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "someone/some-repo",
    "GITHUB_RUN_ID": "20561457327",
    app.SECRET_ENV_VAR: B12_SECRET,
}


@pytest.fixture(autouse=True)
def resume_link(monkeypatch):
    """Pin the resume link so tests do not depend on the real one."""
    monkeypatch.setattr(app, "RESUME_LINK", "https://resume.example.com/aidar.pdf")


class RecordingTransport:
    """Stands in for the network and keeps the request it was handed."""

    def __init__(self, status: int = 200, body: bytes = b'{"success": true, "receipt": "r-123"}'):
        self.status = status
        self.body = body
        self.request = None

    def __call__(self, request):
        self.request = request
        return self.status, self.body


def test_matches_b12s_published_example():
    """Canonicalization and signing reproduce B12's worked example exactly."""
    body = app.canonicalize(B12_EXAMPLE_PAYLOAD)
    assert body == B12_EXAMPLE_CANONICAL.encode("utf-8")
    assert app.sign(body, B12_SECRET) == f"sha256={B12_EXAMPLE_DIGEST}"


def test_signature_covers_the_bytes_actually_sent():
    """The header must sign the request's own body, not a re-serialization.

    This is the bug the whole design guards against: build a payload, hand it to
    an HTTP client that serializes it again, and the signature silently stops
    matching the body. Verifying the header against request.data closes that gap.
    """
    transport = RecordingTransport()
    app.submit(B12_EXAMPLE_PAYLOAD, B12_SECRET, transport=transport)

    sent = transport.request.data
    header = transport.request.get_header(app.SIGNATURE_HEADER.capitalize())
    recomputed = hmac.new(B12_SECRET.encode("utf-8"), sent, hashlib.sha256).hexdigest()

    assert header == f"sha256={recomputed}"
    assert json.loads(sent) == B12_EXAMPLE_PAYLOAD
    assert transport.request.get_method() == "POST"


def test_non_ascii_is_literal_utf8_not_escaped():
    """Non-ASCII stays as UTF-8 bytes rather than \\uXXXX escapes.

    B12's example is pure ASCII, so it passes under either json.dumps setting.
    This pins the reading of "UTF-8-encoded" that the example cannot decide.
    """
    body = app.canonicalize({**B12_EXAMPLE_PAYLOAD, "name": "Айдар Камалов"})
    assert "Айдар Камалов".encode("utf-8") in body
    assert b"\\u" not in body


@pytest.mark.parametrize(
    "moment,expected",
    [
        (datetime(2026, 1, 6, 16, 59, 37, 571000, tzinfo=timezone.utc), "2026-01-06T16:59:37.571Z"),
        (datetime(2026, 1, 6, 16, 59, 37, 0, tzinfo=timezone.utc), "2026-01-06T16:59:37.000Z"),
        (datetime(2026, 1, 6, 16, 59, 37, 999999, tzinfo=timezone.utc), "2026-01-06T16:59:37.999Z"),
    ],
)
def test_timestamp_is_iso8601_with_milliseconds(moment, expected):
    assert app.utc_timestamp(moment) == expected
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", app.utc_timestamp(moment))


def test_timestamp_converts_other_offsets_to_utc():
    from datetime import timedelta

    noon_in_bishkek = datetime(2026, 1, 6, 22, 59, 37, 571000, tzinfo=timezone(timedelta(hours=6)))
    assert app.utc_timestamp(noon_in_bishkek) == "2026-01-06T16:59:37.571Z"


def test_links_are_derived_from_the_running_job():
    payload = app.build_payload(CI_ENV)
    assert payload["repository_link"] == "https://github.com/someone/some-repo"
    assert payload["action_run_link"] == (
        "https://github.com/someone/some-repo/actions/runs/20561457327"
    )


@pytest.mark.parametrize("missing", ["GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"])
def test_missing_ci_environment_fails_loudly(missing):
    env = {key: value for key, value in CI_ENV.items() if key != missing}
    with pytest.raises(app.ConfigurationError, match=missing):
        app.build_payload(env)


def test_missing_secret_exits_misconfigured(capsys):
    env = {key: value for key, value in CI_ENV.items() if key != app.SECRET_ENV_VAR}
    assert app.main([], env=env, transport=RecordingTransport()) == app.EXIT_MISCONFIGURED
    assert app.SECRET_ENV_VAR in capsys.readouterr().err


def test_non_200_response_fails_the_run(capsys):
    transport = RecordingTransport(status=403, body=b'{"error": "bad signature"}')
    assert app.main([], env=CI_ENV, transport=transport) == app.EXIT_SUBMISSION_FAILED
    stderr = capsys.readouterr().err
    assert "403" in stderr
    assert "bad signature" in stderr


def test_unreachable_endpoint_fails_without_retrying(capsys):
    """A connection failure is reported once. It is never retried, because the
    endpoint has no idempotency key and a resend could double-submit."""
    attempts = []

    def refusing_transport(request):
        attempts.append(request)
        raise urllib.error.URLError("connection refused")

    assert app.main([], env=CI_ENV, transport=refusing_transport) == app.EXIT_SUBMISSION_FAILED
    assert len(attempts) == 1
    assert "connection refused" in capsys.readouterr().err


def test_successful_submission_prints_the_receipt(capsys):
    transport = RecordingTransport(body=b'{"success": true, "receipt": "abc-789"}')
    assert app.main([], env=CI_ENV, transport=transport) == 0
    assert "abc-789" in capsys.readouterr().out


def test_dry_run_posts_nothing_and_hides_the_secret(capsys):
    transport = RecordingTransport()
    assert app.main(["--dry-run"], env=CI_ENV, transport=transport) == 0
    stdout = capsys.readouterr().out
    assert transport.request is None
    assert "sha256=" in stdout
    assert B12_SECRET not in stdout
