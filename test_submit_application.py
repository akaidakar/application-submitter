"""Network-free tests for payload signing and submission handling."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.error
from datetime import datetime, timedelta, timezone

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

# The exercise publishes a worked example: the payload above, a signing key,
# and the digest they produce. The exercise treats the key as a secret, so it
# never appears here. The digest test reads it from the same environment
# variable the submission uses and skips when it is absent.
PUBLISHED_EXAMPLE_KEY = os.environ.get(app.SECRET_ENV_VAR)

# Every other test signs with a different key, so none of them can pass by
# accidentally depending on the published one.
TEST_SECRET = "test-signing-key"

CI_ENV = {
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "someone/some-repo",
    "GITHUB_RUN_ID": "20561457327",
    app.SECRET_ENV_VAR: TEST_SECRET,
}

APPLICANT_ARGS = [
    "--name", "Some Applicant",
    "--email", "applicant@example.com",
    "--resume-link", "https://resume.example.com/applicant.pdf",
]
NAME, EMAIL, RESUME_LINK = APPLICANT_ARGS[1::2]


class FakeTransport:
    """Stands in for the network. Answers with a response or raises an error."""

    def __init__(self, status=200, body=b'{"success": true, "receipt": "r-123"}', error=None):
        self.status, self.body, self.error = status, body, error
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return self.status, self.body


def test_canonicalization_matches_b12s_published_example():
    assert app.canonicalize(B12_EXAMPLE_PAYLOAD) == B12_EXAMPLE_CANONICAL.encode("utf-8")


@pytest.mark.skipif(not PUBLISHED_EXAMPLE_KEY, reason=f"{app.SECRET_ENV_VAR} is not set")
def test_signature_matches_b12s_published_digest():
    """Check this implementation against B12's spec rather than against itself."""
    body = app.canonicalize(B12_EXAMPLE_PAYLOAD)
    assert app.sign(body, PUBLISHED_EXAMPLE_KEY) == f"sha256={B12_EXAMPLE_DIGEST}"


def test_signature_covers_the_bytes_actually_sent():
    transport = FakeTransport()
    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=transport) == 0

    (request,) = transport.requests
    sent = request.data
    recomputed = hmac.new(TEST_SECRET.encode("utf-8"), sent, hashlib.sha256).hexdigest()
    assert request.get_header(app.SIGNATURE_HEADER.capitalize()) == f"sha256={recomputed}"

    payload = json.loads(sent)
    assert sent == app.canonicalize(payload)
    assert (payload["name"], payload["email"], payload["resume_link"]) == (NAME, EMAIL, RESUME_LINK)
    assert payload["repository_link"] == "https://github.com/someone/some-repo"
    assert payload["action_run_link"] == "https://github.com/someone/some-repo/actions/runs/20561457327"
    assert request.full_url == app.SUBMISSION_URL
    assert request.get_header("Content-type") == "application/json"
    assert request.get_method() == "POST"


def test_non_ascii_is_literal_utf8_not_escaped():
    body = app.canonicalize({**B12_EXAMPLE_PAYLOAD, "name": "Айдар Камалов"})
    assert "Айдар Камалов".encode("utf-8") in body
    assert b"\\u" not in body


@pytest.mark.parametrize(
    "moment,expected",
    [
        (datetime(2026, 1, 6, 16, 59, 37, 571000, tzinfo=timezone.utc), "2026-01-06T16:59:37.571Z"),
        (datetime(2026, 1, 6, 16, 59, 37, 0, tzinfo=timezone.utc), "2026-01-06T16:59:37.000Z"),
        (datetime(2026, 1, 6, 16, 59, 37, 999999, tzinfo=timezone.utc), "2026-01-06T16:59:37.999Z"),
        # Six hours ahead of UTC, converted rather than emitted with an offset.
        (datetime(2026, 1, 6, 22, 59, 37, 571000, tzinfo=timezone(timedelta(hours=6))), "2026-01-06T16:59:37.571Z"),
    ],
)
def test_timestamp_is_utc_iso8601_with_milliseconds(moment, expected):
    assert app.utc_timestamp(moment) == expected


@pytest.mark.parametrize("missing", ["GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"])
def test_missing_ci_environment_fails_loudly(missing):
    env = {key: value for key, value in CI_ENV.items() if key != missing}
    with pytest.raises(app.ConfigurationError, match=missing):
        app.build_payload(NAME, EMAIL, RESUME_LINK, env)


def test_missing_secret_exits_misconfigured(capsys):
    env = {key: value for key, value in CI_ENV.items() if key != app.SECRET_ENV_VAR}
    assert app.main(APPLICANT_ARGS, env=env, transport=FakeTransport()) == app.EXIT_MISCONFIGURED
    assert app.SECRET_ENV_VAR in capsys.readouterr().err


def test_omitted_applicant_argument_fails_before_posting():
    transport = FakeTransport()
    with pytest.raises(SystemExit) as exit_info:
        app.main(APPLICANT_ARGS[2:], env=CI_ENV, transport=transport)
    assert exit_info.value.code == app.EXIT_MISCONFIGURED
    assert transport.requests == []


def test_blank_applicant_argument_fails_before_posting(capsys):
    argv = ["--name", "   ", *APPLICANT_ARGS[2:]]
    transport = FakeTransport()
    assert app.main(argv, env=CI_ENV, transport=transport) == app.EXIT_MISCONFIGURED
    assert transport.requests == []
    assert "--name" in capsys.readouterr().err


def test_applicant_arguments_are_trimmed():
    argv = ["--name", f"  {NAME} ", "--email", f" {EMAIL}", "--resume-link", f"{RESUME_LINK} "]
    transport = FakeTransport()
    assert app.main(argv, env=CI_ENV, transport=transport) == 0
    payload = json.loads(transport.requests[0].data)
    assert (payload["name"], payload["email"], payload["resume_link"]) == (NAME, EMAIL, RESUME_LINK)


def test_dry_run_posts_nothing_and_hides_the_secret(capsys):
    transport = FakeTransport()
    assert app.main([*APPLICANT_ARGS, "--dry-run"], env=CI_ENV, transport=transport) == 0
    stdout = capsys.readouterr().out
    assert transport.requests == []
    assert "sha256=" in stdout
    assert TEST_SECRET not in stdout


def test_successful_submission_prints_the_receipt(capsys):
    transport = FakeTransport(body=b'{"success": true, "receipt": "abc-789"}')
    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=transport) == 0
    assert "abc-789" in capsys.readouterr().out


def test_non_200_response_fails_the_run(capsys):
    transport = FakeTransport(status=403, body=b'{"error": "bad signature"}')
    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=transport) == app.EXIT_SUBMISSION_FAILED
    stderr = capsys.readouterr().err
    assert "403" in stderr
    assert "bad signature" in stderr


@pytest.mark.parametrize("body", [
    b"not json",
    b"[]",
    b'{"success": false, "receipt": "r-123"}',
    b'{"success": true, "receipt": ""}',
])
def test_invalid_response_fails_cleanly(body, capsys):
    transport = FakeTransport(body=body)
    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=transport) == app.EXIT_SUBMISSION_FAILED
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "Submission receipt:" not in captured.out


@pytest.mark.parametrize("error", [
    urllib.error.URLError("connection refused"),
    TimeoutError("read timed out"),
])
def test_no_response_fails_without_retrying(error, capsys):
    transport = FakeTransport(error=error)
    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=transport) == app.EXIT_SUBMISSION_FAILED
    assert len(transport.requests) == 1
    assert str(error) in capsys.readouterr().err


def test_receipt_is_written_to_the_step_summary_only_on_success(tmp_path):
    summary = tmp_path / "summary.md"
    env = {**CI_ENV, "GITHUB_STEP_SUMMARY": str(summary)}

    failure = FakeTransport(status=500, body=b"boom")
    assert app.main(APPLICANT_ARGS, env=env, transport=failure) == app.EXIT_SUBMISSION_FAILED
    assert not summary.exists()

    success = FakeTransport(body=b'{"success": true, "receipt": "abc-789"}')
    assert app.main(APPLICANT_ARGS, env=env, transport=success) == 0
    assert "abc-789" in summary.read_text(encoding="utf-8")
