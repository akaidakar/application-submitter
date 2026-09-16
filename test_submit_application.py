"""Network-free tests for payload signing and submission handling."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
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

# The exercise publishes a worked example: the payload above, a signing key,
# and the digest they produce. The key is treated as a secret and never written
# down here, so the digest test reads it from the same environment variable the
# submission uses and skips when it is absent. CI provides it from the
# repository secret; locally, export B12_SIGNING_SECRET to run that one test.
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
APPLICANT = app.Applicant("Some Applicant", "applicant@example.com", "https://resume.example.com/applicant.pdf")


class RecordingTransport:
    """Stands in for the network and keeps the request it was handed."""

    def __init__(self, status: int = 200, body: bytes = b'{"success": true, "receipt": "r-123"}'):
        self.status = status
        self.body = body
        self.request = None

    def __call__(self, request):
        self.request = request
        return self.status, self.body


def test_canonicalization_matches_b12s_published_example():
    body = app.canonicalize(B12_EXAMPLE_PAYLOAD)
    assert body == B12_EXAMPLE_CANONICAL.encode("utf-8")


@pytest.mark.skipif(
    not PUBLISHED_EXAMPLE_KEY, reason=f"{app.SECRET_ENV_VAR} is not set"
)
def test_signature_matches_b12s_published_digest():
    """Check this implementation against B12's spec rather than against itself."""
    body = app.canonicalize(B12_EXAMPLE_PAYLOAD)
    assert app.sign(body, PUBLISHED_EXAMPLE_KEY) == f"sha256={B12_EXAMPLE_DIGEST}"


def test_signature_covers_the_bytes_actually_sent():
    transport = RecordingTransport()
    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=transport) == 0

    sent = transport.request.data
    header = transport.request.get_header(app.SIGNATURE_HEADER.capitalize())
    recomputed = hmac.new(TEST_SECRET.encode("utf-8"), sent, hashlib.sha256).hexdigest()

    assert header == f"sha256={recomputed}"
    payload = json.loads(sent)
    assert payload["resume_link"] == APPLICANT.resume_link
    assert payload["name"] == APPLICANT.name
    assert payload["email"] == APPLICANT.email
    assert payload["action_run_link"].endswith("/actions/runs/20561457327")
    assert sent == app.canonicalize(payload)
    assert transport.request.full_url == app.SUBMISSION_URL
    assert transport.request.get_header("Content-type") == "application/json"
    assert transport.request.get_method() == "POST"


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
    payload = app.build_payload(APPLICANT, CI_ENV)
    assert payload["repository_link"] == "https://github.com/someone/some-repo"
    assert payload["action_run_link"] == (
        "https://github.com/someone/some-repo/actions/runs/20561457327"
    )


@pytest.mark.parametrize("missing", ["GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"])
def test_missing_ci_environment_fails_loudly(missing):
    env = {key: value for key, value in CI_ENV.items() if key != missing}
    with pytest.raises(app.ConfigurationError, match=missing):
        app.build_payload(APPLICANT, env)


def test_missing_secret_exits_misconfigured(capsys):
    env = {key: value for key, value in CI_ENV.items() if key != app.SECRET_ENV_VAR}
    assert app.main(APPLICANT_ARGS, env=env, transport=RecordingTransport()) == app.EXIT_MISCONFIGURED
    assert app.SECRET_ENV_VAR in capsys.readouterr().err


def test_non_200_response_fails_the_run(capsys):
    transport = RecordingTransport(status=403, body=b'{"error": "bad signature"}')
    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=transport) == app.EXIT_SUBMISSION_FAILED
    stderr = capsys.readouterr().err
    assert "403" in stderr
    assert "bad signature" in stderr


def test_unreachable_endpoint_fails_without_retrying(capsys):
    attempts = []

    def refusing_transport(request):
        attempts.append(request)
        raise urllib.error.URLError("connection refused")

    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=refusing_transport) == app.EXIT_SUBMISSION_FAILED
    assert len(attempts) == 1
    assert "connection refused" in capsys.readouterr().err


def test_successful_submission_prints_the_receipt(capsys):
    transport = RecordingTransport(body=b'{"success": true, "receipt": "abc-789"}')
    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=transport) == 0
    assert "abc-789" in capsys.readouterr().out


def test_dry_run_posts_nothing_and_hides_the_secret(capsys):
    transport = RecordingTransport()
    assert app.main([*APPLICANT_ARGS, "--dry-run"], env=CI_ENV, transport=transport) == 0
    stdout = capsys.readouterr().out
    assert transport.request is None
    assert "sha256=" in stdout
    assert TEST_SECRET not in stdout


@pytest.mark.parametrize("flag", ["--name", "--email", "--resume-link"])
def test_omitted_applicant_argument_fails_before_posting(flag):
    argv = list(APPLICANT_ARGS)
    position = argv.index(flag)
    del argv[position : position + 2]
    transport = RecordingTransport()
    with pytest.raises(SystemExit) as exit_info:
        app.main(argv, env=CI_ENV, transport=transport)
    assert exit_info.value.code == app.EXIT_MISCONFIGURED
    assert transport.request is None


@pytest.mark.parametrize("flag", ["--name", "--email", "--resume-link"])
@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_applicant_argument_fails_before_posting(flag, blank, capsys):
    argv = list(APPLICANT_ARGS)
    argv[argv.index(flag) + 1] = blank
    transport = RecordingTransport()
    assert app.main(argv, env=CI_ENV, transport=transport) == app.EXIT_MISCONFIGURED
    assert transport.request is None
    assert flag in capsys.readouterr().err


def test_applicant_arguments_are_trimmed():
    applicant = app.Applicant("  Some Applicant ", " a@example.com", "https://r.example.com ")
    assert (applicant.name, applicant.email, applicant.resume_link) == (
        "Some Applicant", "a@example.com", "https://r.example.com"
    )


@pytest.mark.parametrize("body", [
    b"not json", b"\xff", b"[]", b"null",
    b'{"success": false, "receipt": "r-123"}',
    b'{"success": "false", "receipt": "r-123"}',
    b'{"success": 1, "receipt": "r-123"}',
    b'{"success": true}',
    b'{"success": true, "receipt": 123}',
    b'{"success": true, "receipt": ""}',
    b'{"success": true, "receipt": "   "}',
])
def test_invalid_response_fails_cleanly(body, capsys):
    transport = RecordingTransport(body=body)
    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=transport) == app.EXIT_SUBMISSION_FAILED
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "Submission receipt:" not in captured.out


def test_timeout_fails_without_retrying(capsys):
    attempts = []

    def timed_out(request):
        attempts.append(request)
        raise TimeoutError("read timed out")

    assert app.main(APPLICANT_ARGS, env=CI_ENV, transport=timed_out) == app.EXIT_SUBMISSION_FAILED
    assert len(attempts) == 1
    assert "read timed out" in capsys.readouterr().err


def test_receipt_is_written_to_the_step_summary(tmp_path):
    summary = tmp_path / "summary.md"
    env = {**CI_ENV, "GITHUB_STEP_SUMMARY": str(summary)}
    transport = RecordingTransport(body=b'{"success": true, "receipt": "abc-789"}')
    assert app.main(APPLICANT_ARGS, env=env, transport=transport) == 0
    assert "abc-789" in summary.read_text(encoding="utf-8")


def test_failed_submission_writes_no_step_summary(tmp_path):
    summary = tmp_path / "summary.md"
    env = {**CI_ENV, "GITHUB_STEP_SUMMARY": str(summary)}
    transport = RecordingTransport(status=500, body=b"boom")
    assert app.main(APPLICANT_ARGS, env=env, transport=transport) == app.EXIT_SUBMISSION_FAILED
    assert not summary.exists()
