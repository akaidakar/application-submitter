"""Submit a job application by POSTing a signed, canonicalized JSON payload.

The request body is serialized exactly once. Those same bytes are what gets
signed and what gets sent, so the signature can never drift from the payload.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

SUBMISSION_URL = "https://b12.io/apply/submission"
SIGNATURE_HEADER = "X-Signature-256"
SECRET_ENV_VAR = "B12_SIGNING_SECRET"
REQUEST_TIMEOUT_SECONDS = 30

NAME = "Aidar Kamalov"
EMAIL = "akaudakar@gmail.com"
RESUME_LINK = ""  # Set before submitting; main() refuses to run while empty.

EXIT_SUBMISSION_FAILED = 1
EXIT_MISCONFIGURED = 2

# A transport takes a prepared request and returns (status_code, body_bytes).
# Injecting it keeps the tests off the network.
Transport = Callable[[urllib.request.Request], "tuple[int, bytes]"]


class ConfigurationError(RuntimeError):
    """Something the environment must supply is missing or unusable."""


def canonicalize(payload: Mapping[str, Any]) -> bytes:
    """Serialize a payload to the exact bytes to sign and send.

    Keys sorted alphabetically, compact separators, encoded as UTF-8.

    ensure_ascii is False so non-ASCII characters are emitted as literal UTF-8
    rather than \\uXXXX escapes. B12's published example cannot distinguish the
    two settings because it contains only ASCII; see the README.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign(body: bytes, secret: str) -> str:
    """Return the X-Signature-256 header value for a raw request body."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def utc_timestamp(now: datetime | None = None) -> str:
    """Return an ISO 8601 UTC timestamp with milliseconds and a trailing Z.

    datetime.isoformat() would give microseconds and a +00:00 offset, so the
    format is spelled out to match the shape B12's example uses.
    """
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    milliseconds = moment.microsecond // 1000
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{milliseconds:03d}Z"


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not value:
        raise ConfigurationError(
            f"{name} is not set. This script derives its links from the CI "
            f"environment and will not post a payload it had to guess at."
        )
    return value


def repository_link(env: Mapping[str, str]) -> str:
    server = _required(env, "GITHUB_SERVER_URL")
    repository = _required(env, "GITHUB_REPOSITORY")
    return f"{server}/{repository}"


def action_run_link(env: Mapping[str, str]) -> str:
    """Build a link to the run that is executing right now.

    Deriving this rather than pasting it is what makes the link self-referential:
    the payload always points at the run that posted it.
    """
    run_id = _required(env, "GITHUB_RUN_ID")
    return f"{repository_link(env)}/actions/runs/{run_id}"


def build_payload(env: Mapping[str, str], now: datetime | None = None) -> dict[str, str]:
    if not RESUME_LINK:
        raise ConfigurationError("RESUME_LINK is empty. Set it before submitting.")
    return {
        "timestamp": utc_timestamp(now),
        "name": NAME,
        "email": EMAIL,
        "resume_link": RESUME_LINK,
        "repository_link": repository_link(env),
        "action_run_link": action_run_link(env),
    }


def urllib_transport(request: urllib.request.Request) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        # An HTTP error is still a response: the server received the request.
        # Returning it rather than raising keeps that distinct from URLError,
        # which means the request may never have arrived.
        return error.code, error.read()


def build_request(body: bytes, signature: str) -> urllib.request.Request:
    return urllib.request.Request(
        SUBMISSION_URL,
        data=body,
        headers={"Content-Type": "application/json", SIGNATURE_HEADER: signature},
        method="POST",
    )


def submit(
    payload: Mapping[str, Any],
    secret: str,
    transport: Transport = urllib_transport,
) -> tuple[int, bytes]:
    body = canonicalize(payload)
    return transport(build_request(body, sign(body, secret)))


def read_receipt(body: bytes) -> str:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as error:
        raise ConfigurationError(f"Response was not JSON: {body!r}") from error
    if not parsed.get("success"):
        raise ConfigurationError(f"Response did not report success: {parsed!r}")
    receipt = parsed.get("receipt")
    if not receipt:
        raise ConfigurationError(f"Response carried no receipt: {parsed!r}")
    return str(receipt)


def _append_step_summary(text: str, env: Mapping[str, str]) -> None:
    summary_path = env.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as summary:
        summary.write(text + "\n")


def main(
    argv: list[str] | None = None,
    env: Mapping[str, str] = os.environ,
    transport: Transport = urllib_transport,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the canonical body and signature without posting.",
    )
    args = parser.parse_args(argv)

    try:
        secret = _required(env, SECRET_ENV_VAR)
        payload = build_payload(env)
    except ConfigurationError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_MISCONFIGURED

    body = canonicalize(payload)
    signature = sign(body, secret)

    if args.dry_run:
        print("Dry run. Nothing was posted.")
        print(f"body:      {body.decode('utf-8')}")
        print(f"signature: {signature}")
        return 0

    try:
        status, response_body = transport(build_request(body, signature))
    except urllib.error.URLError as error:
        # No HTTP response, so the request may or may not have arrived. This is
        # deliberately not retried: the endpoint offers no idempotency key, and
        # a duplicate application is worse than a manual re-run.
        print(f"error: could not reach {SUBMISSION_URL}: {error.reason}", file=sys.stderr)
        print(f"body was: {body.decode('utf-8')}", file=sys.stderr)
        return EXIT_SUBMISSION_FAILED

    if status != 200:
        print(f"error: expected HTTP 200, got {status}", file=sys.stderr)
        print(f"response: {response_body.decode('utf-8', 'replace')}", file=sys.stderr)
        print(f"body was:  {body.decode('utf-8')}", file=sys.stderr)
        print(f"signature: {signature}", file=sys.stderr)
        return EXIT_SUBMISSION_FAILED

    try:
        receipt = read_receipt(response_body)
    except ConfigurationError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_SUBMISSION_FAILED

    print(f"Submission receipt: {receipt}")
    _append_step_summary(f"Submission receipt: `{receipt}`", env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
