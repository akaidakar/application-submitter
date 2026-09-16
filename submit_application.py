"""Submit a signed application to B12.

The body is serialized exactly once. Those same bytes are both signed and sent,
so the signature cannot drift from the payload.
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

EXIT_SUBMISSION_FAILED = 1
EXIT_MISCONFIGURED = 2

# A transport takes a prepared request and returns (status_code, body_bytes).
# Injecting it keeps the tests off the network.
Transport = Callable[[urllib.request.Request], "tuple[int, bytes]"]


class ConfigurationError(RuntimeError):
    """Something the caller must supply is missing or unusable."""


class Applicant:
    """The three fields that describe who is applying.

    They arrive as command-line arguments so the workflow can show them as
    dispatch inputs and anyone can run the same script with their own details.
    """

    def __init__(self, name: str, email: str, resume_link: str):
        self.name = _nonblank("--name", name)
        self.email = _nonblank("--email", email)
        self.resume_link = _nonblank("--resume-link", resume_link)


def _nonblank(label: str, value: str | None) -> str:
    if value is None or not value.strip():
        raise ConfigurationError(f"{label} is required and cannot be blank.")
    return value.strip()


def canonicalize(payload: Mapping[str, Any]) -> bytes:
    r"""Serialize to the exact bytes that get signed and sent.

    ensure_ascii=False emits non-ASCII as literal UTF-8 rather than \uXXXX
    escapes. B12's example payload is pure ASCII, so their published digest
    matches under either setting; "UTF-8-encoded" reads as the literal form.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def utc_timestamp(now: datetime | None = None) -> str:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not value or not value.strip():
        raise ConfigurationError(f"{name} is not set. Set it before submitting.")
    return value.strip()


def repository_link(env: Mapping[str, str]) -> str:
    server = _required(env, "GITHUB_SERVER_URL")
    repository = _required(env, "GITHUB_REPOSITORY")
    return f"{server}/{repository}"


def action_run_link(env: Mapping[str, str]) -> str:
    run_id = _required(env, "GITHUB_RUN_ID")
    return f"{repository_link(env)}/actions/runs/{run_id}"


def build_payload(
    applicant: Applicant, env: Mapping[str, str], now: datetime | None = None
) -> dict[str, str]:
    return {
        "timestamp": utc_timestamp(now),
        "name": applicant.name,
        "email": applicant.email,
        "resume_link": applicant.resume_link,
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
        # where the request may never have arrived at all.
        return error.code, error.read()


def build_request(body: bytes, signature: str) -> urllib.request.Request:
    return urllib.request.Request(
        SUBMISSION_URL,
        data=body,
        headers={"Content-Type": "application/json", SIGNATURE_HEADER: signature},
        method="POST",
    )


def read_receipt(body: bytes) -> str:
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"Response was not JSON: {body!r}") from error
    if not isinstance(parsed, dict) or parsed.get("success") is not True:
        raise ValueError(f"Response did not report success: {parsed!r}")
    receipt = parsed.get("receipt")
    if not isinstance(receipt, str) or not receipt.strip():
        raise ValueError(f"Response carried no receipt: {parsed!r}")
    return receipt


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
    parser.add_argument("--name", required=True, help="Applicant's full name.")
    parser.add_argument("--email", required=True, help="Applicant's email address.")
    parser.add_argument(
        "--resume-link", required=True, help="Public URL of a résumé or LinkedIn profile."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the canonical body and signature without posting.",
    )
    args = parser.parse_args(argv)

    try:
        applicant = Applicant(args.name, args.email, args.resume_link)
        secret = _required(env, SECRET_ENV_VAR)
        payload = build_payload(applicant, env)
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
    except (urllib.error.URLError, TimeoutError) as error:
        # No HTTP response, so a lost request and a lost reply look identical
        # from here. The endpoint offers no idempotency key, so retrying could
        # file a second application. Re-run the workflow by hand instead.
        print(f"error: could not reach {SUBMISSION_URL}: {error}", file=sys.stderr)
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
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_SUBMISSION_FAILED

    print(f"Submission receipt: {receipt}")
    _append_step_summary(f"Submission receipt: `{receipt}`", env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
