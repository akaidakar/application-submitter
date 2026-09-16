"""Submit a signed application to B12.

canonicalize() serializes the body exactly once. The script signs and sends
those same bytes, so the signature cannot drift from the payload.
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
# argparse also exits with 2 on a bad command line, so a missing flag and a
# missing environment variable report the same code. Tests rely on that.
EXIT_MISCONFIGURED = 2

# A transport takes a prepared request and returns (status_code, body_bytes).
# Injecting it keeps the tests off the network.
Transport = Callable[[urllib.request.Request], tuple[int, bytes]]


class ConfigurationError(RuntimeError):
    """Something the caller must supply is missing or unusable."""


def required(value: str | None, message: str) -> str:
    if value is None or not value.strip():
        raise ConfigurationError(message)
    return value.strip()


def required_env(env: Mapping[str, str], name: str) -> str:
    return required(env.get(name), f"{name} is not set. Set it before submitting.")


def canonicalize(payload: Mapping[str, Any]) -> bytes:
    # ensure_ascii=False writes non-ASCII as literal UTF-8. See README.
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def utc_timestamp(now: datetime | None = None) -> str:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_payload(
    name: str,
    email: str,
    resume_link: str,
    env: Mapping[str, str],
    now: datetime | None = None,
) -> dict[str, str]:
    """The applicant comes from the caller; the links come from the running job."""
    server = required_env(env, "GITHUB_SERVER_URL")
    repository = required_env(env, "GITHUB_REPOSITORY")
    run_id = required_env(env, "GITHUB_RUN_ID")
    return {
        "timestamp": utc_timestamp(now),
        "name": name,
        "email": email,
        "resume_link": resume_link,
        "repository_link": f"{server}/{repository}",
        "action_run_link": f"{server}/{repository}/actions/runs/{run_id}",
    }


def urllib_transport(request: urllib.request.Request) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        # An HTTP error is still a response, so the server received the request.
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


def read_receipt(status: int, body: bytes) -> str:
    if status != 200:
        raise ValueError(f"expected HTTP 200, got {status}: {body.decode('utf-8', 'replace')}")
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"response was not JSON: {body!r}") from error
    if not isinstance(parsed, dict) or parsed.get("success") is not True:
        raise ValueError(f"response did not report success: {parsed!r}")
    receipt = parsed.get("receipt")
    if not isinstance(receipt, str) or not receipt.strip():
        raise ValueError(f"response carried no receipt: {parsed!r}")
    return receipt


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
        applicant = [
            required(value, f"{flag} is required and cannot be blank.")
            for flag, value in [
                ("--name", args.name),
                ("--email", args.email),
                ("--resume-link", args.resume_link),
            ]
        ]
        secret = required_env(env, SECRET_ENV_VAR)
        payload = build_payload(*applicant, env)
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
        receipt = read_receipt(*transport(build_request(body, signature)))
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        # On a URLError or timeout there was no HTTP response, so a lost
        # request and a lost reply look identical from here. The endpoint
        # offers no idempotency key, so retrying could file a second
        # application. Re-run the workflow by hand instead.
        print(f"error: {error}", file=sys.stderr)
        print(f"body was:  {body.decode('utf-8')}", file=sys.stderr)
        print(f"signature: {signature}", file=sys.stderr)
        return EXIT_SUBMISSION_FAILED

    print(f"Submission receipt: {receipt}")
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write(f"Submission receipt: `{receipt}`\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
