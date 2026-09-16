# Application submitter

A Python script, run from a GitHub Action, that POSTs a signed application
payload to B12's submission endpoint and prints the receipt it gets back.

## Running it

Tests run on every push. Submitting is manual:

1. Go to Actions, pick "submit application", click "Run workflow".
2. Leave "dry run" ticked to print the exact body and signature without posting.
3. Untick it to submit. The receipt is printed in the job log and in the run summary.

Locally:

```sh
pip install pytest && pytest
B12_SIGNING_SECRET=... \
GITHUB_SERVER_URL=https://github.com \
GITHUB_REPOSITORY=akaidakar/b12b12b12b12b12 \
GITHUB_RUN_ID=0 \
python submit_application.py --dry-run
```

## Decisions

**The body is serialized once.** `canonicalize()` returns bytes, and those bytes
are both what gets signed and what gets sent. The common way to break an HMAC
signature is to build a dict, sign one serialization of it, and let an HTTP
client produce a different one for the wire. `urllib.request.Request` takes
bytes directly, so there is no code path where that can happen. One test
recomputes the HMAC from the prepared request's own `.data` and checks it
against the header, which is the invariant that matters.

**Their published example is the test fixture.** The exercise includes a
canonical payload and its expected digest, so the first test checks this
implementation against B12's spec rather than against itself.

**`ensure_ascii=False`.** The example payload is entirely ASCII, so it produces
identical bytes whether non-ASCII is escaped to `\uXXXX` or emitted as literal
UTF-8. The published digest cannot tell the two apart. "UTF-8-encoded" reads as
literal UTF-8, so that is the choice here, and a test with a Cyrillic name pins
it.

**The run link is derived, not pasted.** `repository_link` and `action_run_link`
are built from `GITHUB_SERVER_URL`, `GITHUB_REPOSITORY` and `GITHUB_RUN_ID` at
run time, so the payload always points at the run that posted it. If any of
those are missing the script exits before posting rather than sending a guessed
link.

**The signing secret is read from the environment with no fallback.** It is
published in the exercise, but a secret with a default baked into the source is
not a secret. It comes from a repository secret in CI, and the script fails with
an instruction to set it when it is absent.

**Failures are not retried.** The endpoint offers no idempotency key, so a lost
response and a lost request look identical from here. Retrying could file a
second application to save one button click. Instead the script exits non-zero
with the status, the response body, and the request body it sent, so a failure
is diagnosable from the log, and the run is repeated by hand.

**Timestamps are formatted explicitly.** `datetime.isoformat()` produces
microseconds and a `+00:00` offset. The format string here gives milliseconds
and a trailing `Z`, matching the shape of the example.

## Layout

| File | Purpose |
| --- | --- |
| `submit_application.py` | Canonicalize, sign, post, report |
| `test_submit_application.py` | 16 tests, no network |
| `.github/workflows/tests.yml` | Tests on push, reusable by the submit workflow |
| `.github/workflows/submit.yml` | Manual submission, runs the tests first |

Exit codes: `0` submitted, `1` submission failed, `2` misconfigured.
