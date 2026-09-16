# Application submitter

Sends a signed application to B12 through GitHub Actions and prints the receipt.

## Setup

1. Check `NAME` and `EMAIL` in `submit_application.py`.
2. Under Settings → Secrets and variables → Actions, add:
   - Secret `B12_SIGNING_SECRET`: the value from the exercise.
   - Variable `RESUME_LINK`: a public résumé or LinkedIn URL.
3. Open Actions → submit application → Run workflow. Keep "dry run" checked to
   print the exact body and signature without posting; uncheck it to submit.
4. Send B12 the receipt from the job log or the run summary.

## Tests

With Python 3.10 or newer:

```sh
python3 -m pip install pytest
python3 -m pytest -q
```

The tests use no network and need no environment setup.

## Decisions

**The body is serialized once.** `canonicalize()` returns bytes, and those bytes
are both what gets signed and what gets sent. The usual way to break an HMAC
signature is to build a dict, sign one serialization of it, and let the HTTP
client produce a different one for the wire. `urllib.request.Request` takes
bytes directly, so that cannot happen here. One test recomputes the HMAC from
the prepared request's own `.data` and checks it against the header.

**B12's worked example is the first test.** The exercise publishes a payload, a
signing key, and the digest they produce, so signing is checked against their
spec rather than against this implementation's own output. All three values are
inline in the test file, because a published example is documentation and only
works with all of its parts. The submission path is separate: it reads its key
from the environment and has no fallback, so nothing can sign with a default.

**`ensure_ascii=False`.** The example payload is pure ASCII, so it produces the
same bytes whether non-ASCII is escaped to `\uXXXX` or written as literal UTF-8.
The published digest cannot distinguish the two. "UTF-8-encoded" reads as the
literal form, so that is the setting here, and a test with a Cyrillic name pins
it.

**Links are derived, not pasted.** `repository_link` and `action_run_link` come
from `GITHUB_SERVER_URL`, `GITHUB_REPOSITORY` and `GITHUB_RUN_ID` at run time,
so the payload always points at the run that posted it. If any are missing the
script exits before posting rather than sending a link it guessed at.

**Submitting is manual.** Tests run on every push, but the POST only runs from a
`workflow_dispatch` that defaults to a dry run. The endpoint belongs to someone
else and repeat submissions are not something to fire on every commit.

**Failures are not retried.** Without an idempotency key, a lost response and a
lost request look identical from the client, so a retry could file a second
application. The script exits non-zero with the status, the response body, and
the request body it sent, which is enough to diagnose the failure from the log
and re-run by hand.

**Timestamps are explicit.** `isoformat(timespec="milliseconds")` with the
offset replaced by `Z` matches the shape of the example. A bare `isoformat()`
would give microseconds and `+00:00`.

## Layout

| File | Purpose |
| --- | --- |
| `submit_application.py` | Canonicalize, sign, post, report |
| `test_submit_application.py` | Tests, no network |
| `.github/workflows/tests.yml` | Tests on every push, reusable by the submit workflow |
| `.github/workflows/submit.yml` | Manual submission, runs the tests first |

Exit codes: `0` submitted, `1` submission failed, `2` misconfigured.
