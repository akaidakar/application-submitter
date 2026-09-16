# Application submitter

Sends a signed application to B12 through GitHub Actions and prints the receipt.

![Dispatching the workflow as a dry run and reading the signed body in the job log](docs/demo.gif)

## Setup

Only collaborators can dispatch a workflow, so to run it yourself, fork the
repository first. The submission then links to your fork and your run.

1. Open the Actions tab of the fork and enable workflows. GitHub disables them
   on a fresh fork until you do.
2. Under Settings, then Secrets and variables, then Actions, add a secret
   named `B12_SIGNING_SECRET` with the value from the exercise.
3. Under Actions, choose submit application, then Run workflow. The form asks
   for a name, an email, and a public résumé or LinkedIn URL. None are
   prefilled, so a fork never submits the original owner's details by
   accident. Keep "dry run" checked to print the exact body and signature
   without posting; uncheck it to submit.
4. Send B12 the receipt from the job log or the run summary.

The script can also run outside Actions for a dry run:

```sh
B12_SIGNING_SECRET=... GITHUB_SERVER_URL=https://github.com \
GITHUB_REPOSITORY=you/repo GITHUB_RUN_ID=1 \
python3 submit_application.py --name "Your Name" --email you@example.com \
  --resume-link https://example.com/resume.pdf --dry-run
```

It exits 0 after a submission or a dry run, 1 when the submission failed, and
2 when a flag or environment variable is missing or blank.

## Tests

With Python 3.10 or newer:

```sh
python3 -m pip install pytest
python3 -m pytest -q
```

The tests use no network. One test signs B12's example payload with the real
key and compares against their published digest; it skips unless
`B12_SIGNING_SECRET` is exported. CI passes the repository secret to that job.

## Decisions

The script signs the bytes it sends. `canonicalize()` returns bytes, and the
same object goes to both `sign()` and the request. Building a dict, signing one
serialization, and letting the HTTP client produce another is the usual way to
break an HMAC, and `urllib.request.Request` takes bytes directly, so it cannot
happen here. One test recomputes the HMAC from the prepared request's own
`.data` and checks it against the header.

Name, email and résumé link are workflow inputs, so the same script submits for
anyone. `repository_link` and `action_run_link` come from `GITHUB_SERVER_URL`,
`GITHUB_REPOSITORY` and `GITHUB_RUN_ID` because they describe the run itself.
If any are missing the script exits before posting rather than sending a link
it guessed at. The key stays in the environment because it is a secret. Inputs
reach the script through environment variables, so a quote typed into the form
cannot break the command line.

The POST only runs from a `workflow_dispatch` that defaults to a dry run. The
endpoint belongs to someone else, and a submission should not go out on every
commit.

The script does not retry. Without an idempotency key, a lost response and a
lost request look identical from the client, so a retry could file a second
application. On failure it prints the status, the response, and the body it
sent, which is enough to diagnose from the log and re-run by hand.
