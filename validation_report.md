# github-review-helper PoC Validation Report

Date: 2026-06-20
Target used for live checks: `salemove/github-review-helper` on `http://localhost:4567/`

Important: rotate the GitHub token that was pasted into chat before using it
again. The reproduction below does not require a GitHub token and does not call
merge, squash, status creation, branch deletion, or comment-writing paths.

## Summary

| ID | Result | Reportable? | Notes |
| --- | --- | --- | --- |
| VULN-001 | Valid | Yes | Authorization checks the PR author, not the comment author. |
| VULN-013 | Valid | Yes | Request body is fully read before auth and has no size limit. |
| VULN-006 | Valid behavior, lower impact | Maybe | SHA-256 webhook signatures are rejected; SHA-1 only. |
| VULN-010 | Weak / mostly informational | No or low | Error messages are mostly generic; impact is overstated. |
| VULN-002 | Not proven as written | No | The PoC sends `head.ref`, but the parser ignores it; real refs are constrained. |
| VULN-003 | Valid reliability bug | Maybe | Process-global `GIT_SEQUENCE_EDITOR` can race across concurrent repo operations. |
| VULN-004 | Not valid under real GitHub events | No | Injection requires synthetic repo/SHA fields that valid GitHub events do not allow. |

## Live Reproduction Results

Run:

```powershell
C:\Users\bolig\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe .\poc\verified_repro.py
```

Observed locally:

```text
sha1_valid_ping: status=200 body='Not an event I understand. Ignoring.'
sha256_only_ping: status=401 body='Please provide a X-Hub-Signature\n'
missing_signature: status=401 body='Please provide a X-Hub-Signature\n'
bad_signature: status=403 body='Bad X-Hub-Signature\n'
malformed_json_after_valid_hmac: status=500 body="Failed to parse the request's body\n"
preauth_large_bad_sig_32mib: status=403 body='Bad X-Hub-Signature\n'
```

The 32 MiB invalid-signature request receiving `403 Bad X-Hub-Signature`
confirms the body was read and HMAC-processed before authentication rejected it.

## VULN-001: Authorization Bypass

Status: valid.

Root cause:

- `parsers.go` parses only `comment.body`; it does not parse `comment.user.login`.
- `IssueComment.User.Login` is populated from `message.Issue.User.Login`, which is the PR/issue author.
- `main.go` then calls `checkUserAuthorization(issueComment, ...)`.
- `checkUserAuthorization` calls `isCollaborator(issueComment.Repository, issueComment.User, ...)`.

Impact:

An attacker who can comment on a PR can issue `!check`, `!squash`, or `!merge`
on PRs authored by a collaborator, because the collaborator check is performed
against the PR author instead of the commenter.

Safe proof:

Use a GitHub `issue_comment` payload where:

- `issue.user.login` is a collaborator.
- `comment.user.login` is a non-collaborator.
- `comment.body` is `!check`, `!squash`, or `!merge`.

Expected vulnerable behavior:

The bot checks collaborator status for `issue.user.login`, never
`comment.user.login`.

## VULN-013: Unbounded Request Body / Pre-Auth DoS

Status: valid.

Root cause:

- `main.go` calls `ioutil.ReadAll(r.Body)`.
- Authentication is checked only after the whole body has been read.
- There is no `http.MaxBytesReader`, `io.LimitReader`, reverse-proxy limit, or
  app-level content-length check in the handler.

Live proof:

An unauthenticated 32 MiB request with an invalid HMAC returned
`403 Bad X-Hub-Signature`, showing the body was accepted into the HMAC path
before rejection.

Impact:

An unauthenticated client can send very large request bodies and force memory
allocation and HMAC work before any signature rejection happens.

## VULN-006: SHA-1 Only Webhook HMAC

Status: confirmed behavior, impact lower than the original PoC says.

Root cause:

- `authentication.go` reads only `X-Hub-Signature`.
- It parses only the `sha1=` format.
- It never checks `X-Hub-Signature-256`.

Live proof:

- Valid SHA-1 signature: `200`.
- Valid SHA-256-only signature: `401 Please provide a X-Hub-Signature`.

Impact:

This is a compatibility and security-hardening issue. It does not by itself let
an attacker forge webhook requests, but the app should support GitHub's
recommended `X-Hub-Signature-256` header.

## VULN-010: Information Leakage in Error Responses

Status: weak / mostly informational.

Live proof:

The app exposes distinct responses for missing signature, bad signature, and
malformed JSON:

- `Please provide a X-Hub-Signature`
- `Bad X-Hub-Signature`
- `Failed to parse the request's body`

Assessment:

These messages reveal control-flow state, but not secrets. The original PoC
overstates this as a standalone vulnerability. It may be worth cleaning up, but
it is probably not a strong bug-bounty report on its own.

## VULN-002: Git Argument Injection via Branch Names

Status: not proven as written.

Why the PoC is wrong:

- The `pull_request` parser does not read `pull_request.head.ref`.
- `parsePullRequestEvent` keeps only `head.sha` and `head.repo`.
- The squash path later calls `AutosquashAndPush("origin/"+baseRef, headSHA, headRef)`, where `headRef` comes from the GitHub PR API, not the webhook field used by the PoC.
- The rebase argument uses the head SHA, not the branch name.
- The push destination is passed as `"@:"+destinationRef`, which does not begin with `-`.

Additional constraint:

`git check-ref-format --branch` rejects branch shorthands such as `--exec=id`
and `-oProxyCommand=x`.

Residual note:

Adding `--` before user-derived refs is still good defensive hardening, but the
submitted PoC does not demonstrate an exploitable issue.

## VULN-003: `GIT_SEQUENCE_EDITOR` Race

Status: valid reliability bug, security impact depends on who can trigger
concurrent squash operations.

Root cause:

- `git/git.go` uses `os.Setenv("GIT_SEQUENCE_EDITOR", "true")`.
- That environment variable is process-global.
- The lock is per `repo`, so operations on different repos can run
  concurrently.

Impact:

Two concurrent autosquash operations for different repos can interfere. One
operation can unset `GIT_SEQUENCE_EDITOR` while another operation is between
setting the variable and starting `git rebase --interactive`, causing the second
operation to fail or hang waiting for an editor.

Better fix:

Set the environment on the `exec.Cmd` instance for that single git process
instead of changing the process-global environment.

## VULN-004: GitHub Search Query Injection

Status: not valid under real GitHub webhook constraints.

Why:

- The query is built from status event `sha`, repository owner, and repository
  name.
- Real GitHub SHAs are hex strings.
- Real GitHub repository owners/names cannot contain the spaces and search
  operators used by the PoC, such as `is:merged status:failure`.
- A synthetic HMAC-signed payload can inject these fields only if the webhook
  secret is already known. At that point the attacker already has webhook
  forgery capability.

Assessment:

It is reasonable to validate or quote query components defensively, but the PoC
does not show a practical external vulnerability.

## Recommended Report Order

1. Report VULN-001 as the strongest issue.
2. Report VULN-013 as a real unauthenticated DoS risk.
3. Include VULN-006 as hardening/compatibility, preferably as a separate lower
   severity issue.
4. Mention VULN-003 only if the program accepts reliability/DoS reports.
5. Do not submit VULN-002, VULN-004, or VULN-010 as standalone high-severity
   findings without stronger evidence.
