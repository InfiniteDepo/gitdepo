---
name: security-review
description: Review a gitdepo design or pull request diff for exploitable security problems (permissions, data exposure, injection, redirects, outbound requests, secrets) using the repository's own patterns. Use when asked to "security review", "check this PR for security issues", or before merging a change to auth, permissions, tokens, keys, webhooks, uploads or outbound requests.
---

# Security review

You review; you don't edit, commit or push. This catches common mistakes before a maintainer looks; it does not replace the maintainers' review, and a clean result is not a security sign-off. Read `CLAUDE.md` first: its "Learnings" name the one function each decision must go through (permissions, trash, projects, rate limits, audit, client IP).

## Scope

- A design: the plan as written, plus the existing code it reuses.
- A pull request: the real diff, `git diff origin/develop...<sha>`, and the code around it.
- Find **every** entry path that reaches the changed code, not only the ones named: web routes, API (including the project `/-` and `/repositories/{id}` mounts), git over HTTP and SSH, hooks, LFS and package tokens, Actions job tokens, cron, CLI and the internal API. Grep for callers.

## Checklist

- **Who may do this?** Every new route, API endpoint, query or list checks permission before it reads or writes, through the shared helpers (`GetUserRepoPermission`, `AccessibleRepositoryCondition`, the org owner checks), never a hand-rolled check. Lists filter in SQL the same way the single-item check does.
- **Hidden = missing.** Something the viewer can't see answers exactly like something that doesn't exist: same status, same text, same timing class. No error text, count or redirect leaks existence.
- **Tokens and keys.** Scoped and restricted tokens, deploy keys and job tokens get only what they grant; expired, revoked or suspended credentials are refused on every path; a credential never outlives its owner's access.
- **Input validation.** List every new input (form fields, query parameters, API JSON, headers, push options, uploaded files and archive entries) and check each on the server, not only in the form or the browser: type, length, range and count limits, an allowlist where the values are a fixed set, normalisation before comparison (case, Unicode, trailing spaces, `..`), and a clean 4xx (never a 500 or a partial write) for anything refused.
- **Input reaching HTML, SQL, git, shell or logs.** Templates escape (watch `Flash` messages and `safe`/HTML helpers); SQL uses bound values (never a value as a column name); git arguments can't start with `-` and paths can't escape the repository; no shell string building; log and audit text is stripped of control characters.
- **Redirects and outbound requests.** Redirect targets are relative or allow-listed. Outbound URLs (webhooks, migrations, mirrors, log shipping) go through the host allow-list at dial time, so DNS rebinding and redirects to internal addresses are refused.
- **Secrets.** Never logged, returned by an API, shown after creation or written to the audit log; compared in constant time; stored hashed or encrypted.
- **Races.** Check-then-write sequences that matter hold a lock or use a conditional update; no mutex held across a database query.
- **Writes that must be audited** go through the audit helpers and fail closed.
- **Fail closed.** A setting that can't be read, an unknown value or a missing row means "refuse", not "allow".

## Report

Report real, exploitable problems only: who the attacker is, the preconditions, the steps, the impact and the smallest fix, with file:line. If you find nothing exploitable, say so plainly. Notes that prevent a likely bug go in a separate short list. No hardening wish lists.

**Never post a vulnerability in a public issue, pull request, comment, commit message or code comment.** Give findings only to the person who asked; they report them privately as `SECURITY.md` describes. A fix can land in a pull request with a neutral title and description.
