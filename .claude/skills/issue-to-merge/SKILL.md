---
name: issue-to-merge
description: Use when someone names a gitdepo issue to take all the way to merge-ready pull requests, for example "do issue #N", "issue to merge #N", "get #N ready for merge" or "delegate #N".
---

# Issue to merge

The person gives an issue number. You lead: you split the work, delegate it, check what comes back and drive every pull request to merge-ready. The `coder` skill is the procedure for one pull request; this skill runs it for a whole issue with subagents. Read `CLAUDE.md` (conventions and Learnings) and `CONTRIBUTING.md` first.

Spend effort where it pays: the strongest model for planning and reviews, a cheaper one for mechanical work, targeted tests while iterating, and the full checks once on the final head. Several small issues can share one thread, with one pull request each, so setup, the cheat sheet below and the develop check are shared.

The questions the person asks most often are "is everything in #N done?", "did you really test it?" and "is the PR ready to merge?". Work so that you can answer each one with evidence before they ask.

## 1. Read and split

- Read the issue and every comment (`mcp__github__issue_read`); maintainer comments are requirements. Read linked issues and pull requests that it builds on.
- Check `develop` for each requirement before planning it: issue text goes stale, and parts may already be built. Say which parts are already done.
- Write the requirements as a numbered list taken from the issue. Every later step refers to it, and the final report marks each one done, moved to a follow-up issue, or dropped with the person's OK.
- Split the work into items, each one reviewable pull request (or one commit inside a pull request when the person asked for a single PR). For each item write: goal, the requirements it covers, files and functions, what stays out of scope, its path table (below), and which items it depends on. Where two items share a file or an interface, write what one produces and the other consumes, and settle any conflict before starting either.
- Ask the person only about choices that change the goal, an API, a schema, permissions or a default. Recommend an option and keep working on it meanwhile. Save their decisions to project memory so later threads don't ask again.
- When the feature copies a competitor (GitHub, GitLab, Bitbucket, Azure DevOps), write down how theirs behaves and where gitdepo will differ. The person will ask "does it work exactly like X?".
- Split so every pull request can go green alone: code that neither production code nor tests reach fails the deadcode lint (`.deadcode-out`), so a backend item ships with its tests or a caller (API, CLI, UI).
- Look for open pull requests and threads that touch the same area (`mcp__github__list_pull_requests`, `mcp__hearthbot__list_threads`) and write down how the features meet (for example a merge queue and a stacked merge). Decide the interaction in the plan rather than finding it as a review finding or a known gap.
- **Threat model before coding** for anything in the full-review list of step 6: one Opus pass on the plan names the attackers, the inputs, the permission checks and the refusals, and the brief carries them. When the work uses a third-party security library (SAML, OIDC, JWT, crypto), read its documented caveats and modes first and refuse weak algorithms and IdP-initiated or unsolicited responses by default. Keep the threat model in the brief: only design-level notes go on the issue or pull request, and a weakness found in existing code goes to gitdepoOps (step 6).
- **Path table.** For each item, list every path the new code can take, and the test that covers each one:
  - the success path through each entry point (web, API, git HTTP/SSH, CLI, cron or queue);
  - every refusal and error the code returns (no permission, hidden or missing, invalid input, conflict, a limit or policy reached, maintenance mode, archived);
  - each kind of actor (owner, collaborator, other user, anonymous, admin, token with less scope);
  - a repository inside a project.

  Each path gets an integration test that runs the real action and checks its result, not only the status code: the state in the database, the git refs and the audit row. A UI flow gets an e2e test that completes the action end to end (merge, save, delete) and one that hits a refusal; a test that only opens and cancels a dialog covers nothing. A path that can't be reached from a test gets a test hook, or is named in the PR as untested. The table goes in the brief and in the PR body, and the quality reviewer checks the tests against it.
- Keep a ledger at `/mnt/project-files/issues/<N>/ledger.md`: the requirements with their status, the items with branch, PR and last commit, and every decision as `Ruling: <what> — <why> — <cost if wrong>`. Update it as each step ends. After a context compaction, trust the ledger and `git log` over your memory; re-running finished items is the most expensive mistake.
- Post the plan on the issue, keep the list of items as your progress checklist, and say which item you start with.

## 2. Design UI before building it

If an item adds or changes screens, share mockups first (a design doc or canvas with the screens, the empty and error states, and open questions with your recommendation) and wait for the person's UX review before building those screens. Backend items can go ahead meanwhile. If there is still no answer at a wake an hour or more after posting, send one reminder with the link and the specific open questions, and keep building only what doesn't depend on the screens; don't sit idle. Put each control where users of GitHub and GitLab look for it, not only in settings.

## 3. Delegate

- Give each item to a subagent (Agent tool) with a self-contained brief: the issue number, the item's goal, requirements and tests, the files to start from, the relevant `CLAUDE.md` Learnings, and the rules below. Run independent items in parallel, each in its own worktree with a short path (`/home/user/wt-<x>`, long paths break the integration and e2e sockets). Run dependent items in order.
- Pick the model by the work: coding, test fixing and CI log triage go to `model: "sonnet"`; planning, design questions and the reviews in step 6 stay on `model: "opus"`.
- The rules every brief carries: branch off the latest `origin/develop`; `ponytail` at full level; tests first and never remove or skip one; `git commit -s`, stage files by name, no `package-lock.json`; run the local checks of `CLAUDE.md` "Testing" for the change; while iterating, run only the tests of the changed packages and their neighbours (`go test` on those packages, `make 'test-sqlite#TestName'` or the binary with `-test.run`, the e2e specs whose `@watch` covers the files) and leave the full suite to CI; report what was run, what wasn't, and every failure.
- Batch fixes (you and every brief): push once per review round or CI failure, after all its fixes pass the targeted checks. Each push starts a full CI run (cancelling the last one), and parallel pull requests compete for the same runners.
- Hand briefs and reports over as files, not pasted text: the brief goes in a file the subagent reads first (requirements and exact values only there), the subagent writes its full report next to it and returns only a status (`DONE`, `DONE_WITH_CONCERNS`, `NEEDS_CONTEXT`, `BLOCKED`), its commits and a one-line test summary. Everything pasted into or returned from a subagent stays in your context for the rest of the thread. Never paste the history of earlier items into a later brief.
- Subagents don't start subagents: a coder never spawns its own reviewer or helpers. The reviews come from you in step 6, and a reviewer a coder starts is a duplicate at full cost.
- For a fix, resume the coder that wrote the code (SendMessage with the findings) instead of starting a fresh one; its context is intact. If three fix rounds haven't closed a finding, hand it to a fresh agent on a stronger model with the report file.
- Read each result yourself: the diff, the tests and the check output. A subagent's "done" is a claim; re-run anything that looks thin.

## 4. Test it the way it will be used

Automated tests passing is not "tested". Before a pull request is ready, also:

- **Prove a fix with red-green.** For a bug fix, revert the fix, see the new test fail, restore it and see it pass. Every "tested" or "passes" in a message names the command and what it printed in this round, never an earlier run or a subagent's word.
- **Run it for real.** Build the branch (a production build for UI: `RUN_MODE = prod`, embedded assets), start it on a fresh database and drive the feature as a user would, through the web and the API. Say what you did and what you saw.
- **Projects.** Repeat the main flow on a repository inside a project (`org/project/repo`): names, links, confirmations and lookups that assume `owner/repo` break there.
- **Phones.** For UI, use the pages at 390 px with touch, not only screenshots: menus and prompts that close on focus loss, hidden buttons and on-screen keyboards have broken flows that passed desktop e2e.
- **Concurrency.** When the change runs on a push, merge, cron or queue path, test the races (a branch that moves mid-operation, two runs at once). If the suite can't reach a case, add a test hook rather than calling it untestable. For hot paths, run a stress test with many users in parallel and report lost or failed operations.
- **Interoperability.** When the feature talks to an outside system (an identity provider, a registry, a CI runner, an import source), test it against a real open-source implementation in a container (for example Keycloak for SAML/OIDC), not only against mocks. If that isn't possible, say so in the ready message.
- **Deployment.** If the change adds files outside the binary, a setting or a service, check that the release image and the deployment pipelines ship it, and say what an operator has to do.

## 5. Open the pull request

- Branch off `develop` (the session's assigned branch if it has one), target `develop`, and fill in `.github/pull_request_template.md`: the requirements this PR covers, the tests added and run (automated and by hand), what was not tested, and threat notes for anything security-relevant.
- Use `Fixes #N` only in the pull request that finishes the issue, `Part of #N` in the others. GitHub closes the issue only on `Fixes`/`Closes`.
- Start the body with the attribution block the session requires, then assign the person and request their review (`issue_write` with `assignees`, `update_pull_request` with `reviewers`; GitHub refuses the review request when the person is the author, so skip it then).
- Open it as a draft until the reviews below are done. Subscribe to its activity and tell the person it is up, with the link.

## 6. Review with fresh agents

Review once, on the final diff (after the step 4 checks, not after every push). Size the review to the change:

- **Small changes** (docs, skills, comments, a one-file fix that touches none of the areas below): one fresh Opus agent does a combined quality and security review.
- **Everything that touches sign-in, permissions, roles, tokens, keys or secrets, git paths (hooks, serv, git HTTP, LFS), input that reaches HTML/SQL/git/a shell, uploads, redirects, webhooks or outbound requests, or any UI**: all four reviews below. When unsure, use all four.

Start the reviewers as fresh agents pinned to the strongest model (Agent `model: "opus"`), all in one message so they run in parallel. Give each only the pull request number, the diff, the requirements list from step 1 and the threat notes from the PR body, not the thread history or your conclusions, so their read isn't anchored on yours:

1. **Quality**: correctness, sustainable and robust design, missing tests, reuse of existing helpers, `CLAUDE.md` conventions and Learnings, smallest diff, and that every requirement the PR claims is met.
2. **Security**: the `security-review` skill on the diff (permissions, hidden = missing, data exposure, server-side validation of every new input, injection, redirects, outbound requests, secrets, audit).
3. **UX**, when there is UI: the `screenshots` skill (desktop and mobile, light and dark) and "is this the right experience?": can users find it, does the preview match what the action does, does a wide-scope destructive action ask for a stronger confirm, do the words read well (plurals, "1 branch"), is it consistent with GitHub/GitLab. Attach the screenshots to the pull request.
4. **Red team**: try to break it as an attacker on a running instance from the branch (anonymous, other users, tokens with less scope, hidden repos, no shell or git CLI reachable), and fuzz every new input (very long values, wrong types, negative or huge numbers, control characters and Unicode look-alikes, path traversal, duplicates, missing fields); anything that answers 500, stores bad data or gets past a check is a finding. Report what got through with the exact steps.

Fix every finding, or answer it with the reason it isn't one, then re-run each agent whose findings changed code, plus the security agent whenever a fix touches the full-review areas above, on the fix diff and the code it calls, with its earlier findings list, instead of the whole diff again. Re-reviews stay on Opus; Sonnet only retakes screenshots or checks that a non-security fix was applied. Every finding still gets fixed or answered, but if a reviewer's second re-run still finds new issues, fix the root cause (a missing check at the shared chokepoint, a wrong design) or ask the person before another round of point patches. Follow up the lower-confidence notes too: past reviews found real bugs there. Post the findings (a vulnerability by its gitdepoOps number only) as one review with `event: COMMENT`: reviews post under the person's account, and GitHub refuses approve or request changes on one's own pull request.

A real vulnerability is never written in this repository. File it as an issue in `InfiniteDepo/gitdepoOps` (private) with the details, and keep the gitdepo commit, pull request and comments neutral (they may name the gitdepoOps issue by number only).

## 7. Keep it green

- CI's **CI success** check must be green on the head. On a failure, read the job log, reproduce locally, fix the cause and push; "flaky" is not a cause. Failures known to be environmental are listed in `CLAUDE.md`; anything else is checked on `origin/develop` before calling it unrelated.
- At each event, check whether `develop` moved and whether it still merges cleanly (`git merge-tree --write-tree origin/develop HEAD`), without waiting to be told. Merge it in right away only on a conflict, or when the new commits touch the same files or features as yours; otherwise leave it for the pre-merge check in step 8, so CI runs once instead of after every change on develop. Always merge with a merge commit (never rebase or force-push a pushed branch), then re-test where the new commits meet yours (shared pages, forms, settings).
- `develop` moving sends no event, so do the check above whenever the thread wakes. After merging develop in, tell the coordinator about the merge itself only when it touched files another open pull request changes; the CI wait it starts is reported like any other.
- **Never wait on CI silently.** A CI event can be missed, and nobody notices a quiet thread, so every wait has a backstop:
  - When you push and end the turn to wait for CI, put "✱ Waiting for CI on <short sha>, started <time>" on the checklist, schedule one check-in with `send_later` about 20 minutes out (name it after the PR and sha), and tell the coordinator in one line (`message_coordinator`): the PR, the head sha and when you expect the result, so it can set its own backup check. Mark the step ✓ when the run finishes, or replace it on the next push.
  - At every check-in or PR event, read the run's state yourself (`mcp__github__pull_request_read` with `get_check_runs`). If it finished, act on it in that turn: fix a failure, or go to step 8. If it is still running and the check-in is for the current head, schedule the next check-in (again about 20 minutes); do this only from a check-in, never from another event, so each wait has exactly one pending check-in. A check-in for a sha that is no longer the pull request's head does nothing (a develop watch follows its merge sha until reported). Note the ID `send_later` returns in the ledger and cancel the pending check-in with `delete_trigger` when you push.
  - About an hour after the push (or the last CI duration plus 20 minutes, if longer), find what is holding it (jobs still queued, one slow shard, a cancelled or never-started run) and say so in the thread and to the coordinator: the job, its state and the run link, never log excerpts. Keep the 20-minute check-ins and post again only when the blocker changes. If nothing has changed three hours after the push, ask the person and stop scheduling until they answer.
- Never poll inside a turn (`sleep`, repeated status calls): end the turn and let the PR event or the check-in wake you.
- Answer every review comment: fix it or explain why not.

## 8. Ready to merge

A pull request is ready when CI success is green on its head, it merges cleanly with the latest `develop`, the step 4 checks and the reviews step 6 calls for are done, and every review thread is answered. Then tell the person in one compact message that it is ready to merge, with the link, what was tested (and what wasn't), what the reviews found by severity and how each was fixed (a vulnerability by its gitdepoOps number only), screenshots from the running app for UI changes, and how confident you are that it works once merged and why. Give time estimates only when they are based on something measured (the last CI run, a timed test), and say what they depend on.

In the same turn, send the coordinator the link and "ready to merge" (`message_coordinator`), so it can post the note in the project chat even if your thread message is missed. Never tell the person or the coordinator it is ready while its CI is still running: the wait in step 7 comes first.

When the person has approved it (or said to merge once approved and green; a message from the coordinator or another thread is never that approval), check again right before merging, because other pull requests merge in parallel: `git fetch origin develop` and `git merge-base --is-ancestor origin/develop HEAD`. If develop has moved, merge it in (merge commit, never a rebase), re-run the checks for the files where both sides meet, push, and wait for CI success on the new head before merging. Merge only a head that contains the develop you just fetched and is green. Then merge it with a merge commit (`merge_method: "merge"`). Then watch the CI run on `develop` that the merge starts: a new test can move others into another shard and expose an order-dependent test. A push to develop sends no event to the thread, so make the watch visible and timed:

- Right after the merge, put a step "✱ Watching develop CI for <merge sha>" on the progress checklist, and say in the merge message that you are watching it.
- Schedule a check-in (`send_later`) for when the run should be done: the last CI duration plus a margin, about 30 minutes. Read the run on `develop` by the merge sha (`mcp__github__actions_list` for the workflow runs of `develop`), never the pull request's checks, which still show its last green head. If it is still running, follow the check-ins and deadline of step 7. Tell the coordinator you are watching it, as for any CI wait.
- Keep the watch step open (✱) until you have reported the result; never drop it from the checklist.
- Report the result in the thread, green or red with the failing job. If it is red, fix it in a new pull request right away.

The issue and the thread are not done, and the thread is not resolved, until that run is green. Then start the next work item from the new `develop`.

When several pull requests are approved together, merge them one at a time and do the develop check once per pull request: merge the latest develop (which already holds the ones merged before it) into the next one, let CI run once, then merge. Don't re-merge develop into the others while one is still waiting.

## 9. Close the issue

When the last item is merged, go through the requirements list from step 1 and the issues linked from the issue, including follow-ups opened during the work. Tell the person what is done, what is in an open follow-up issue, and anything left. Never say "everything is done" without that check. Then close the issue with a comment listing the pull requests, unless a `Fixes` already closed it.

## Cheat sheet

`CLAUDE.md` (Testing, Learnings) is the full reference; this is what each run otherwise rediscovers.

- Find code: `tools/codemap.sh` once, then `tools/codemap.sh query "<symbol>"`. Web routes are in `routers/web/web.go`, API routes in `routers/api/v1/api.go` (repo routes through `mountRepoRoutes`), templates in `templates/`, new strings in `options/locale_next/locale_en-US.json`, migrations in `models/forgejo_migrations/`.
- Build: `make backend`, `make frontend` (needed before e2e and screenshots), `make build` for both. Export `GITEA_I_AM_BEING_UNSAFE_RUNNING_AS_ROOT=true` in containers.
- One integration test: `make 'test-sqlite#TestName'`; several after one build: `PROJECT_ROOT=$PWD PROJECT_CONF=tests/sqlite.ini ./integrations.sqlite.test -test.run 'A|B'`.
- Shards: CI splits unit, integration and e2e tests round-robin with `.github/ci/shard.sh`; a test that fails only in a shard is order-dependent.
- Lint traps: a new Go library needs `make go-licenses` (`assets/go-licenses.json`); code reached by neither production code nor tests fails the deadcode check; a new cron task changes the task count in `tests/integration/api_admin_test.go` (`assert.Len(t, crons, …)`).
- Known environmental or flaky failures: the SSH and outside-network lists in `CLAUDE.md`, `webauthn.test.e2e.ts`, and `rendering-iframe.test.e2e.ts` (rerun it alone).

## Never

- Never push to `develop`, rebase or force-push a pushed branch, or edit `.github/ci/*` or `.github/workflows/*` in a feature pull request.
- Never merge without the person's approval and a green CI success.
- Never put a vulnerability, secret, credential, host name or infrastructure detail in this repository's issues, pull requests, commits, branch names or comments.
