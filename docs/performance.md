# Git performance under load

How gitdepo's git over HTTP holds up with 16 to 3,000 users, compared with the Forgejo commit gitdepo forked from, Gitea and Bitbucket Data Center.
Measured on 2026-10-23.

## Result in short

- With default settings, gitdepo handles 2× the pushes and 2.3× the pulls of Forgejo.
- With 3,000 users working at a normal pace, the slowest 10% of gitdepo's pushes take 0.29 s, where Forgejo's take 31 s.
- gitdepo's defaults also beat Forgejo with hand-tuned settings.
- It also leads Gitea and Bitbucket Data Center on every step ([Other git servers](#other-git-servers)).
- The limit is CPU in the application (git and its hook processes), never the database.

## How it was tested

| | |
|---|---|
| Hardware | One machine with 4 CPU cores and 15 GB RAM, PostgreSQL 16 on the same machine, and the load generator on the same 4 cores. Absolute numbers are small; the ratios carry over to bigger hardware. |
| Forgejo | Upstream `3a81b293` (2026-10-03), the commit gitdepo forked from. |
| gitdepo | `develop` at `0a4f1e05` (2026-10-22). |
| Data | 300 private repositories (306 commits, 2.7 MB each), 3,000 users with access tokens, 10 users per repository. |
| Pull | A protocol v2 `git fetch` (`ls-refs`, then `fetch` with wants and haves), and a share of full clones. |
| Push | A new commit on the user's own branch through `git-receive-pack`, with every hook running. |
| Realistic | Each user pauses 0 to 5 minutes between operations, and 20% of operations are pushes. |
| Nonstop | No pauses: deliberate overload. |

Both servers ran back to back on the same machine, each with a fresh database and the same steps in the same order. SSH was not tested; it runs the same hooks plus one more process per operation.

## Default settings

| Step | Forgejo | gitdepo | Change |
|---|---|---|---|
| Pushes only, 16 users | 7.5 pushes/s, median 2.13 s | 15.4 pushes/s, median 1.03 s | +105% |
| Pulls only, 16 users | 77.8 ops/s, fetch median 0.18 s | 182.7 ops/s, fetch median 0.06 s | +135% |
| Mixed, 100 users | 15.4 ops/s, push median 8.7 s | 28.8 ops/s, push median 3.8 s | +87% |
| Nonstop, 3,000 users | 17.8 ops/s, 0 refused, medians 114 to 147 s | 27.1 ops/s, 1,517 refused as busy, medians 61 to 108 s | +52% completed |
| Realistic, 3,000 users: fetch median / 90th percentile | 0.14 s / 38.8 s | 0.02 s / 0.04 s | |
| Realistic, 3,000 users: push median / 90th percentile | 0.92 s / 31.0 s | 0.23 s / 0.29 s | |

In the realistic run, throughput (18 to 21 operations per second on both) is set by how often users act, so latency is what to compare.

## Tuned settings

Tuned means `[database] MAX_OPEN_CONNS = 100`, `MAX_IDLE_CONNS = 100` and `[security] SUCCESSFUL_TOKENS_CACHE_SIZE = 10000`. gitdepo now ships the last two as defaults.

| Step | Forgejo | gitdepo |
|---|---|---|
| Pushes only, 16 users | 8.6 pushes/s | 15.5 pushes/s (+80%) |
| Pulls only, 16 users | 148.4 ops/s | 171.5 ops/s (+16%) |
| Nonstop, 3,000 users | 19.4 ops/s, 0 refused | 24.7 ops/s, 1,954 refused as busy |
| Realistic, 3,000 users: fetch median / 99th percentile | 0.04 s / 4.3 s | 0.02 s / 0.07 s |
| Realistic, 3,000 users: push median / 99th percentile | 0.45 s / 5.0 s | 0.24 s / 0.35 s |

## Other git servers

The same steps on the same machine against Gitea 28.2.0 (the binary from the official image, run natively) and Bitbucket Data Center 10.5.1 (the official Docker image), each with default settings, a fresh database and the same seed.

| Step | gitdepo | Forgejo | Gitea | Bitbucket |
|---|---|---|---|---|
| Pushes only, 16 users | **15.4 pushes/s** | 7.5 | 6.9 | 10.4 |
| Pulls only, 16 users | **182.7 ops/s** | 77.8 | 70.9 | 22.6 |
| Mixed, 100 users | **28.8 ops/s** | 15.4 | 12.6 | 23.4 |
| Nonstop, 3,000 users: completed | **27.1 ops/s** | 17.8 | 2.4 | 12.2 |
| Nonstop, 3,000 users: failed | 1,517 refused as busy (503) | 0 | 44,814 errors (500) | 0 |
| Realistic, 3,000 users: push median / 90th percentile | **0.23 s / 0.29 s** | 0.92 s / 31.0 s | 2.08 s / 16.9 s | 1.32 s / 43.6 s |
| Realistic, 3,000 users: fetch median / 90th percentile | **0.02 s / 0.04 s** | 0.14 s / 38.8 s | 0.41 s / 25.6 s | 1.13 s / 60.4 s |
| Realistic, 3,000 users: errors | 0 | 0 | 175 | 0 |

- **Gitea** doesn't cap its database pool by default. Under nonstop load it opened more connections than PostgreSQL allows ("too many clients"), so 99% of requests failed. With the tuned settings it completed 16.1 ops/s, but it started a git process for every request (617 at once, against gitdepo's 28), and the kernel killed it for running out of memory.
- **Bitbucket** had no errors, but at 3,000 nonstop users it kept requests waiting for 2 to 4 minutes, and its pulls cost far more CPU than in the Go servers.
- Bitbucket ran on Atlassian's 10-user developer license, so the 3,000 simulated users shared 9 accounts and 9 access tokens, where the other servers checked 3,000 different tokens. That favours Bitbucket. Bitbucket 10.5 also blocks basic authentication and enforces two-step verification by default, so the test turned both off (`-Dcom.atlassian.plugins.authentication.basic.auth.filter.force.allow=true`, `-Datlassian.authentication.2sv.enforcement.enabled=false`), ran it with search off and a 2 GB heap, and ran only the default-settings steps.
- Azure DevOps Server (Windows Server and SQL Server only) and GitHub Enterprise Server (a virtual machine appliance) couldn't run on the test machine, so they aren't included.

## What made the difference

| Finding | Change | Effect |
|---|---|---|
| The access-token cache was never created (a one-character bug inherited from upstream), so every git request re-hashed its token with PBKDF2. With only 2 idle database connections, PostgreSQL also opened about 70 new connections per second. | [#567](https://github.com/InfiniteSpoved/spoved/pull/567) fixes the cache, keeps idle connections open and skips the `update` hook | Pulls 52 → 146 ops/s, pushes 6.1 → 8.2/s |
| Each push starts the gitdepo binary as git hooks, and about 40% of that start-up was garbage collection. | [#575](https://github.com/InfiniteSpoved/spoved/pull/575) runs the hooks with garbage collection off | Pushes 8.2 → 11.6/s |
| Under heavy git load, web pages slowed from 0.05 s to 1.7 s, because git work took every core. | [#578](https://github.com/InfiniteSpoved/spoved/pull/578) caps concurrent git operations | Web median 1.7 → 0.32 s at 100 users |
| A repository created by an import has no reachability bitmap, so every full clone walks its whole history (4.9 s of CPU for a repository the size of gitdepo). | [#584](https://github.com/InfiniteSpoved/spoved/pull/584) writes a bitmap at import | Clones of an imported repository 0.6 → 1.7/s |

The bitmap gain doesn't show in the tables above, because the test repositories are small and were created by push, not imported.

## When the server is full

Under nonstop overload, Forgejo keeps every request waiting, for two minutes or more at 3,000 users. gitdepo refuses a git operation it can't start within a minute with HTTP 503 and "The server is busy, please try again in a moment.", so web pages stay responsive. git does not retry by itself. The limit and the wait are `[git] MAX_CONCURRENT_OPERATIONS` (default 4 per CPU core, 0 = no limit) and `OPERATION_QUEUE_TIMEOUT` (default 1 minute).

The audit log costs gitdepo 3 to 5% more CPU per operation than Forgejo, which the changes above more than make up for.

## Still open

- [#568](https://github.com/InfiniteSpoved/spoved/issues/568): a smaller hook binary, which would make pushes cheaper still.
- [#569](https://github.com/InfiniteSpoved/spoved/issues/569): per-user git rate limits, so one user can't fill the cap.
- [#570](https://github.com/InfiniteSpoved/spoved/issues/570): repacking after pushes, and a cache for identical fetches.
