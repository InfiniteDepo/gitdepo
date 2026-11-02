---
name: tester
description: Run the local equivalent of gitdepo's CI on a branch or pull request head and report each failure as real, known-environmental or flaky. Use when asked to "test this PR", "run the checks", "run CI locally" or "is this failure mine".
---

# Tester

You test; you don't change product code. Read `CLAUDE.md` ("Environment", "Testing", "Learnings") first.

## 1. Set up

- Check out the exact head you were given (`git checkout <sha>`) and note the 40-char SHA in your report.
- Only if you run as root (common in containers): `export GITEA_I_AM_BEING_UNSAFE_RUNNING_AS_ROOT=true`. On your own machine you don't need it.
- List the changed files: `git diff --name-only origin/develop...HEAD`. They decide what to run.

## 2. Run, fastest first

Stop at the first stage that fails only if a later stage needs it to pass (a build error).

1. **Backend lint:** golangci-lint on the changed packages, `make lint-go-vet lint-locale lint-locale-usage lint-swagger lint-editorconfig`, and `make fmt` must leave no diff.
2. **Frontend**, if templates, JS or CSS changed: `make lint-frontend checks-frontend test-frontend frontend`.
3. **Unit:** `go test -tags 'sqlite sqlite_unlock_notify'` on the changed packages and their neighbours.
4. **Migrations**, if `models/forgejo_migrations` changed: `make generate-ini-sqlite` once, then `PROJECT_CONF=tests/sqlite.ini go test ./models/forgejo_migrations/...`. Never at the same time as the integration suite.
5. **Integration**, for backend changes: the whole suite in one run, `make test-sqlite`, in the background (about 45 min); grep its output for `^(--- FAIL|FAIL|ok)`. Don't judge a PR on a partial or hand-made split.
6. **E2E:** `make frontend` first, then the specs whose `@watch` covers the changed files: `make 'test-e2e-sqlite#<spec>.test.e2e'`. A Go e2e run stops at the first failing spec file, so check that every spec ran.
7. **Other databases**, when the change adds SQL, a migration or a column type: CI runs SQLite, but gitdepo also runs on PostgreSQL and MySQL. Run the new tests there too (`make 'test-pgsql#TestName'`, `make 'test-mysql#TestName'`, and `make test-pgsql-migration` for a migration; each needs that database running, see `tests/pgsql.ini.tmpl`/`tests/mysql.ini.tmpl`). If you can't, list in the report what only those databases would catch: a value used as a column name, case-sensitive `LIKE`, `GROUP BY` without every selected column, string vs number comparison, `ON CONFLICT`/`INSERT IGNORE`, a failed statement aborting a PostgreSQL transaction.
8. **Performance**, when the change adds a list, a page or a query in a loop: no query per row (use one `GROUP BY` or a bulk load), a bounded page size, and an index for the new `WHERE`. Where a page must stay cheap, add a query-count test (see the query-count Learnings in `CLAUDE.md`).

Stage nothing and commit nothing: `make lint`/`make frontend` may rewrite `package-lock.json`; restore it (`git checkout -- package-lock.json`) when you finish.

## 3. Classify every failure

- **Known environmental:** listed in `CLAUDE.md` (no ssh tools, root warning, browser limits in containers). Name the list entry; on your own machine these usually pass.
- **Flaky:** rerun the single test (`make 'test-sqlite#TestName'`, or the one spec). If it passes alone, rerun it on `origin/develop` too; flaky means it also flips there. "Flaky" without a rerun is not a verdict.
- **Order-dependent:** passes alone, fails in the full run. Find the earlier test that leaves state behind (`-test.run '^(A|B|C)$'` with the tests before it).
- **Real:** fails on the head and passes on `origin/develop`. Give the test name, the first error line and the file:line it points to.

## 4. Report

One block, in this order: the SHA; each stage with PASS, FAIL or SKIPPED (and why skipped); then every failure as `name: real | environmental (<list entry>) | flaky (rerun results) | order-dependent (<culprit>)` with its first error line. Never paste secrets, tokens or full logs; cite the line that matters.
