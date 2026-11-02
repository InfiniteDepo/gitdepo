# Contributing to gitdepo

gitdepo is a modified version of [Forgejo](https://forgejo.org), distributed under the GPL-3.0-or-later (see [`LICENSE`](LICENSE) and GPLv3 §5). It is not affiliated with or endorsed by the Forgejo project. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

The product name is always written in lowercase: **gitdepo**.

## Where things go

- Bugs and feature requests: open an issue in the [issue tracker of this repository](https://github.com/InfiniteDepo/gitdepo/issues). Feature requests are welcome; the templates guide you.
- Security problems: see [`SECURITY.md`](SECURITY.md). Do not open a public issue.
- Do not report gitdepo changes or bugs to the Forgejo project, and do not propose gitdepo changes to it. Forgejo's own issue trackers, chat rooms and contribution rules do not apply here.

## Branches

- `develop` is the default branch. Open all pull requests against `develop`.
- Merge `develop` into your branch with a merge commit when it falls behind. Do not rebase or force-push a branch that is already pushed.
- Maintainers port Forgejo changes into `develop` periodically; you do not need to do this in your pull request.

## Building and testing

You need Go (the version in `go.mod`), Node.js (the version in `.node-version`), `make` and Git.

```sh
make deps
make build                 # frontend and backend
./gitea web                # then open http://localhost:3000 for the installer
```

Before opening a pull request, run what applies to your change:

- Backend: `make fmt` (must leave no diff), `make lint-go lint-go-vet lint-locale lint-locale-usage lint-swagger lint-editorconfig`.
- Frontend (templates, JS, CSS): `make lint-frontend checks-frontend test-frontend frontend`.
- Unit tests: `go test -tags 'sqlite sqlite_unlock_notify' ./path/to/package/...` for the packages you changed and their neighbours.
- Integration tests: `make test-sqlite`. Run the whole suite; the tests share state and depend on order, so do not shard it. A single test: `make 'test-sqlite#TestName'`.
- End-to-end tests: `make 'test-e2e-sqlite#<spec>.test.e2e'` for the specs that cover your files. Run `make frontend` first. The first run downloads the browsers Playwright needs; see [`tests/e2e/README.md`](tests/e2e/README.md).
- Migrations: `make generate-ini-sqlite` once, then `PROJECT_CONF=tests/sqlite.ini go test ./models/forgejo_migrations/...`. Do not run it at the same time as the integration suite.

Conventions:

- Database migrations go in `models/forgejo_migrations/v18<letter>_<description>.go`. Pick the next free letter (`ls models/forgejo_migrations`).
- New interface strings go in `options/locale_next/locale_en-US.json`.
- After changing the API, run `make generate-swagger`. Do not edit `templates/swagger/v1_json.tmpl` by hand.
- Add tests for what you change, and do not remove existing tests or checks.
- Stage files by name; `make lint` can rewrite `package-lock.json`.

## Continuous integration

Every pull request runs the lints, frontend checks, unit, migration, integration and end-to-end tests on GitHub-hosted runners (`.github/workflows/ci.yml`). The check **CI success** on the head of your pull request must be green before it can be merged.

Pull requests from forks run the same CI. Each run for an outside contributor starts once a maintainer approves it. The `dco` check runs too. Changes under `.github/` (the workflows) need the maintainer's review (`.github/CODEOWNERS`). The lints and tests you can run yourself are listed in the repository's `CLAUDE.md`.

## License

gitdepo is licensed GPL-3.0-or-later because it is a fork of Forgejo, which is GPL-3.0-or-later. Contributions are accepted under the same license (inbound = outbound). Keep the existing copyright and SPDX headers of the original authors. New files get `Copyright <year> The gitdepo contributors. All rights reserved.` and `SPDX-License-Identifier: GPL-3.0-or-later` as the first two comment lines, as in any new Go file.

Every commit must carry a `Signed-off-by:` line, which certifies the [Developer Certificate of Origin](https://developercertificate.org/). Add it with `git commit -s`. This applies to commits made from the day the repository is made public; earlier history is not rewritten. A check (`tools/check-dco.sh`, run by `.github/workflows/dco.yml`) fails a pull request whose own commits, merge commits excluded, lack the line.

## AI-assisted contributions

AI-assisted contributions are welcome, and gitdepo's own changes are AI-assisted and reviewed by people. Please review and test what you submit, and say in the pull request if AI helped; it helps reviewers.
