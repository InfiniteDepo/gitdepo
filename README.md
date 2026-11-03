# gitdepo

**gitdepo: a self-hosted Git forge, based on Forgejo.**

gitdepo is a self-hosted Git forge for companies that must pass security and compliance audits, built with **SOC 2** and **ISO/IEC 27001** controls in mind: who can access what, how credentials are managed, how changes reach protected branches, and how the platform is operated.
It keeps everything Forgejo offers and adds a tamper-evident audit log, projects, credential expiry and more.

> gitdepo helps you meet SOC 2 and ISO 27001 controls; it does not make an organization compliant or certified by itself. Certification covers your organization, processes and evidence, not a single tool.

## Highlights

- **Tamper-evident audit log**: sign-ins, credential use and settings changes are recorded in a hash chain you can verify and export ([#518](https://github.com/InfiniteDepo/gitdepo/pull/518), [#535](https://github.com/InfiniteDepo/gitdepo/pull/535)).
- **Projects**: group repositories under an organization and share teams, branch rules, webhooks, secrets and deploy keys across them ([#434](https://github.com/InfiniteDepo/gitdepo/pull/434), [#450](https://github.com/InfiniteDepo/gitdepo/pull/450), [#452](https://github.com/InfiniteDepo/gitdepo/pull/452)).
- **One-command Bitbucket Data Center import**: bring projects, repositories, permissions, keys and branch rules over with `admin bitbucket-import` ([#488](https://github.com/InfiniteDepo/gitdepo/pull/488)).
- **Read-only auditor role**: reviewers read every repository and nothing else, granted through a user group ([#118](https://github.com/InfiniteDepo/gitdepo/pull/118)).
- **Credential expiry**: SSH keys, deploy keys, access tokens and OAuth2 app secrets expire, with a maximum set by the admin ([#115](https://github.com/InfiniteDepo/gitdepo/pull/115), [#466](https://github.com/InfiniteDepo/gitdepo/pull/466)).
- **Organization guard rails**: required 2FA, verified email domains and repository policies per organization ([#331](https://github.com/InfiniteDepo/gitdepo/pull/331), [#356](https://github.com/InfiniteDepo/gitdepo/pull/356), [#336](https://github.com/InfiniteDepo/gitdepo/pull/336)).
- **Trash and restore**: deleted repositories and organizations stay recoverable for a retention period ([#281](https://github.com/InfiniteDepo/gitdepo/pull/281), [#313](https://github.com/InfiniteDepo/gitdepo/pull/313)).
- **Exact and regex code search**: zoekt searches several branches at once ([#270](https://github.com/InfiniteDepo/gitdepo/pull/270)).
- **Faster git under load**: 2× the pushes and 2.3× the pulls of Forgejo with default settings, and pushes stay under a second with 3,000 users ([`docs/performance.md`](docs/performance.md)).

## Coming from GitHub, GitLab, Bitbucket or Azure DevOps?

| You know | In gitdepo |
|---|---|
| GitHub organizations and teams, GitLab groups | Organizations and teams, plus [user groups shared across organizations](docs/features.md#identity-and-access) |
| GitLab subgroups, Bitbucket projects, Azure DevOps projects | [Projects](docs/features.md#projects): repositories grouped under an organization |
| GitHub Actions, GitLab CI, Azure Pipelines | Actions: GitHub-compatible workflows, with [job token permissions and scheduled runs](docs/features.md#actions) |
| Branch protection, GitLab push rules, Bitbucket branch restrictions | [Branch protection, approval rules and push rules](docs/features.md#change-control), also at organization and project level |
| GitHub and GitLab audit events | [Audit log](docs/features.md#audit-log) |
| GitHub and GitLab personal access tokens | Access tokens with [expiry](docs/features.md#credentials) and a [scope policy](docs/features.md#operations-and-administration) |
| Bitbucket Data Center repositories | [`admin bitbucket-import`](docs/features.md#bitbucket-data-center-import) |
| GitLab auditor users | The [auditor role](docs/features.md#identity-and-access) |

## Get started

You need Go (the version in `go.mod`), Node.js (the version in `.node-version`), `make` and Git.

```sh
make deps
make build        # frontend and backend
./gitea web       # then open http://localhost:3000 for the installer
```

The binary is still called `gitea`. Settings go in `app.ini`; [`custom/conf/app.example.ini`](custom/conf/app.example.ini) lists every key.

### Install on Kubernetes

The [Helm chart](helm/gitdepo/README.md) installs the published image `ghcr.io/infinitedepo/gitdepo` on any cluster (AKS, EKS, GKE, on-prem) with an external PostgreSQL database; it has example values for each cloud.

## Why a separate project

gitdepo was inspired by teams moving off big vendors that keep raising prices while long-standing customer bugs stay open, such as Bitbucket Data Center, GitLab and GitHub. Anyone moving off them can use gitdepo.

gitdepo's goals have diverged from Forgejo's:

- **Compliance-first.** Features are chosen for audit and enterprise needs (access reviews, least privilege, credential policy, change control), not general-purpose or community hosting.
- **AI-assisted development.** gitdepo is built with AI coding agents (Claude Code) working alongside people, with review, security review and testing on every change. Forgejo doesn't accept AI-generated contributions, so gitdepo's changes are not offered back upstream.
- **Independent roadmap.** gitdepo still merges Forgejo's changes regularly to keep its fixes and security updates.

## Credits

gitdepo is a fork of **[Forgejo](https://codeberg.org/forgejo/forgejo)**, its predecessor, which is itself a fork of [Gitea](https://gitea.com) and [Gogs](https://gogs.io). Almost all of gitdepo's code is their work. Thank you to the Forgejo, Gitea and Gogs contributors. See [NOTICE](NOTICE).

gitdepo started as a fork of [Forgejo](https://forgejo.org) and keeps everything Forgejo offers: Git hosting, issues, pull requests, wikis, project boards, Actions (GitHub-compatible CI), a package registry for about 20 formats, LDAP and OAuth2/OIDC sign-in, and more. On top of that it adds the features listed in [`docs/features.md`](docs/features.md).

gitdepo is a modified version of Forgejo, changed by the gitdepo contributors since 2026 (see the git history for each change). It is not affiliated with or endorsed by Forgejo or Codeberg e.V. "Forgejo" is a trademark of Codeberg e.V. and names the Forgejo project only.

"Git" is a trademark of the Software Freedom Conservancy. gitdepo uses Git but is not affiliated with or endorsed by the Git project.

## Features gitdepo adds

[`docs/features.md`](docs/features.md) lists every feature gitdepo adds to Forgejo, grouped by area, with links to the pull requests that added them.

## Roadmap

Planned work is tracked in [issues](https://github.com/InfiniteDepo/gitdepo/issues), labelled by priority (`P0` to `P4`). Highlights include SCIM, incremental backups, high availability on Kubernetes (AKS), and a refreshed interface.

## Naming

The interface, emails, logo and default settings say gitdepo, and a "based on Forgejo" link in the footer credits the upstream project. Set `APP_NAME` in `app.ini` to show your own site name. [`docs/branding.md`](docs/branding.md) lists what the rename changes and how to keep it across upstream merges.

## Documentation

Forgejo's [documentation](https://forgejo.org/docs/latest/) applies to everything gitdepo inherits. gitdepo's additions are described in their pull requests and in [`docs/`](docs).

## Contributing

Changes go through pull requests into `develop` on this repository. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow, local test steps and conventions.

Pick a [good first issue](https://github.com/InfiniteDepo/gitdepo/issues?q=is%3Aopen+label%3A%22good+first+issue%22). The repository ships Claude Code skills in [`.claude/skills`](.claude/skills) (`coder`, `issue-to-merge`, `tester`, `security-review`, `screenshots`) that take an issue to a reviewed pull request with AI help; [`CONTRIBUTING.md`](CONTRIBUTING.md#ai-assisted-contributions) says how to disclose it.

## License

gitdepo is distributed under the terms of the [GPL version 3.0](LICENSE) or any later version, the same license as Forgejo. Forgejo versions before v9.0 were distributed under the MIT license. Copyright notices of the original authors are kept in the source files.
