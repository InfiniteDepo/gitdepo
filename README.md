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
| GitHub organizations and teams, GitLab groups | Organizations and teams, plus [user groups shared across organizations](#identity-and-access) |
| GitLab subgroups, Bitbucket projects, Azure DevOps projects | [Projects](#projects): repositories grouped under an organization |
| GitHub Actions, GitLab CI, Azure Pipelines | Actions: GitHub-compatible workflows, with [job token permissions and scheduled runs](#actions) |
| Branch protection, GitLab push rules, Bitbucket branch restrictions | [Branch protection, approval rules and push rules](#change-control), also at organization and project level |
| GitHub and GitLab audit events | [Audit log](#audit-log) |
| GitHub and GitLab personal access tokens | Access tokens with [expiry](#credentials) and a [scope policy](#operations-and-administration) |
| Bitbucket Data Center repositories | [`admin bitbucket-import`](#bitbucket-data-center-import) |
| GitLab auditor users | The [auditor role](#identity-and-access) |

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

gitdepo started as a fork of [Forgejo](https://forgejo.org) and keeps everything Forgejo offers: Git hosting, issues, pull requests, wikis, project boards, Actions (GitHub-compatible CI), a package registry for about 20 formats, LDAP and OAuth2/OIDC sign-in, and more. On top of that it adds the features listed below.

gitdepo is a modified version of Forgejo, changed by the gitdepo contributors since 2026 (see the git history for each change). It is not affiliated with or endorsed by Forgejo or Codeberg e.V. "Forgejo" is a trademark of Codeberg e.V. and names the Forgejo project only.

"Git" is a trademark of the Software Freedom Conservancy. gitdepo uses Git but is not affiliated with or endorsed by the Git project.

## Features gitdepo adds

Each feature links to the pull request that added it.

### Identity and access

| Feature | What it does |
|---|---|
| **User groups shared across organizations** ([#3](https://github.com/InfiniteDepo/gitdepo/pull/3), API [#9](https://github.com/InfiniteDepo/gitdepo/pull/9)) | Instance-wide groups, managed by site admins, that org owners link to their teams. One group gives the same people access across many organizations, while each org keeps control of the permissions. |
| **Groups synced from LDAP / OIDC** ([#48](https://github.com/InfiniteDepo/gitdepo/pull/48)) | Directory groups (Active Directory, Entra ID claims) map to user groups. Membership syncs at sign-in and during LDAP sync, and only memberships added by the directory are ever removed. |
| **Team pages show where access comes from** ([#51](https://github.com/InfiniteDepo/gitdepo/pull/51), [#53](https://github.com/InfiniteDepo/gitdepo/pull/53)) | Each linked group's member count, and which group each member comes from. |
| **Roles through groups** ([#54](https://github.com/InfiniteDepo/gitdepo/pull/54)) | A group can make its members site administrators or allow them to create organizations. The last site admin can't be removed. |
| **Auditor (read-all) role** ([#118](https://github.com/InfiniteDepo/gitdepo/pull/118)) | Members of an auditor group can read every repository and private organization, and nothing more. Writes are refused everywhere (web, API, git, SSH, LFS). Read-only access for security and compliance reviewers without admin rights. |
| **No organization creation by default** ([#44](https://github.com/InfiniteDepo/gitdepo/pull/44)) | New users can't create organizations unless an admin allows it. |

### Credentials

| Feature | What it does |
|---|---|
| **Expiry for SSH keys, deploy keys and access tokens** ([#115](https://github.com/InfiniteDepo/gitdepo/pull/115)) | Expiry dates, required by default with a maximum of 365 days ([#459](https://github.com/InfiniteDepo/gitdepo/issues/459)). Expired credentials are refused everywhere. Admins can lower the maximum or turn a policy off: `[security] SSH_KEY_*`, `DEPLOY_KEY_*` and `ACCESS_TOKEN_*` with `_EXPIRY_REQUIRED` and `_MAX_LIFETIME_DAYS`. Turning a policy off needs both keys, `_EXPIRY_REQUIRED = false` and `_MAX_LIFETIME_DAYS = 0`: a maximum alone still requires an expiry date. |
| **Expiry for OAuth2 app secrets** ([#466](https://github.com/InfiniteDepo/gitdepo/pull/466)) | Client secrets expire; an expired secret is refused at the token endpoint. `[security] OAUTH2_APP_SECRET_EXPIRY_REQUIRED` and `OAUTH2_APP_SECRET_MAX_LIFETIME_DAYS` (default 365 days). Who may create OAuth2 apps is set under a policy form on Site administration → Applications ([#286](https://github.com/InfiniteDepo/gitdepo/pull/286)). |
| **Specific deploy keys in branch and tag protection** ([#50](https://github.com/InfiniteDepo/gitdepo/pull/50)) | Allow chosen deploy keys, not all of them, to push to protected branches and tags. Deploy-key pushes to protected tags are decided by the key, never by the repository owner's identity. |

### Change control

| Feature | What it does |
|---|---|
| **Push rules** ([#116](https://github.com/InfiniteDepo/gitdepo/pull/116)) | Require commit message and branch name patterns, author emails that match the pusher, and maximum file sizes; block banned file names. |
| **Approval rules** ([#241](https://github.com/InfiniteDepo/gitdepo/pull/241), [#284](https://github.com/InfiniteDepo/gitdepo/pull/284)) | Protected branches require approvals from chosen users or teams, or from the code owners. Branch protection → Approval rules. |
| **Organization-wide branch protection** ([#247](https://github.com/InfiniteDepo/gitdepo/pull/247), [#254](https://github.com/InfiniteDepo/gitdepo/pull/254)) | Branch rules set once by an organization owner apply to every repository of the organization. Organization settings → Branches; API under `/orgs/{org}`. |
| **Delete and force-push allow-lists** ([#52](https://github.com/InfiniteDepo/gitdepo/pull/52)) | Protected branches can allow chosen users, teams or deploy keys to delete them or force-push; everyone else stays blocked. The default branch can never be deleted. |
| **Pull request title rules** ([#352](https://github.com/InfiniteDepo/gitdepo/pull/352)) | Regular-expression rules for pull request titles, enforced when the pull request is created or edited, or only at merge. Repository settings → Push rules. |
| **Attention set** ([#347](https://github.com/InfiniteDepo/gitdepo/pull/347)) | Shows on each pull request whose turn it is, and filters lists with `@me`. Always on. |
| **Merge queue** ([#31](https://github.com/InfiniteDepo/gitdepo/issues/31)) | Protected branches can require a merge queue: each pull request is tested on top of the branch and the ones ahead of it (Actions `merge_group` event), and exactly the tested commit is merged, alone or in groups. See [`docs/merge-queue.md`](docs/merge-queue.md). |
| **Scheduled auto-merge** ([#110](https://github.com/InfiniteDepo/gitdepo/pull/110)) | Merge an approved pull request at a chosen time (e.g. after hours), tied to the reviewed commit so later pushes can't slip in unreviewed. |
| **Revert a merged pull request** ([#90](https://github.com/InfiniteDepo/gitdepo/pull/90), [#135](https://github.com/InfiniteDepo/gitdepo/pull/135)) | One button creates a pull request that reverts the merge, for every merge style. Both pull requests link to each other in the timeline. |
| **Generated release notes** ([#108](https://github.com/InfiniteDepo/gitdepo/pull/108)) | Draft release notes from the pull requests merged since the previous tag, grouped by label (`.forgejo/release.yml` or `.github/release.yml`). |
| **Organization and instance-wide templates** ([#99](https://github.com/InfiniteDepo/gitdepo/pull/99)) | Issue and pull request templates fall back to the organization's `.forgejo` repository, then to an instance repository (`[repository] DEFAULT_TEMPLATES_REPO`), so one checklist applies everywhere. |

### Operations and administration

| Feature | What it does |
|---|---|
| **Rate limiting** ([#133](https://github.com/InfiniteDepo/gitdepo/pull/133), [#201](https://github.com/InfiniteDepo/gitdepo/pull/201), [#362](https://github.com/InfiniteDepo/gitdepo/pull/362), [#373](https://github.com/InfiniteDepo/gitdepo/pull/373), [#379](https://github.com/InfiniteDepo/gitdepo/pull/379), [#386](https://github.com/InfiniteDepo/gitdepo/pull/386)) | Limits for API, git, web and sign-in traffic per user and per IP, with standard 429 responses; stricter limits on failed sign-ins, heavy requests (search, diffs, blame, archives) and SSH. Admins can be exempted. Off until enabled in `[rate_limit]` (`[rate_limit.heavy]`, `[rate_limit.ssh]`, `[rate_limit.ssh_connect]`). |
| **Storage report** ([#109](https://github.com/InfiniteDepo/gitdepo/pull/109), API [#141](https://github.com/InfiniteDepo/gitdepo/pull/141)) | Site administration → Storage: git and LFS size in total, per owner and per repository, with a CSV export of the per-owner table and admin API endpoints. |
| **Trash and restore** ([#281](https://github.com/InfiniteDepo/gitdepo/pull/281), [#313](https://github.com/InfiniteDepo/gitdepo/pull/313)) | Deleted repositories, organizations and purged users' repositories stay hidden for a retention period; admins restore or purge them at Site administration → Trash. `[trash] RETENTION_DAYS`, `TRASH_USER_REPOS`. |
| **Maintenance and read-only mode** ([#259](https://github.com/InfiniteDepo/gitdepo/pull/259)) | Block writes, or everyone but admins, during upgrades and backups. Site administration → Maintenance, `admin maintenance enable\|disable`, or `[maintenance] MODE`. |
| **IP allowlist** ([#261](https://github.com/InfiniteDepo/gitdepo/pull/261)) | Restrict web, API, git, SSH and package access to chosen addresses. Site administration → IP allowlist. |
| **Log shipping** ([#320](https://github.com/InfiniteDepo/gitdepo/pull/320), [#398](https://github.com/InfiniteDepo/gitdepo/pull/398)) | Send application, access, router and git logs over HTTPS to New Relic (`[log.newrelic]`) or any endpoint (Site administration → Log shipping). Secrets are redacted. |
| **Access token scope policy** ([#325](https://github.com/InfiniteDepo/gitdepo/pull/325), [#400](https://github.com/InfiniteDepo/gitdepo/pull/400)) | Limit which scopes non-admins can give tokens and integrations, require a repository restriction for chosen scopes, and refuse older tokens after a date. `[security] ACCESS_TOKEN_ALLOWED_SCOPES`, `ACCESS_TOKEN_SCOPES_REQUIRING_REPO_RESTRICTION`, `ACCESS_TOKEN_SCOPE_POLICY_ENFORCE_AFTER`. |
| **Tokens of service accounts** ([#502](https://github.com/InfiniteDepo/gitdepo/issues/502)) | Site administration → Users → Edit lists, creates, regenerates and revokes the access tokens of a local account, with the same form, expiry and scope policy as the user's own page. Every change is in the audit log with the admin as actor. |
| **Personal repository policy and size limit** ([#495](https://github.com/InfiniteDepo/gitdepo/pull/495), [#497](https://github.com/InfiniteDepo/gitdepo/pull/497)) | Allow, force private or disable repositories under user accounts, and lock writes past a size limit. `[repository] PERSONAL_REPOS`, `PERSONAL_REPOS_SIZE_LIMIT`; Site administration → Personal repositories. |
| **Announcement banners** ([#49](https://github.com/InfiniteDepo/gitdepo/pull/49)) | Site-wide banners (info, warning, critical) with schedules, shown to everyone, signed-in users or admins, for maintenance and policy notices. |

### Audit log

Records who did what and with which credential. See [`docs/audit-log.md`](docs/audit-log.md).

| Feature | What it does |
|---|---|
| **Audit log, filters and export** ([#509](https://github.com/InfiniteDepo/gitdepo/pull/509), [#518](https://github.com/InfiniteDepo/gitdepo/pull/518), [#534](https://github.com/InfiniteDepo/gitdepo/pull/534)) | Site administration → Audit (admins and auditors), `GET /api/v1/admin/audit` and `admin audit export`, with filters by actor, action, target, credential and time. Always on. |
| **Sign-ins and credential activity** ([#520](https://github.com/InfiniteDepo/gitdepo/pull/520), [#533](https://github.com/InfiniteDepo/gitdepo/pull/533)) | Sign-ins, failures, credential use, refusals, API writes, pushes, downloads and uploads. `[audit] LOG_READS` also records reads of private repositories. |
| **Change records** ([#521](https://github.com/InfiniteDepo/gitdepo/pull/521), [#522](https://github.com/InfiniteDepo/gitdepo/pull/522), [#524](https://github.com/InfiniteDepo/gitdepo/pull/524), [#526](https://github.com/InfiniteDepo/gitdepo/pull/526), [#528](https://github.com/InfiniteDepo/gitdepo/pull/528), [#529](https://github.com/InfiniteDepo/gitdepo/pull/529), [#530](https://github.com/InfiniteDepo/gitdepo/pull/530), [#531](https://github.com/InfiniteDepo/gitdepo/pull/531)) | Accounts, keys, OAuth2 apps, runners, settings, organizations, teams, repositories, webhooks and mirrors record who changed what. |
| **Hash chain and retention** ([#535](https://github.com/InfiniteDepo/gitdepo/pull/535), [#537](https://github.com/InfiniteDepo/gitdepo/pull/537)) | Entries are sealed in a hash chain; `admin audit verify` checks it. Retention is set at Site administration → Audit → Retention. |

### Projects

Projects group repositories under an organization (`org/project/repo`).

| Feature | What it does |
|---|---|
| **Projects and paths** ([#434](https://github.com/InfiniteDepo/gitdepo/pull/434), [#436](https://github.com/InfiniteDepo/gitdepo/pull/436), [#438](https://github.com/InfiniteDepo/gitdepo/pull/438), [#439](https://github.com/InfiniteDepo/gitdepo/pull/439)) | Create, rename and delete projects at `/org/{org}/groups`; web, git over HTTP and SSH, and LFS work with the project path. Always on. |
| **Moves and redirects** ([#443](https://github.com/InfiniteDepo/gitdepo/pull/443)) | Move repositories into, out of and between projects; old paths redirect. Repository settings → Danger zone. |
| **Teams** ([#450](https://github.com/InfiniteDepo/gitdepo/pull/450)) | Link a team to a project to give it every repository in it. |
| **Branch rules, webhooks, secrets, variables and deploy keys** ([#452](https://github.com/InfiniteDepo/gitdepo/pull/452), [#453](https://github.com/InfiniteDepo/gitdepo/pull/453), [#454](https://github.com/InfiniteDepo/gitdepo/pull/454), [#456](https://github.com/InfiniteDepo/gitdepo/pull/456)) | Set once on the project and apply to all its repositories. Project settings. |
| **API** ([#442](https://github.com/InfiniteDepo/gitdepo/pull/442), [#469](https://github.com/InfiniteDepo/gitdepo/pull/469)) | `/orgs/{org}/projects` and its branch protection, hook, secret and variable endpoints; `/repositories/{id}`. |
| **URL forms** | Web, git, LFS and API paths of `org/project/repo`, redirects and what to update in tools that link to repositories: [`docs/projects.md`](docs/projects.md). |
| **Projects elsewhere** ([#458](https://github.com/InfiniteDepo/gitdepo/pull/458), [#494](https://github.com/InfiniteDepo/gitdepo/pull/494), [#523](https://github.com/InfiniteDepo/gitdepo/pull/523)) | References, mail, packages, token repository pickers and migrations understand `owner/project/repo`. |

### Bitbucket Data Center import

| Feature | What it does |
|---|---|
| **`admin bitbucket-import`** ([#488](https://github.com/InfiniteDepo/gitdepo/pull/488), [#489](https://github.com/InfiniteDepo/gitdepo/pull/489), [#490](https://github.com/InfiniteDepo/gitdepo/pull/490)) | Imports projects and repositories into an organization, with pull requests, team and collaborator permissions, access keys, branch rules and webhooks. Reports what it cannot map. `admin bitbucket-import --server <url> --org <org>`, token from `--token-file` or `BITBUCKET_TOKEN`; `--skip-unmapped`, `--key-expiry` and a dry run. |
| **Origin on the repository** ([#487](https://github.com/InfiniteDepo/gitdepo/pull/487)) | The repository page shows the Bitbucket origin, and search finds `KEY/slug`. |

### Organization controls

| Feature | What it does |
|---|---|
| **Organization deploy keys** ([#428](https://github.com/InfiniteDepo/gitdepo/pull/428), [#429](https://github.com/InfiniteDepo/gitdepo/pull/429), [#430](https://github.com/InfiniteDepo/gitdepo/pull/430)) | One SSH deploy key for chosen repositories or all of an organization's. Organization settings → Deploy keys; `/api/v1/orgs/{org}/keys`. |
| **Required 2FA** ([#331](https://github.com/InfiniteDepo/gitdepo/pull/331), [#397](https://github.com/InfiniteDepo/gitdepo/pull/397)) | Members without two-factor authentication lose access to the organization's repositories; owners see who is missing. Organization settings → `require_two_factor`. |
| **Repository policies** ([#336](https://github.com/InfiniteDepo/gitdepo/pull/336), [#395](https://github.com/InfiniteDepo/gitdepo/pull/395)) | Owners restrict visibility changes and private forks; the site sets a minimum with `[repository] ORG_RESTRICT_VISIBILITY_CHANGE` and `ORG_PRIVATE_FORK_POLICY`. |
| **Verified domains** ([#356](https://github.com/InfiniteDepo/gitdepo/pull/356)) | Verify a domain with a DNS TXT record and require members to have a verified email domain. Organization settings → Verified domains. |
| **Repository units** ([#326](https://github.com/InfiniteDepo/gitdepo/pull/326)) | Owners switch units such as Issues or Packages off for the whole organization. |

### Actions

| Feature | What it does |
|---|---|
| **Job token permissions** ([#367](https://github.com/InfiniteDepo/gitdepo/pull/367), [#371](https://github.com/InfiniteDepo/gitdepo/pull/371), [#388](https://github.com/InfiniteDepo/gitdepo/pull/388)) | Workflow `permissions:` limit what the job token can do; the default is `[actions] DEFAULT_TOKEN_PERMISSIONS` or Settings → Actions → General. |
| **Scheduled runs** ([#391](https://github.com/InfiniteDepo/gitdepo/pull/391), [#396](https://github.com/InfiniteDepo/gitdepo/pull/396)) | "Run later" on a manual workflow, with a list of scheduled runs to cancel or retime. |
| **Run retention** ([#107](https://github.com/InfiniteDepo/gitdepo/pull/107), [#419](https://github.com/InfiniteDepo/gitdepo/pull/419), [#420](https://github.com/InfiniteDepo/gitdepo/pull/420), [#424](https://github.com/InfiniteDepo/gitdepo/pull/424)) | `[actions] RUN_RETENTION_DAYS` deletes old runs, keeping the latest run of each workflow; `RUN_RETENTION_MAX_DAYS` caps it; organizations and repositories can shorten it; "Keep this run" exempts a run; Settings → Actions → delete runs older than. |
| **Organization and instance run pages** ([#304](https://github.com/InfiniteDepo/gitdepo/pull/304), [#312](https://github.com/InfiniteDepo/gitdepo/pull/312), [#316](https://github.com/InfiniteDepo/gitdepo/pull/316)) | Runs, queue and failure overview per organization (`/org/{org}/actions`) and for the whole instance (Site administration → Actions), with a usage CSV export. |
| **Restrict who registers runners** ([#106](https://github.com/InfiniteDepo/gitdepo/pull/106)) | `[actions] RUNNER_REGISTRATION = admin`, `admin_and_org_owners` or `everyone`. |

### Search

| Feature | What it does |
|---|---|
| **zoekt code search** ([#270](https://github.com/InfiniteDepo/gitdepo/pull/270), [#280](https://github.com/InfiniteDepo/gitdepo/pull/280), [#353](https://github.com/InfiniteDepo/gitdepo/pull/353)) | Exact and regular-expression search over several branches. `[indexer] REPO_INDEXER_TYPE = zoekt`. |

### Interface

| Feature | What it does |
|---|---|
| **Company design tokens and themes** ([#104](https://github.com/InfiniteDepo/gitdepo/pull/104)) | Light, dark, auto and high-contrast themes built on design tokens, with WCAG contrast checked in tests. Enable them with `[ui] THEMES` and `DEFAULT_THEME`. |
| **draw.io diagrams** ([#103](https://github.com/InfiniteDepo/gitdepo/pull/103)) | `.drawio` files render in the file view, sandboxed, with no requests outside the instance. `[markup] DRAWIO_ENABLED` turns it off. |
| **Web IDE** ([#24](https://github.com/InfiniteDepo/gitdepo/issues/24)) | VS Code in the browser: press `.` on a file, folder or pull request, edit, rename and delete files, and commit them in one commit to the branch or to a new branch with a pull request. Protected branches, push rules and quota apply as for any push. Its files are served from disk, not from the binary; `[ide] ENABLED` turns it off. See [`docs/web-ide.md`](docs/web-ide.md). |

### Development and quality

- CI on every pull request runs the lints, frontend checks, unit, migration, integration and end-to-end tests ([#11](https://github.com/InfiniteDepo/gitdepo/pull/11), [#36](https://github.com/InfiniteDepo/gitdepo/pull/36), [#27](https://github.com/InfiniteDepo/gitdepo/pull/27), [#146](https://github.com/InfiniteDepo/gitdepo/pull/146)).
- Fix for a cancellation race in git attribute checks ([#42](https://github.com/InfiniteDepo/gitdepo/pull/42)).

Many features are **off or unchanged by default** and are switched on in `app.ini`; the audit log, projects and similar features are always on and need no setting.

## Roadmap

Planned work is tracked in [issues](https://github.com/InfiniteDepo/gitdepo/issues), labelled by priority (`P0` to `P4`). Highlights include SAML and SCIM, incremental backups, high availability on Kubernetes (AKS), and a refreshed interface.

## Naming

The interface, emails, logo and default settings say gitdepo, and a "based on Forgejo" link in the footer credits the upstream project. Set `APP_NAME` in `app.ini` to show your own site name. [`docs/branding.md`](docs/branding.md) lists what the rename changes and how to keep it across upstream merges.

## Documentation

Forgejo's [documentation](https://forgejo.org/docs/latest/) applies to everything gitdepo inherits. gitdepo's additions are described in their pull requests and in [`docs/`](docs).

## Contributing

Changes go through pull requests into `develop` on this repository. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow, local test steps and conventions.

Pick a [good first issue](https://github.com/InfiniteDepo/gitdepo/issues?q=is%3Aopen+label%3A%22good+first+issue%22). The repository ships Claude Code skills in [`.claude/skills`](.claude/skills) (`coder`, `issue-to-merge`, `tester`, `security-review`, `screenshots`) that take an issue to a reviewed pull request with AI help; [`CONTRIBUTING.md`](CONTRIBUTING.md#ai-assisted-contributions) says how to disclose it.

## License

gitdepo is distributed under the terms of the [GPL version 3.0](LICENSE) or any later version, the same license as Forgejo. Forgejo versions before v9.0 were distributed under the MIT license. Copyright notices of the original authors are kept in the source files.
