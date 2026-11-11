# Features gitdepo adds to Forgejo

This is the complete list of what gitdepo adds on top of [Forgejo](https://forgejo.org). Everything else gitdepo inherits from Forgejo, and Forgejo's [documentation](https://forgejo.org/docs/latest/) applies to it.

Each feature links to the pull requests (or the issue) that added it. When a pull request adds or changes a feature, update this page in the same pull request.

## Identity and access

| Feature | What it does |
|---|---|
| **User groups shared across organizations** ([#3](https://github.com/InfiniteDepo/gitdepo/pull/3), API [#9](https://github.com/InfiniteDepo/gitdepo/pull/9)) | Instance-wide groups, managed by site admins, that org owners link to their teams. One group gives the same people access across many organizations, while each org keeps control of the permissions. |
| **Groups synced from LDAP / OIDC** ([#48](https://github.com/InfiniteDepo/gitdepo/pull/48)) | Directory groups (Active Directory, Entra ID claims) map to user groups. Membership syncs at sign-in and during LDAP sync, and only memberships added by the directory are ever removed. |
| **Team pages show where access comes from** ([#51](https://github.com/InfiniteDepo/gitdepo/pull/51), [#53](https://github.com/InfiniteDepo/gitdepo/pull/53)) | Each linked group's member count, and which group each member comes from. |
| **Roles through groups** ([#54](https://github.com/InfiniteDepo/gitdepo/pull/54)) | A group can make its members site administrators or allow them to create organizations. The last site admin can't be removed. |
| **Auditor (read-all) role** ([#118](https://github.com/InfiniteDepo/gitdepo/pull/118)) | Members of an auditor group can read every repository and private organization, and nothing more. Writes are refused everywhere (web, API, git, SSH, LFS). Read-only access for security and compliance reviewers without admin rights. |
| **No organization creation by default** ([#44](https://github.com/InfiniteDepo/gitdepo/pull/44)) | New users can't create organizations unless an admin allows it. |
| **SAML 2.0 single sign-on** ([#590](https://github.com/InfiniteDepo/gitdepo/pull/590)) | SAML is a sign-in source next to LDAP and OAuth2 (Site administration → Authentication sources), with signed assertions, replay protection, group claims for user group sync, IdP-initiated sign-in when allowed, and single logout. |

## Credentials

| Feature | What it does |
|---|---|
| **Expiry for SSH keys, deploy keys and access tokens** ([#115](https://github.com/InfiniteDepo/gitdepo/pull/115)) | Expiry dates, required by default with a maximum of 365 days ([#459](https://github.com/InfiniteDepo/gitdepo/issues/459)). Expired credentials are refused everywhere. Admins can lower the maximum or turn a policy off: `[security] SSH_KEY_*`, `DEPLOY_KEY_*` and `ACCESS_TOKEN_*` with `_EXPIRY_REQUIRED` and `_MAX_LIFETIME_DAYS`. Turning a policy off needs both keys, `_EXPIRY_REQUIRED = false` and `_MAX_LIFETIME_DAYS = 0`: a maximum alone still requires an expiry date. |
| **Expiry for OAuth2 app secrets** ([#466](https://github.com/InfiniteDepo/gitdepo/pull/466)) | Client secrets expire; an expired secret is refused at the token endpoint. `[security] OAUTH2_APP_SECRET_EXPIRY_REQUIRED` and `OAUTH2_APP_SECRET_MAX_LIFETIME_DAYS` (default 365 days). Who may create OAuth2 apps is set under a policy form on Site administration → Applications ([#286](https://github.com/InfiniteDepo/gitdepo/pull/286)). |
| **Specific deploy keys in branch and tag protection** ([#50](https://github.com/InfiniteDepo/gitdepo/pull/50)) | Allow chosen deploy keys, not all of them, to push to protected branches and tags. Deploy-key pushes to protected tags are decided by the key, never by the repository owner's identity. |
| **Organization, project and repository access tokens** ([#28](https://github.com/InfiniteDepo/gitdepo/issues/28): [#585](https://github.com/InfiniteDepo/gitdepo/pull/585), [#587](https://github.com/InfiniteDepo/gitdepo/pull/587)) | Tokens owned by an organization, a project or a repository instead of a person, so automation keeps working when people leave. They act only on the repositories they cover, at the mode they were given, expire like personal tokens, can be rotated or revoked (a revoked token keeps its name in history and the audit log), and their owners are mailed before they expire. Managed in the settings of the repository, project or organization; API under `/repos/{owner}/{repo}/tokens`, `/orgs/{org}/tokens` and `/orgs/{org}/projects/{id}/tokens`. |

## Change control

| Feature | What it does |
|---|---|
| **Push rules** ([#116](https://github.com/InfiniteDepo/gitdepo/pull/116)) | Require commit message and branch name patterns, author emails that match the pusher, and maximum file sizes; block banned file names. |
| **Approval rules** ([#241](https://github.com/InfiniteDepo/gitdepo/pull/241), [#284](https://github.com/InfiniteDepo/gitdepo/pull/284)) | Protected branches require approvals from chosen users or teams, or from the code owners. Branch protection → Approval rules. |
| **Organization-wide branch protection** ([#247](https://github.com/InfiniteDepo/gitdepo/pull/247), [#254](https://github.com/InfiniteDepo/gitdepo/pull/254)) | Branch rules set once by an organization owner apply to every repository of the organization. Organization settings → Branches; API under `/orgs/{org}`. |
| **Delete and force-push allow-lists** ([#52](https://github.com/InfiniteDepo/gitdepo/pull/52)) | Protected branches can allow chosen users, teams or deploy keys to delete them or force-push; everyone else stays blocked. The default branch can never be deleted. |
| **Pull request title rules** ([#352](https://github.com/InfiniteDepo/gitdepo/pull/352)) | Regular-expression rules for pull request titles, enforced when the pull request is created or edited, or only at merge. Repository settings → Push rules. |
| **Attention set** ([#347](https://github.com/InfiniteDepo/gitdepo/pull/347)) | Shows on each pull request whose turn it is, and filters lists with `@me`. Always on. |
| **Merge queue** ([#31](https://github.com/InfiniteDepo/gitdepo/issues/31): [#593](https://github.com/InfiniteDepo/gitdepo/pull/593)) | Protected branches can require a merge queue: each pull request is tested on top of the branch and the ones ahead of it (Actions `merge_group` event), and exactly the tested commit is merged, alone or in groups. See [`docs/merge-queue.md`](merge-queue.md). |
| **Stacked pull requests** ([#158](https://github.com/InfiniteDepo/gitdepo/issues/158): [#592](https://github.com/InfiniteDepo/gitdepo/pull/592)) | A pull request based on another one's branch shows the whole stack with each one's review and check state, lists mark stacked pull requests, and "Merge stack" merges them in order. Also in the API. |
| **Branching model and merge forward** ([#22](https://github.com/InfiniteDepo/gitdepo/issues/22): [#571](https://github.com/InfiniteDepo/gitdepo/pull/571), [#573](https://github.com/InfiniteDepo/gitdepo/pull/573), [#576](https://github.com/InfiniteDepo/gitdepo/pull/576), [#577](https://github.com/InfiniteDepo/gitdepo/pull/577)) | Name the development branch and the release branches per repository or organization (an organization can lock it). A pull request merged into a release branch is merged forward into each later release branch and then the development branch; a conflict or a refused step opens a pull request for it and is noted in the timeline. "Don't merge forward" skips it where allowed. Repository or organization settings → Branching model. Turning a branch type off stops keeping the base branch it names (the other kept branches stay kept). |
| **Scheduled auto-merge** ([#110](https://github.com/InfiniteDepo/gitdepo/pull/110)) | Merge an approved pull request at a chosen time (e.g. after hours), tied to the reviewed commit so later pushes can't slip in unreviewed. |
| **Revert a merged pull request** ([#90](https://github.com/InfiniteDepo/gitdepo/pull/90), [#135](https://github.com/InfiniteDepo/gitdepo/pull/135)) | One button creates a pull request that reverts the merge, for every merge style. Both pull requests link to each other in the timeline. |
| **Generated release notes** ([#108](https://github.com/InfiniteDepo/gitdepo/pull/108)) | Draft release notes from the pull requests merged since the previous tag, grouped by label (`.forgejo/release.yml` or `.github/release.yml`). |
| **Organization and instance-wide templates** ([#99](https://github.com/InfiniteDepo/gitdepo/pull/99)) | Issue and pull request templates fall back to the organization's `.forgejo` repository, then to an instance repository (`[repository] DEFAULT_TEMPLATES_REPO`), so one checklist applies everywhere. |
| **Delete merged branches** ([#566](https://github.com/InfiniteDepo/gitdepo/pull/566)) | Lists the branches whose last commit is already in the default branch and deletes the ticked ones, for a repository, a project or a whole organization. Protected branches, the default branch and branches of open pull requests are never deleted. |

## Operations and administration

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
| **Limit on concurrent git operations** ([#578](https://github.com/InfiniteDepo/gitdepo/pull/578)) | Clones, fetches and pushes over HTTP and SSH wait for a free slot and are refused with 503 and `Retry-After` past a timeout, so web pages stay responsive under load. `[git] MAX_CONCURRENT_OPERATIONS` (default 4 × CPU cores) and `OPERATION_QUEUE_TIMEOUT`. See [`performance.md`](performance.md). |
| **Helm chart** ([#557](https://github.com/InfiniteDepo/gitdepo/pull/557)) | Install on Kubernetes with the chart in [`helm/gitdepo`](../helm/gitdepo). |

## Audit log

Records who did what and with which credential. See [`docs/audit-log.md`](audit-log.md).

| Feature | What it does |
|---|---|
| **Audit log, filters and export** ([#509](https://github.com/InfiniteDepo/gitdepo/pull/509), [#518](https://github.com/InfiniteDepo/gitdepo/pull/518), [#534](https://github.com/InfiniteDepo/gitdepo/pull/534)) | Site administration → Audit (admins and auditors), `GET /api/v1/admin/audit` and `admin audit export`, with filters by actor, action, target, credential and time. Always on. |
| **Sign-ins and credential activity** ([#520](https://github.com/InfiniteDepo/gitdepo/pull/520), [#533](https://github.com/InfiniteDepo/gitdepo/pull/533)) | Sign-ins, failures, credential use, refusals, API writes, pushes, downloads and uploads. `[audit] LOG_READS` also records reads of private repositories. |
| **Change records** ([#521](https://github.com/InfiniteDepo/gitdepo/pull/521), [#522](https://github.com/InfiniteDepo/gitdepo/pull/522), [#524](https://github.com/InfiniteDepo/gitdepo/pull/524), [#526](https://github.com/InfiniteDepo/gitdepo/pull/526), [#528](https://github.com/InfiniteDepo/gitdepo/pull/528), [#529](https://github.com/InfiniteDepo/gitdepo/pull/529), [#530](https://github.com/InfiniteDepo/gitdepo/pull/530), [#531](https://github.com/InfiniteDepo/gitdepo/pull/531)) | Accounts, keys, OAuth2 apps, runners, settings, organizations, teams, repositories, webhooks and mirrors record who changed what. |
| **Hash chain and retention** ([#535](https://github.com/InfiniteDepo/gitdepo/pull/535), [#537](https://github.com/InfiniteDepo/gitdepo/pull/537)) | Entries are sealed in a hash chain; `admin audit verify` checks it. Retention is set at Site administration → Audit → Retention. |
| **Metrics and volume projection** ([#572](https://github.com/InfiniteDepo/gitdepo/pull/572)) | Prometheus metrics for audit entries and write errors, the read-logging state and write errors on Site administration → Audit, and on the Retention page the log's size, daily growth, a projection per retention choice and a hint when retention is under 12 months. |

## Projects

Projects group repositories under an organization (`org/project/repo`).

| Feature | What it does |
|---|---|
| **Projects and paths** ([#434](https://github.com/InfiniteDepo/gitdepo/pull/434), [#436](https://github.com/InfiniteDepo/gitdepo/pull/436), [#438](https://github.com/InfiniteDepo/gitdepo/pull/438), [#439](https://github.com/InfiniteDepo/gitdepo/pull/439)) | Create, rename and delete projects at `/org/{org}/groups`; web, git over HTTP and SSH, and LFS work with the project path. Always on. |
| **Moves and redirects** ([#443](https://github.com/InfiniteDepo/gitdepo/pull/443)) | Move repositories into, out of and between projects; old paths redirect. Repository settings → Danger zone. |
| **Teams** ([#450](https://github.com/InfiniteDepo/gitdepo/pull/450)) | Link a team to a project to give it every repository in it. |
| **Branch rules, webhooks, secrets, variables and deploy keys** ([#452](https://github.com/InfiniteDepo/gitdepo/pull/452), [#453](https://github.com/InfiniteDepo/gitdepo/pull/453), [#454](https://github.com/InfiniteDepo/gitdepo/pull/454), [#456](https://github.com/InfiniteDepo/gitdepo/pull/456)) | Set once on the project and apply to all its repositories. Project settings. |
| **API** ([#442](https://github.com/InfiniteDepo/gitdepo/pull/442), [#469](https://github.com/InfiniteDepo/gitdepo/pull/469)) | `/orgs/{org}/projects` and its branch protection, hook, secret and variable endpoints; `/repositories/{id}`. |
| **URL forms** | Web, git, LFS and API paths of `org/project/repo`, redirects and what to update in tools that link to repositories: [`docs/projects.md`](projects.md). |
| **Projects elsewhere** ([#458](https://github.com/InfiniteDepo/gitdepo/pull/458), [#494](https://github.com/InfiniteDepo/gitdepo/pull/494), [#523](https://github.com/InfiniteDepo/gitdepo/pull/523)) | References, mail, packages, token repository pickers and migrations understand `owner/project/repo`. |

## Bitbucket Data Center import

| Feature | What it does |
|---|---|
| **`admin bitbucket-import`** ([#488](https://github.com/InfiniteDepo/gitdepo/pull/488), [#489](https://github.com/InfiniteDepo/gitdepo/pull/489), [#490](https://github.com/InfiniteDepo/gitdepo/pull/490)) | Imports projects and repositories into an organization, with pull requests, team and collaborator permissions, access keys, branch rules and webhooks. Reports what it cannot map. `admin bitbucket-import --server <url> --org <org>`, token from `--token-file` or `BITBUCKET_TOKEN`; `--skip-unmapped`, `--key-expiry` and a dry run. |
| **Origin on the repository** ([#487](https://github.com/InfiniteDepo/gitdepo/pull/487)) | The repository page shows the Bitbucket origin, and search finds `KEY/slug`. |

## Organization controls

| Feature | What it does |
|---|---|
| **Organization deploy keys** ([#428](https://github.com/InfiniteDepo/gitdepo/pull/428), [#429](https://github.com/InfiniteDepo/gitdepo/pull/429), [#430](https://github.com/InfiniteDepo/gitdepo/pull/430)) | One SSH deploy key for chosen repositories or all of an organization's. Organization settings → Deploy keys; `/api/v1/orgs/{org}/keys`. |
| **Required 2FA** ([#331](https://github.com/InfiniteDepo/gitdepo/pull/331), [#397](https://github.com/InfiniteDepo/gitdepo/pull/397)) | Members without two-factor authentication lose access to the organization's repositories; owners see who is missing. Organization settings → `require_two_factor`. |
| **Repository policies** ([#336](https://github.com/InfiniteDepo/gitdepo/pull/336), [#395](https://github.com/InfiniteDepo/gitdepo/pull/395)) | Owners restrict visibility changes and private forks; the site sets a minimum with `[repository] ORG_RESTRICT_VISIBILITY_CHANGE` and `ORG_PRIVATE_FORK_POLICY`. |
| **Verified domains** ([#356](https://github.com/InfiniteDepo/gitdepo/pull/356)) | Verify a domain with a DNS TXT record and require members to have a verified email domain. Organization settings → Verified domains. |
| **Repository units** ([#326](https://github.com/InfiniteDepo/gitdepo/pull/326)) | Owners switch units such as Issues or Packages off for the whole organization. |

## Actions

| Feature | What it does |
|---|---|
| **Job token permissions** ([#367](https://github.com/InfiniteDepo/gitdepo/pull/367), [#371](https://github.com/InfiniteDepo/gitdepo/pull/371), [#388](https://github.com/InfiniteDepo/gitdepo/pull/388)) | Workflow `permissions:` limit what the job token can do; the default is `[actions] DEFAULT_TOKEN_PERMISSIONS` or Settings → Actions → General. |
| **Scheduled runs** ([#391](https://github.com/InfiniteDepo/gitdepo/pull/391), [#396](https://github.com/InfiniteDepo/gitdepo/pull/396)) | "Run later" on a manual workflow, with a list of scheduled runs to cancel or retime. |
| **Run retention** ([#107](https://github.com/InfiniteDepo/gitdepo/pull/107), [#419](https://github.com/InfiniteDepo/gitdepo/pull/419), [#420](https://github.com/InfiniteDepo/gitdepo/pull/420), [#424](https://github.com/InfiniteDepo/gitdepo/pull/424)) | `[actions] RUN_RETENTION_DAYS` deletes old runs, keeping the latest run of each workflow; `RUN_RETENTION_MAX_DAYS` caps it; organizations and repositories can shorten it; "Keep this run" exempts a run; Settings → Actions → delete runs older than. |
| **Organization and instance run pages** ([#304](https://github.com/InfiniteDepo/gitdepo/pull/304), [#312](https://github.com/InfiniteDepo/gitdepo/pull/312), [#316](https://github.com/InfiniteDepo/gitdepo/pull/316)) | Runs, queue and failure overview per organization (`/org/{org}/actions`) and for the whole instance (Site administration → Actions), with a usage CSV export. |
| **Restrict who registers runners** ([#106](https://github.com/InfiniteDepo/gitdepo/pull/106)) | `[actions] RUNNER_REGISTRATION = admin`, `admin_and_org_owners` or `everyone`. |

## Security scanning

| Feature | What it does |
|---|---|
| **Dependency graph and SBOM** ([#150](https://github.com/InfiniteDepo/gitdepo/issues/150): [#598](https://github.com/InfiniteDepo/gitdepo/pull/598)) | Reads the dependencies of each repository from its manifests and lock files (npm, Yarn, pnpm, Go, Python, Maven, NuGet, Cargo, Bundler, Composer) without running anything, shows them on a Dependencies page and exports an SBOM (SPDX 2.3 or CycloneDX 1.6). `[dependency_graph] ENABLED`, or Site administration → Configuration → Dependency graph; organizations and repositories can turn it off. |
| **Vulnerability alerts** ([#604](https://github.com/InfiniteDepo/gitdepo/pull/604), [#611](https://github.com/InfiniteDepo/gitdepo/pull/611)) | Matches the stored dependencies against a local copy of the OSV database (downloaded from `OSV_MIRROR_URL`, which can be an internal mirror such as Artifactory), so nothing is looked up per request. |
| **Organization and instance dependency search** ([#606](https://github.com/InfiniteDepo/gitdepo/pull/606), [#607](https://github.com/InfiniteDepo/gitdepo/pull/607), [#608](https://github.com/InfiniteDepo/gitdepo/pull/608)) | Find every repository that uses a package or is affected by an advisory, from the organization's Security tab, Site administration or the API, with CSV and JSON export. |
| **Secret scanning** ([#149](https://github.com/InfiniteDepo/gitdepo/issues/149): [#610](https://github.com/InfiniteDepo/gitdepo/pull/610), [#612](https://github.com/InfiniteDepo/gitdepo/pull/612), [#613](https://github.com/InfiniteDepo/gitdepo/pull/613), [#614](https://github.com/InfiniteDepo/gitdepo/pull/614), [#615](https://github.com/InfiniteDepo/gitdepo/pull/615), [#616](https://github.com/InfiniteDepo/gitdepo/pull/616), [#617](https://github.com/InfiniteDepo/gitdepo/pull/617)) | Scans the whole history of every repository and wiki for leaked secrets (cloud keys, tokens, private keys and more), then each push, and optionally issue, pull request and comment text. Alerts store a fingerprint and the place, never the secret. Alert pages and API per repository, lists per organization and instance, custom patterns for the site or an organization, a mail digest after a push, and redaction of secrets found in text. `[secret_scanning] ENABLED`, or Site administration; organizations and repositories can turn it off. |

## Search

| Feature | What it does |
|---|---|
| **zoekt code search** ([#270](https://github.com/InfiniteDepo/gitdepo/pull/270), [#280](https://github.com/InfiniteDepo/gitdepo/pull/280), [#353](https://github.com/InfiniteDepo/gitdepo/pull/353)) | Exact and regular-expression search over several branches. `[indexer] REPO_INDEXER_TYPE = zoekt`. |

## Interface

| Feature | What it does |
|---|---|
| **Company design tokens and themes** ([#104](https://github.com/InfiniteDepo/gitdepo/pull/104)) | Light, dark, auto and high-contrast themes built on design tokens, with WCAG contrast checked in tests. Enable them with `[ui] THEMES` and `DEFAULT_THEME`. |
| **draw.io diagrams** ([#103](https://github.com/InfiniteDepo/gitdepo/pull/103)) | `.drawio` files render in the file view, sandboxed, with no requests outside the instance. `[markup] DRAWIO_ENABLED` turns it off. |
| **Search engines and AI assistants** ([#574](https://github.com/InfiniteDepo/gitdepo/pull/574)) | Canonical URLs, structured data (JSON-LD) for public repositories and profiles, public organizations in the sitemap, and `llms.txt`. See [`search-engines.md`](search-engines.md). |
| **Web IDE** ([#24](https://github.com/InfiniteDepo/gitdepo/issues/24): [#579](https://github.com/InfiniteDepo/gitdepo/pull/579)) | VS Code in the browser: press `.` on a file, folder or pull request, edit, rename and delete files, and commit them in one commit to the branch or to a new branch with a pull request. Protected branches, push rules and quota apply as for any push. Its files are served from disk, not from the binary; `[ide] ENABLED` turns it off. See [`docs/web-ide.md`](web-ide.md). |

## Development and quality

- CI on every pull request runs the lints, frontend checks, unit, migration, integration and end-to-end tests ([#11](https://github.com/InfiniteDepo/gitdepo/pull/11), [#36](https://github.com/InfiniteDepo/gitdepo/pull/36), [#27](https://github.com/InfiniteDepo/gitdepo/pull/27), [#146](https://github.com/InfiniteDepo/gitdepo/pull/146)).
- Fix for a cancellation race in git attribute checks ([#42](https://github.com/InfiniteDepo/gitdepo/pull/42)).

Many features are **off or unchanged by default** and are switched on in `app.ini`; the audit log, projects and similar features are always on and need no setting.
