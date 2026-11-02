# URLs of repositories in projects

A repository in a project has three path segments, `org/project/repo`, where a repository outside a project has two, `org/repo`. This page lists the forms for the web, git, LFS, the API and redirects, and what to update in tools that build repository URLs from `owner/repo`. The examples use `gitdepo.example.com`, the organization `acme`, the project `payments` and the repository `ledger`.

A project has one level: a project holds repositories, and projects don't nest.

## Names

- Project and repository names may use letters, digits, `-`, `_` and `.`.
- `.`, `..`, `-` and names ending in `.git`, `.wiki`, `.rss` or `.atom` are reserved.
- A project and a repository directly under the organization can't share a name.
- Avoid repository names that equal a page name (`issues`, `raw`, `releases`). To address such a repository without doubt, use the ID forms below.

## Web

| What | URL |
|---|---|
| Repository | `https://gitdepo.example.com/acme/payments/ledger` |
| A page | `https://gitdepo.example.com/acme/payments/ledger/issues` |
| The same page with the separator | `https://gitdepo.example.com/acme/payments/ledger/-/issues` |
| The project | `https://gitdepo.example.com/acme/payments` |
| Project settings | `https://gitdepo.example.com/acme/payments/-/settings` |

- The `/-/` separator is optional for pages: both page forms above work, for repositories in projects and for those outside.
- Raw files, archives, release downloads and attachments also work at `…/ledger/-/raw/…` style paths. Use these when a token must authenticate the download.
- A repository you can't see answers like one that doesn't exist (404).
- Don't build URLs with `@<id>` segments; they are internal and refused.

## Git over HTTP and SSH, and LFS

| What | URL |
|---|---|
| Clone over HTTPS | `https://gitdepo.example.com/acme/payments/ledger.git` |
| Clone over SSH, port 22 | `git@gitdepo.example.com:acme/payments/ledger.git` |
| Clone over SSH, other port | `ssh://git@gitdepo.example.com:2222/acme/payments/ledger.git` |
| Wiki | the repository URL with `.wiki` before `.git` |
| LFS | the HTTPS clone URL is enough; the LFS endpoint is `…/ledger.git/info/lfs` |
| Go modules | `…/ledger?go-get=1` answers for `gitdepo.example.com/acme/payments/ledger` |

- There is no `/-/` form for git. Use the `.git` URL the repository page shows.
- LFS takes access tokens as the password of HTTP Basic authentication.
- Pushing to a repository that doesn't exist doesn't create it in a project.
- `go-get` names the full project path only to a viewer who can see the repository; anyone else gets the answer for `acme/payments` only.

## API

Every repository endpoint exists in three forms:

| Form | Example |
|---|---|
| Owner and name (repositories outside a project) | `/api/v1/repos/acme/ledger/issues` |
| Project form | `/api/v1/repos/acme/payments/ledger/-/issues` |
| ID | `/api/v1/repositories/42/issues` |

- The project form needs `/-/` between the repository and the rest of the path.
- The ID form works for every repository and doesn't change when the repository is renamed or moved. Store it in integrations that must outlive a move.
- A project or ID that doesn't exist, or that the token can't see, answers a plain 404.
- A repository in a project reports `full_name` as `acme/payments/ledger`, and a `project` object with `id`, `name`, `full_name` and `html_url`. `url`, `html_url`, `clone_url` and `ssh_url` already contain the project path. `url` ends in `/-`.
- `/api/v1/orgs/acme/projects` manages projects; each project also has `branch_protections`, `hooks`, `actions/secrets` and `actions/variables` endpoints.
- Endpoints that take a repository in the body (migration, token repository selection) accept a `project` name next to the repository name; it needs a token for the whole organization.

## Redirects

When a repository is renamed, moved into, out of or between projects, or a project is renamed, the old path keeps working as a redirect:

- Web pages answer 301 to the new path and keep the rest of the path and the query. Only `GET` and `HEAD` are redirected.
- git over HTTP answers 301 too. git doesn't follow a 301 after it was asked for credentials, so cloning a private repository from its old URL fails; update the remote with `git remote set-url origin <new url>`.
- SSH doesn't follow redirects; run `git remote set-url`.
- In the API only the old owner/name form redirects (to the project form). The project form and the ID form don't: after a rename, the old project-form URL answers 404.
- A redirect is followed only for someone who may see the new location.
- The old name stays taken in the organization until an owner removes the redirect at *Organization settings → Redirects*.

## Coming from Bitbucket Data Center or GitLab

`admin bitbucket-import --server <url> --org <org> --doer <admin>` imports the projects and repositories of a Bitbucket Data Center server into an organization (token from `--token-file` or `BITBUCKET_TOKEN`; `--dry-run` shows the plan, `--skip-unmapped`, `--key-expiry` and `--csv` are described by `--help`). Each imported repository:

- shows **Migrated from Bitbucket** and the old `KEY/slug` in its header, linked to the old browse page when the server URL is plain http(s);
- shows a banner on its home page, "This repository moved here from Bitbucket", with a `git remote set-url origin <url>` command for each enabled clone protocol and a copy button. Dismissing it is remembered in that browser for 90 days;
- is found by repository search for `KEY/slug` or the old clone or browse URL.

Run the command from the banner in each existing clone.

### Tools that link to repositories

gitdepo states what it produces; how another tool reads it is not verified here. Test each on a staging instance before you cut over.

| Tool | What to check or update |
|---|---|
| Jira development links and DVCS | repository URLs and `full_name` now have three segments; untested, test on a staging instance |
| Renovate | repository identifiers in its configuration; the ID API form or the project API form avoids splitting `owner/repo`; untested, test on a staging instance |
| IDE plugins | the remote URL (`git remote set-url`) and any `owner/repo` setting; untested, test on a staging instance |
| Jenkins | job sources and webhook URLs that name `owner/repo`; untested, test on a staging instance |
| Webhook consumers | payloads carry `repository.full_name` with three segments and `html_url`, `clone_url` and `ssh_url` with the project path; code that splits `full_name` on one `/` needs to change; test on a staging instance |

## Not covered yet

Reusable workflow references (`uses: org/repo/...`) find only repositories outside projects.
