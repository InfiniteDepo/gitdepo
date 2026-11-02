# Audit log

**Site administration > Security > Audit log** (`/admin/audit`) lists the audit log of the whole instance, newest
first. Site administrators who can sign in read it, and so do auditors (the auditor role of a user group) with their
own session or access token; OAuth2 apps and authorized integrations can't use the auditor's access.

## Filters

The page, `GET /api/v1/admin/audit` and `gitdepo admin audit export` take the same parameters, so a page URL is a
link to the same evidence in the API. All filters combine with AND.

| Parameter | Selects |
|---|---|
| `category` | `changes` (default), `signins`, `activity`, `all`, or a comma-separated list of categories |
| `org` | entries that happened in the organization, its projects and repositories (name or ID) |
| `project` | entries in the project (ID; with `org`, it must be a project of that organization) |
| `repo` | the repository's whole history, across transfers and moves (`owner/[project/]name` or ID) |
| `user` | what the user did, also as the admin behind a sudo, and what was done to their account (login or ID) |
| `credential_type`, `credential`, `credential_owner` | by credential type (comma-separated), one credential (`type:id`), or the user or organization owning it |
| `action`, `result`, `ip`, `request_id` | an action key or a prefix (`credential.*`), `success`/`failure`/`refused`, the client IP, one request |
| `since`, `before` | a time range in RFC 3339 |
| `target_type`, `target_id` | the object an entry is about |
| `before_id`, `after_id` | paging: older or newer entries than this ID |

Names are looked up as they are now, so a renamed or trashed object isn't found by its name. A value of only digits is
always read as an ID, never as a name, and is used as it is, so entries of deleted and trashed objects stay reachable;
for a user or organization whose name is all digits, give its ID. The "Audit log" links on the admin user page and the
admin organization and repository lists fill the filter in for you (users and organizations by ID, repositories by
full name). The page shows what each filter resolved to, and its links use IDs. An unknown name is an error, never an empty list.

## Export

`?format=csv` or `?format=json` on the page or the API exports every matching entry, oldest first, with every column.
CSV cells that a spreadsheet would run as a formula start with `'`. Each export is itself recorded (`audit.exported`,
with the filter), and its response carries a manifest:

- `X-Audit-Filter`, `X-Audit-Generated-At`, `X-Audit-Truncated`;
- when the export stopped at 100,000 rows, `X-Audit-Exported-Through` and a `Link: <…>; rel="next"` with the same
  filter plus `since` and `after_id`, which continues it.

`gitdepo admin audit export --since … --until … [filters] --format csv|json [--output FILE]` has no row limit, writes
the same rows as the web export for the same filter, and prints the manifest to stderr. `--output` creates a new file
with mode 0600.

Exports use the heavy rate limit class; the page and the API list use the normal one. Both work in read-only
maintenance mode, and recording continues.

Viewing the page or listing entries through the API isn't recorded yet; that comes with read logging.

## Shipping to a log service

Site administration → Log shipping can send the audit log to New Relic, any HTTPS collector or Grafana Loki: tick the
**Audit log** type of a destination. "All" doesn't include it, because entries carry IP addresses and user agents.
Every entry is sent whatever the destination's minimum level or filters are. The sealer ships each row once, right
after it is committed, as one JSON event: the message is the action key, `seq` and `hash` tie it to the chain, and
`data` is one JSON string (redacted like every shipped field, cut at 2 KB). With Loki, the labels are
`service="gitdepo"`, `logtype="audit"` and `level` (`info` for a success, `warn` otherwise); put the tenant or
authorisation in a custom header. The audit page shows how many destinations this instance streams to.

Shipping is best effort; the database is the source of truth. The receiver can find a gap from `seq` and `hash`.
The shipped copy can't be re-hashed: `data` is redacted and cut at 2 KB, and names may be redacted, so a hash
verifies only against the database. A receiver checks continuity instead: `seq` rises by one, and each event's
`prev_hash` is the `hash` of the one before.

Known gaps:

- A pod ships nothing before its first reload of the destinations (up to 30 s after start).
- Rows sealed after a destination is removed or disabled don't reach it, and nothing is re-sent later.
- The buffer (up to 5 s of events, or what a down destination hasn't taken yet) is lost on a hard kill.
- Loki may reject samples that are too old after a long outage; the shipper drops what it can't deliver.
- The org, project and repository names are looked up when the row is shipped; one deleted since then shows an empty
  name, and the ids stay.

## Retention and volume

**Site administration → Security → Audit log → change** (`/admin/audit/retention`) sets how long entries are kept,
from 30 days to 20 years (default 1 year). A longer value applies at once, a shorter one after 7 days. A value under
1 year shows a reminder that SOC 2 and ISO 27001 audits usually need 12 months of evidence. The page shows how many
entries the log holds and how many it gained a day over the last 30 days, and next to each choice how many entries
(and roughly how much storage, at 1.5 KiB per entry) the log would hold at that rate.

## Metrics

With `[metrics] ENABLED`, `/metrics` has two counters per process: `gitea_audit_events_total{category}` (entries
written whose change committed) and `gitea_audit_write_errors_total` (activity entries that could not be written,
such as a sign-in or a push recorded after the fact). A write error is also shown on the audit page, with the count
since the server started; the server log has the error. A failed write of a change entry fails the change itself.
