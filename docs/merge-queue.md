# Merge queue

A merge queue keeps a busy branch green: instead of merging a pull request that was only tested against an older
state of the branch, gitdepo tests each pull request on top of the branch and the pull requests ahead of it, and merges
exactly the commit it tested. It works like the merge queues of GitHub and GitLab's merge trains.

## Turning it on

Branch protection (repository, project or organization rule) → **Merge queue** → **Require a merge queue**. The API
takes the same fields on `/repos/{owner}/{repo}/branch_protections` (and the project and organization rule
endpoints): `require_merge_queue`, `merge_queue_merge_style`, `merge_queue_build_concurrency`,
`merge_queue_min_group_size`, `merge_queue_max_group_size`, `merge_queue_wait_minutes`,
`merge_queue_check_timeout_minutes`. A value of 0 means the default.

| Setting | Default | What it does |
|---|---|---|
| Merge method | the one chosen when adding | Merge, rebase, rebase-merge or squash. Fast-forward only can't be combined with other pull requests, and manual merges are not offered. |
| Pull requests tested at a time | 5 | How many queue entries have a test commit at once (1 to 100). |
| Check time-out | 60 minutes | An entry whose required checks don't finish in time leaves the queue (1 to 1440). |
| Minimum group size | 1 | Wait for this many passed entries before merging (at most the maximum group size and the number tested at a time)… |
| …but at most | 5 minutes | …counted from when the first entry joined the queue. |
| Maximum group size | 5 | How many passed entries merge in one push. |

While the queue is required, nobody merges into the branch outside it, site and repository administrators included:
the merge button becomes **Add to merge queue**, the merge API answers 405, and "merge when checks succeed" joins the
queue once the pull request's own checks pass. Direct pushes still follow the rule's push settings. Blocking merges of
outdated branches is skipped, since the queue always tests on the latest branch.

## How a pull request goes through

1. **Add.** Anyone who may merge the pull request adds it from the merge box or with
   `POST /repos/{owner}/{repo}/pulls/{index}/merge-queue` (body as for the merge API; the merge message is the title
   and description of the pull request). The pull request must be mergeable as usual: approvals, its own required
   checks, no conflicts, not a work in progress.
2. **Test.** The queue builds a test commit of the branch plus every entry ahead plus this one, pushes it to
   `merge-queue/<branch>/<id>` and asks for checks: Actions workflows run on the `merge_group` event
   (`on: merge_group`), and webhooks with the "Merge group" event get a `checks_requested` payload. When the test
   commit holds a pull request from a fork, the run is treated like that fork's pull request: no secrets, a
   read-only token, and the base branch's workflows unless the fork's author is trusted with Actions.
3. **Merge.** When the required status checks pass on the test commit and every entry ahead of it has merged or
   passed, the branch is moved to that test commit with a normal, non-forced push through the hooks. A passed entry
   merges every passed entry ahead of it in one push, up to the maximum group size. "Skip merge forward" and "delete
   the branch after merging" are kept from when the entry was added.
4. **Leave.** An entry leaves the queue, with a timeline comment saying why, when its checks fail or time out, new
   commits are pushed to it, it is closed or retargeted, it conflicts with the entries ahead, it changes nothing on top
   of them (the same change is ahead of it), its test commit can't be built (its fork is gone, say), the user who added it may
   no longer merge it, it becomes blocked or a work in progress, the queue is turned off, or someone removes it. The
   entries behind it are tested again without it.

A push to the branch outside the queue (allowed by the push settings) rebuilds every entry on the new branch.

## Required checks

The required status checks must pass on the test commit, and only statuses reported after the test commit was
pushed count: with rebase onto an up-to-date branch the test commit is the head commit of the pull request, and its
pull request checks don't stand in for the queue's. An Actions job reports its status as
`workflow / job (merge_group)` there, and `workflow / job (pull_request)` on the pull request, so a check that must
pass on both needs a pattern such as `ci / test (*)`.

## Who may remove an entry

The user who added it, the author of the pull request, and anyone who may merge it: from the merge box, or
`DELETE /repos/{owner}/{repo}/pulls/{index}/merge-queue`. An entry that is being merged can't be removed any more (the
API answers 409).

## Seeing the queue

The merge box of a queued pull request shows its position, its state (waiting, testing, passed) and its test commit.
`/{owner}/{repo}/merge-queue/{branch}` lists the whole queue (linked from the merge box and the Branches page);
`GET /repos/{owner}/{repo}/merge-queue/{branch}` returns it. Repositories in a project use their own path, as
everywhere (see [`projects.md`](projects.md)).

## Notes for administrators

- `merge-queue/` branches are written only by the queue: pushes, renames and deletes of them are refused, and the
  queue deletes them once an entry leaves or merges. The cron task "Delete merge queue build branches that belong to no
  pull request in the queue" (daily) removes any left behind, for example after a server stopped mid-build.
- The cron task "Look at every merge queue" (every minute) handles check time-outs and group wait times; status
  updates and pushes trigger the queue at once. Several servers can run it at the same time.
- Merge forward carries a queued merge on to the next release branches like any other merge, and "Update branch"
  still works on a head branch: neither goes through a queue the target branch may require. This is a known gap: a
  release branch that merge forward writes to is not protected by its own queue.
- A merge whose push went through but whose hook never recorded it (a server that stopped mid-merge) is recorded by
  the queue ten minutes later.
- A merge by the queue shows in the timeline and feeds like any other merge, by the user who added the entry.
