#!/usr/bin/env bash
# Copyright 2026 The gitdepo contributors. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Fails when a commit of a pull request lacks a Signed-off-by line (see
# CONTRIBUTING.md). Checks the commits of HEAD that are not in the base
# branch, merge commits excluded, so a merge of develop into the branch
# never counts.
#
# Usage: tools/check-dco.sh [BASE_REF]   (default origin/develop)
#
# Until the go-public date is set in DCO_START (an ISO date, e.g. 2026-11-01),
# the check only reports and exits 0. Once set, commits made before that date
# are ignored and the rest must be signed off. The environment can override it.
set -euo pipefail

: "${DCO_START=}"
base=${1:-origin/develop}

since=0
if [ -n "$DCO_START" ]; then
  since=$(date -d "$DCO_START" +%s 2>/dev/null) || {
    echo "DCO_START must be a date such as 2026-11-01, got: $DCO_START" >&2
    exit 2
  }
fi

missing=0
while read -r sha; do
  [ -n "$sha" ] || continue
  [ "$(git log -1 --format=%ct "$sha")" -ge "$since" ] || continue
  # read the raw commit: %B would stop at a NUL byte
  if ! git cat-file commit "$sha" | grep -Eq '^Signed-off-by: .+ <.+>$'; then
    echo "No Signed-off-by: $(git log -1 --format='%h %s' "$sha")"
    missing=$((missing + 1))
  fi
done < <(git rev-list --no-merges HEAD --not "$base")

if [ "$missing" -gt 0 ]; then
  echo "$missing commit(s) lack a Signed-off-by line. Add it with: git commit -s --amend (or git rebase --signoff)"
  [ -n "$DCO_START" ] && exit 1
  echo "DCO_START is not set: reporting only."
fi
