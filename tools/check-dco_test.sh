#!/usr/bin/env bash
# Copyright 2026 The gitdepo contributors. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Self-test of check-dco.sh on a throwaway repository.
set -euo pipefail

script=$(cd "$(dirname "$0")" && pwd)/check-dco.sh
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$dir"
git init -q -b develop .
git config user.name Tester
git config user.email tester@example.com
git config commit.gpgsign false

commit() { echo "$1" > "f-$RANDOM"; git add -A; git commit -q "${@:2}" -m "$1"; }
# run the check in a subshell, return its exit code and keep the output in $out
check() { out=$(env "$@" "$script" develop 2>&1) && rc=0 || rc=$?; }
expect() { # name expected-rc
  [ "$rc" -eq "$2" ] || { echo "FAIL $1: exit $rc, wanted $2"; echo "$out"; exit 1; }
  echo "ok $1"
}

commit "unsigned base commit on develop"

git checkout -q -b signed
commit "signed" -s
check DCO_START=1970-01-01; expect "signed commit passes" 0

git checkout -q -b unsigned
commit "unsigned"
check DCO_START=1970-01-01; expect "unsigned commit fails" 1
grep -q "unsigned" <<< "$out" || { echo "FAIL: failing commit not named"; exit 1; }
check DCO_START=; expect "unset DCO_START only reports" 0
grep -q "reporting only" <<< "$out" || { echo "FAIL: no report line"; exit 1; }
check DCO_START=2999-01-01; expect "commits before DCO_START are ignored" 0

# develop moves on and is merged into the branch: its unsigned commits don't count
git checkout -q signed
git checkout -q develop
commit "develop moved on"
git checkout -q signed
git merge -q --no-edit develop
check DCO_START=1970-01-01; expect "merge of develop is not counted" 0

# a trailer-like line that is not a trailer line is no sign-off
git checkout -q -b fake
commit "fake" -m "Signed-off-by: not a real trailer"
check DCO_START=1970-01-01; expect "malformed sign-off fails" 1
# a NUL byte in the message must not hide the sign-off (git log %B stops at it);
# git commit refuses such a message, so write the commit object by hand
git checkout -q -b nul develop
nul_commit() { # printf format of the message
  {
    printf 'tree %s\nparent %s\n' "$(git write-tree)" "$(git rev-parse HEAD)"
    printf 'author Tester <tester@example.com> 1700000000 +0000\n'
    printf 'committer Tester <tester@example.com> 1700000000 +0000\n\n'
    printf "$1"
  } | git hash-object -t commit -w --stdin --literally
}
git reset -q --soft "$(nul_commit 'nul before\n\n\0\n\nSigned-off-by: Tester <tester@example.com>\n')"
check DCO_START=1970-01-01; expect "sign-off after a NUL byte is found" 0
git reset -q --soft "$(nul_commit 'nul without sign-off\n\n\0\n\nmore text\n')"
check DCO_START=1970-01-01; expect "NUL byte without sign-off fails" 1

# the go-public date: an unsigned commit made before it is ignored, one made from that day is checked
git checkout -q -b dates develop
GIT_COMMITTER_DATE=2026-10-18T23:59:59Z commit "unsigned before the date"
check TZ=UTC DCO_START=2026-10-19; expect "unsigned commit before the date is ignored" 0
GIT_COMMITTER_DATE=2026-10-19T00:00:00Z commit "unsigned on the date"
check TZ=UTC DCO_START=2026-10-19; expect "unsigned commit from the date is checked" 1

check DCO_START=not-a-date; expect "bad DCO_START is refused" 2
grep -q "DCO_START must be a date" <<< "$out" || { echo "FAIL: no clear message"; echo "$out"; exit 1; }
echo "all ok"
