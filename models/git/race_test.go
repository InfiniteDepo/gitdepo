// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build race

package git_test

// slowdown scales the time bounds of tests: the race detector makes code
// about ten times slower.
const slowdown = 10
