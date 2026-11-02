// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build race

package dependency

// raceEnabled: the race detector slows a parse down by an order of magnitude, so time bounds are looser.
const raceEnabled = true
