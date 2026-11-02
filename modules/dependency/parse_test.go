// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import "context"

// ParseLimited is ParseFull without the Info.
func (f *Format) ParseLimited(ctx context.Context, data []byte, find Finder, maxRows int) ([]Dependency, error) {
	r, err := f.ParseFull(ctx, data, find, maxRows)
	if err != nil {
		return nil, err
	}
	return r.Deps, nil
}

// Parse is ParseLimited with DefaultMaxDependencies.
func (f *Format) Parse(ctx context.Context, data []byte, find Finder) ([]Dependency, error) {
	return f.ParseLimited(ctx, data, find, DefaultMaxDependencies)
}
