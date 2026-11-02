// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/modules/json"
)

const (
	// maxSettingValue is the most bytes of a value recorded as it is; a longer one is recorded as its hash
	maxSettingValue = 2048
	// maxSettingValues is the most bytes of values one entry records, so that it stays below the data cap
	maxSettingValues = 24 * 1024
)

// selfAuditedKeys are written by code that records its own entry for them (log shipping records each destination
// without its keys, the dependency graph settings without the mirror token), so SetSettings leaves them out of its entry.
var selfAuditedKeys = []string{"log_shipping.destinations", "dependency_graph.config"}

// recordSettings records admin.setting.changed for the keys whose value differs from before (the stored values,
// absent = not stored yet), and nothing when none does. The values of the keys listed in audit_model.Fields["setting"]
// are recorded as they are (parsed, as each is stored as JSON); any other key is recorded as the sha256 of its values, never the value. A future dynamic
// setting that holds a secret must be left out here (like selfAuditedKeys), not hashed.
func recordSettings(ctx context.Context, before, after map[string]string) error {
	keys := make([]string, 0, len(after))
	for k, v := range after {
		if old, ok := before[k]; (!ok || old != v) && !slices.Contains(selfAuditedKeys, k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	b, a, hashed := map[string]any{}, map[string]any{}, map[string]any{}
	data := map[string]any{"keys": keys}
	budget := maxSettingValues
	for _, k := range keys {
		old, had := before[k]
		had = had && old != "" // an empty row is one created to be locked (EnsureSetting): not stored yet
		v := after[k]
		if slices.Contains(audit_model.Fields["setting"], k) && len(v) <= maxSettingValue && len(old) <= maxSettingValue && len(v)+len(old) <= budget {
			var oldValue, value any
			if json.Unmarshal([]byte(v), &value) == nil && (!had || json.Unmarshal([]byte(old), &oldValue) == nil) {
				budget -= len(v) + len(old)
				b[k], a[k] = oldValue, value
				continue
			}
		}
		if slices.Contains(audit_model.Fields["setting"], k) {
			data["truncated"] = true // a value that would have been recorded is cut to its hash (too long, or over the budget)
		}
		h := map[string]any{"after": sha256Hex(v)}
		if had {
			h["before"] = sha256Hex(old)
		}
		hashed[k] = h
	}
	if len(a) > 0 {
		data["before"], data["after"] = b, a
	}
	if len(hashed) > 0 {
		data["hashed"] = hashed
	}
	return audit_model.Record(ctx, audit_model.Event{
		Action: "admin.setting.changed", Result: audit_model.ResultSuccess, TargetType: "setting", Data: data,
	})
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
