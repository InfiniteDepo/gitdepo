// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package logshipping

import (
	"context"
	"maps"
	"slices"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/modules/setting"
)

// destinationFields are the audited fields of a destination: never its key or header values, and of its endpoint
// only the scheme and host.
func destinationFields(d setting.LogShippingDestination) map[string]any {
	names := make([]string, 0, len(d.Headers))
	for _, h := range d.Headers {
		names = append(names, h.Name)
	}
	return map[string]any{
		"id": d.ID, "name": d.Name, "type": d.Type, "endpoint": audit_model.Origin(d.Endpoint), "log_types": slices.Clone(d.LogTypes),
		"enabled": d.Enabled, "level": d.Level, "ndjson": d.NDJSON, "header_names": names,
	}
}

// destinationChanges is the data of an edit from old to d, nil when nothing audited changed. A new key or header
// value, and a new filter, are recorded only as changed.
func destinationChanges(old, d setting.LogShippingDestination) map[string]any {
	data := audit_model.Changes(destinationFields(old), destinationFields(d))
	flags := map[string]bool{
		"key_changed":     old.KeyEnc != d.KeyEnc,
		"headers_changed": !slices.Equal(old.Headers, d.Headers),
		"filter_changed":  old.Expression != d.Expression || old.Exclusion != d.Exclusion,
	}
	for k, v := range flags {
		if v {
			if data == nil {
				data = map[string]any{}
			}
			data[k] = true
		}
	}
	return data
}

func recordDestination(ctx context.Context, action string, d setting.LogShippingDestination, data map[string]any) error {
	fields := destinationFields(d)
	maps.Copy(fields, data)
	return audit_model.Record(ctx, audit_model.Event{
		Action: action, Result: audit_model.ResultSuccess, TargetType: "log_shipping", TargetName: d.Name, Data: fields,
	})
}
