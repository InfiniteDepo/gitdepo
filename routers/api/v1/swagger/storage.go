// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package swagger

import (
	api "forgejo.org/modules/structs"
)

// StorageSummary
// swagger:response StorageSummary
type swaggerResponseStorageSummary struct {
	// in:body
	Body api.StorageSummary `json:"body"`
}

// OwnerStorageList
// swagger:response OwnerStorageList
type swaggerResponseOwnerStorageList struct {
	// in:body
	Body []api.OwnerStorage `json:"body"`

	// The total number of owners
	TotalCount int64 `json:"X-Total-Count"`
}
