// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package swagger

import (
	api "forgejo.org/modules/structs"
)

// TrashItemList
// swagger:response TrashItemList
type swaggerResponseTrashItemList struct {
	// in:body
	Body []api.TrashItem `json:"body"`

	// The total number of items in the trash
	TotalCount int64 `json:"X-Total-Count"`
}
