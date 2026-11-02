// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// Project groups repositories of an organization: `org/project/repo`
// swagger:model
type Project struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	HTMLURL     string `json:"html_url"`
	// swagger:strfmt date-time
	Created time.Time `json:"created_at"`
	// swagger:strfmt date-time
	Updated time.Time `json:"updated_at"`
}

// ProjectMeta is the project of a repository
type ProjectMeta struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
}

// CreateProjectOption options for creating a project
type CreateProjectOption struct {
	// required: true
	Name        string `json:"name" binding:"Required"`
	Description string `json:"description"`
}

// EditProjectOption options for editing a project; only the fields that are set change
type EditProjectOption struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}
