// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package structs

// CodeSearchResult is a file the code search found
type CodeSearchResult struct {
	// the path of the file
	Filename string `json:"filename"`
	// the branch the file was found on
	Branch string `json:"branch"`
	// the commit of the indexed file
	CommitID string `json:"commit_id"`
	// the language of the file
	Language string `json:"language"`
	// the numbers of the lines shown for the match
	LineNumbers []int `json:"line_numbers"`
}
