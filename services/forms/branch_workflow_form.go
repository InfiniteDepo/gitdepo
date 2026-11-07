// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forms

import (
	"net/http"
	"strconv"
	"strings"

	repo_model "forgejo.org/models/repo"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/web/middleware"
	"forgejo.org/services/context"

	"code.forgejo.org/go-chi/binding"
)

// BranchWorkflowForm is the form of the organization and repository branch workflow pages.
type BranchWorkflowForm struct {
	DeleteAfterMerge string `binding:"Required;In(inherit,off,default-on,always)"`
	Enforce          bool   // organizations only
}

// Validate validates the fields
func (f *BranchWorkflowForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}

// BranchingModelForm is the branching model section of the organization and repository branch workflow pages.
type BranchingModelForm struct {
	Inherit                   bool // repositories of organizations only
	DevelopmentBranch         string
	ProductionBranch          string
	ReleasePrefixes           string // separated by commas
	MergeForward              bool
	MergeForwardNeverBypass   bool
	MergeForwardAnyoneMaySkip bool
	DefaultPRTarget           string
	// the branch types besides Release, one entry per table row; TypeOn holds the indexes of the rows that are on
	TypeName     []string
	TypePrefix   []string
	TypeBase     []string
	TypeBranch   []string
	TypeOn       []string
	EnforceModel bool // organizations only
	// the names of new branches: one exception pattern per line, user and team names separated by commas or lines
	RequireBranchType bool
	BranchExceptions  string
	ExemptUsers       string
	ExemptTeams       string
}

// Naming returns the naming fields of the form.
func (f *BranchingModelForm) Naming() api.BranchNaming {
	list := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	}
	return api.BranchNaming{RequireBranchType: f.RequireBranchType, Exceptions: strings.FieldsFunc(f.BranchExceptions, func(r rune) bool { return r == '\n' || r == '\r' }), ExemptUsers: list(f.ExemptUsers), ExemptTeams: list(f.ExemptTeams)}
}

// Model builds the branching model the form describes; branchworkflow.NormalizeBranchingModel checks it.
func (f *BranchingModelForm) Model() *repo_model.BranchingModel {
	m := &repo_model.BranchingModel{DevelopmentBranch: f.DevelopmentBranch, ProductionBranch: f.ProductionBranch, ReleasePrefixes: strings.Split(f.ReleasePrefixes, ","), DefaultPRTarget: f.DefaultPRTarget, MergeForward: f.MergeForward, MergeForwardNeverBypass: f.MergeForwardNeverBypass, MergeForwardAnyoneMaySkip: f.MergeForwardAnyoneMaySkip}
	at := func(l []string, i int) string {
		if i < len(l) {
			return l[i]
		}
		return ""
	}
	on := make(map[string]bool, len(f.TypeOn)) // a set: a row count the model limit refuses must not cost a scan per row
	for _, o := range f.TypeOn {
		on[o] = true
	}
	for i, name := range f.TypeName {
		if strings.TrimSpace(name) == "" && strings.TrimSpace(at(f.TypePrefix, i)) == "" { // an empty row of the table
			continue
		}
		m.Types = append(m.Types, repo_model.BranchType{Name: name, Prefix: at(f.TypePrefix, i), Base: at(f.TypeBase, i), BaseBranch: at(f.TypeBranch, i), Off: !on[strconv.Itoa(i)]})
	}
	return m
}

// Validate validates the fields
func (f *BranchingModelForm) Validate(req *http.Request, errs binding.Errors) binding.Errors {
	ctx := context.GetValidateContext(req)
	return middleware.Validate(errs, ctx.Data, f, ctx.Locale)
}
