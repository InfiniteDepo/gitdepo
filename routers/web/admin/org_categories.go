// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	gocontext "context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"

	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	system_model "forgejo.org/models/system"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
)

const (
	tplOrgCategories   base.TplName = "admin/org_category/list"
	tplOrgCategoryEdit base.TplName = "admin/org_category/edit"
)

func orgCategoriesLink() string {
	return setting.AppSubURL + "/admin/org-categories"
}

// OrgCategories lists the organization categories and the owner setting
func OrgCategories(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.org_categories")
	ctx.Data["PageIsAdminOrgCategories"] = true
	cats, err := org_model.FindOrgCategories(ctx)
	if err != nil {
		ctx.ServerError("FindOrgCategories", err)
		return
	}
	ctx.Data["OrgCategories"] = cats
	ctx.Data["OwnersCanAssign"] = setting.Config().OrgCategoryOwnersCanAssign.Value(ctx)
	ctx.HTML(http.StatusOK, tplOrgCategories)
}

// OrgCategoriesSettingsPost stores whether organization owners can set their category
func OrgCategoriesSettingsPost(ctx *context.Context) {
	v := strconv.FormatBool(ctx.FormBool("owners_can_assign"))
	if err := system_model.SetSettings(ctx, map[string]string{setting.Config().OrgCategoryOwnersCanAssign.DynKey(): v}); err != nil {
		ctx.ServerError("SetSettings", err)
		return
	}
	config.GetDynGetter().InvalidateCache()
	ctx.Flash.Success(ctx.Tr("admin.org_categories.settings_saved"))
	ctx.Redirect(orgCategoriesLink())
}

// NewOrgCategory renders the form to create a category
func NewOrgCategory(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.org_categories.new")
	ctx.Data["PageIsAdminOrgCategories"] = true
	ctx.Data["color"] = "#6c757d"
	ctx.HTML(http.StatusOK, tplOrgCategoryEdit)
}

// saveOrgCategory applies the form to c and stores it with save, rendering the form with an error when it fails
func saveOrgCategory(ctx *context.Context, c *org_model.OrgCategory, save func(gocontext.Context, *org_model.OrgCategory) error, flash template.HTML) {
	form := web.GetForm(ctx).(*forms.OrgCategoryForm)
	if ctx.HasError() {
		ctx.HTML(http.StatusOK, tplOrgCategoryEdit)
		return
	}
	c.Name, c.Description, c.Color, c.Position = form.Name, form.Description, form.Color, form.Position
	err := save(ctx, c)
	switch {
	case errors.Is(err, util.ErrAlreadyExist):
		ctx.Data["Err_Name"] = true
		ctx.RenderWithErr(ctx.Tr("admin.org_categories.name_taken"), tplOrgCategoryEdit, form)
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Data["Err_Color"] = true
		ctx.RenderWithErr(ctx.Tr("admin.org_categories.invalid"), tplOrgCategoryEdit, form)
	case err != nil:
		ctx.ServerError("SaveOrgCategory", err)
	default:
		ctx.Flash.Success(flash)
		ctx.Redirect(orgCategoriesLink())
	}
}

// NewOrgCategoryPost creates a category
func NewOrgCategoryPost(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("admin.org_categories.new")
	ctx.Data["PageIsAdminOrgCategories"] = true
	saveOrgCategory(ctx, &org_model.OrgCategory{}, org_model.CreateOrgCategory, ctx.Tr("admin.org_categories.created"))
}

func getOrgCategory(ctx *context.Context) *org_model.OrgCategory {
	c, err := org_model.GetOrgCategoryByID(ctx, ctx.ParamsInt64(":id"))
	if err != nil {
		ctx.NotFoundOrServerError("GetOrgCategoryByID", db.IsErrNotExist, err)
		return nil
	}
	ctx.Data["Title"] = ctx.Tr("admin.org_categories.edit")
	ctx.Data["PageIsAdminOrgCategories"] = true
	ctx.Data["OrgCategory"] = c
	ctx.Data["OrgCategoryLink"] = fmt.Sprintf("%s/%d", orgCategoriesLink(), c.ID)
	return c
}

// EditOrgCategory renders the form to edit a category
func EditOrgCategory(ctx *context.Context) {
	c := getOrgCategory(ctx)
	if ctx.Written() {
		return
	}
	ctx.Data["name"], ctx.Data["description"], ctx.Data["color"], ctx.Data["position"] = c.Name, c.Description, c.Color, c.Position
	ctx.HTML(http.StatusOK, tplOrgCategoryEdit)
}

// EditOrgCategoryPost updates a category
func EditOrgCategoryPost(ctx *context.Context) {
	c := getOrgCategory(ctx)
	if ctx.Written() {
		return
	}
	saveOrgCategory(ctx, c, org_model.UpdateOrgCategory, ctx.Tr("admin.org_categories.updated"))
}

// DeleteOrgCategory deletes a category; its organizations move to "Other"
func DeleteOrgCategory(ctx *context.Context) {
	c := getOrgCategory(ctx)
	if ctx.Written() {
		return
	}
	if err := org_model.DeleteOrgCategory(ctx, c.ID); err != nil {
		ctx.ServerError("DeleteOrgCategory", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.org_categories.deleted"))
	ctx.JSONRedirect(orgCategoriesLink())
}
