// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	"errors"
	"html/template"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	user_model "forgejo.org/models/user"
	vulnerability_model "forgejo.org/models/vulnerability"
	"forgejo.org/modules/base"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/context"
	dependency_service "forgejo.org/services/dependency"
	vulnerability_service "forgejo.org/services/vulnerability"
)

const tplDependencyGraph base.TplName = "admin/dependency_graph"

// DependencyGraph shows the dependency graph settings: the site switch, the scan limits, the advisory source and the
// status of the advisory mirror.
func DependencyGraph(ctx *context.Context) {
	stored := setting.Config().DependencyGraphConfig.Value(ctx)
	cfg := stored.Merge()
	renderDependencyGraph(ctx, dependencyGraphForm(stored, &cfg), http.StatusOK)
}

func renderDependencyGraph(ctx *context.Context, form dependencyGraphFormData, status int) {
	ctx.Data["Title"] = ctx.Tr("admin.dependency_graph")
	ctx.Data["PageIsAdminConfig"] = true
	ctx.Data["PageIsAdminConfigDependencyGraph"] = true
	s := setting.Config().DependencyGraph.Value(ctx)
	stored := setting.Config().DependencyGraphConfig.Value(ctx)
	ctx.Data["Enabled"] = s.Enabled()
	if form.PostedEnabled != nil {
		ctx.Data["Enabled"] = *form.PostedEnabled // a refused save shows the switch as posted
	}
	ctx.Data["FileDefault"] = setting.DependencyGraph.Enabled
	// the later of the two saves: the switch and the settings
	by, at := s.UpdatedBy, s.UpdatedUnix
	if stored.UpdatedUnix > at {
		by, at = stored.UpdatedBy, stored.UpdatedUnix
	}
	if at > 0 {
		ctx.Data["UpdatedUnix"] = timeutil.TimeStamp(at)
		ctx.Data["UpdatedBy"] = "-"
		if u, err := user_model.GetPossibleUserByID(ctx, by); err == nil {
			ctx.Data["UpdatedBy"] = u.Name
		}
	}
	statuses, err := vulnerability_model.Statuses(ctx)
	if err != nil {
		ctx.ServerError("Statuses", err)
		return
	}
	if form.Revision, err = vulnerability_service.SettingsRevision(ctx); err != nil {
		ctx.ServerError("SettingsRevision", err)
		return
	}
	ctx.Data["MirrorStatuses"] = statuses
	cfg := stored.Merge()
	ctx.Data["MirrorURL"] = cfg.OSVMirrorURL
	ctx.Data["MirrorInterval"] = shortDuration(cfg.UpdateInterval)
	ctx.Data["MirrorRunning"] = vulnerability_service.Running()
	ctx.Data["MirrorSiteOn"] = dependency_service.SiteEnabled(ctx)
	ctx.Data["MirrorConfigInvalid"] = cfg.MirrorConfigInvalid
	ctx.Data["Form"] = form
	ctx.Data["DefaultOSVMirrorURL"] = setting.DefaultOSVMirrorURL
	// the auditor reads the page; only a site admin changes anything
	ctx.Data["CanChange"] = ctx.Doer.IsAdmin
	ctx.HTML(status, tplDependencyGraph)
}

// dependencyGraphField is one field of the settings form: its value in force and, when a saved value differs from
// app.ini, the app.ini value (else "").
type dependencyGraphField struct {
	Value, Default string
}

// dependencyGraphFormData is the settings form. It never holds the token, only whether one is in force.
type dependencyGraphFormData struct {
	Limits                 map[string]dependencyGraphField
	Source, SignIn         string
	MirrorURL, User, Hosts dependencyGraphField
	HasToken               bool // a token is in force for the mirror
	TokenSaved             bool // a token is saved on this page (it can be removed whatever the source)
	SourceDefault          string
	HostsFromAppIni        bool // an empty host list is app.ini's OSV_MIRROR_ALLOWED_HOSTS, else the webhook list
	Revision               string

	// a refused save: the field (a limit name, mirror_url, ..., or "" for the whole form) and its message
	ErrorField   string
	ErrorMessage template.HTML
	TokenAgain   bool // a token was entered: it isn't shown again
	RemoveToken  bool // "Remove the token" was ticked
	// the site switch as posted, when it was
	PostedEnabled *bool
}

// Open reports whether the fold holding the refused field is open.
func (f dependencyGraphFormData) Open(fold string) bool {
	switch f.ErrorField {
	case "max_manifest_size", "max_manifests", "max_dependencies", "max_tree_entries":
		return fold == "repository"
	case "osv_max_download", "osv_max_uncompressed", "osv_max_entries", "osv_max_entry_size", "osv_ecosystem_timeout":
		return fold == "download"
	}
	return false
}

// dependencyGraphLimitText is a limit in its form unit, exactly (0.5 for half a MiB).
func dependencyGraphLimitText(name string, v int64) string {
	unit := dependencyGraphFormUnits[name]
	if unit <= 1 {
		return strconv.FormatInt(v, 10)
	}
	return strconv.FormatFloat(float64(v)/float64(unit), 'f', -1, 64)
}

func dependencyGraphForm(stored setting.DependencyGraphConfig, cfg *setting.DependencyGraphOptions) dependencyGraphFormData {
	f := dependencyGraphFormData{Limits: map[string]dependencyGraphField{}}
	for _, l := range setting.DependencyGraphLimits {
		field := dependencyGraphField{Value: dependencyGraphLimitText(l.Name, l.Get(cfg))}
		if _, ok := stored.Limits[l.Name]; ok {
			if app := dependencyGraphLimitText(l.Name, l.Get(&setting.DependencyGraph)); app != field.Value {
				field.Default = app
			}
		}
		f.Limits[l.Name] = field
	}
	appSource := setting.DependencyGraphAppSource()
	f.Source = stored.Source
	if f.Source == "" {
		f.Source = appSource
	} else if f.Source != appSource {
		f.SourceDefault = appSource
	}
	f.MirrorURL.Value = stored.MirrorURL
	if f.MirrorURL.Value == "" && appSource == setting.OSVSourceMirror {
		f.MirrorURL.Value = setting.DependencyGraph.OSVMirrorURL
	}
	if appSource == setting.OSVSourceMirror && stored.MirrorURL != "" && stored.MirrorURL != setting.DependencyGraph.OSVMirrorURL {
		f.MirrorURL.Default = setting.DependencyGraph.OSVMirrorURL
	}
	f.SignIn, f.User.Value = stored.SignIn, stored.User
	if f.SignIn == "" {
		f.SignIn, f.User.Value = setting.DependencyGraphAppSignIn(), setting.DependencyGraph.OSVMirrorUser
	}
	f.TokenSaved = stored.TokenEnc != nil && *stored.TokenEnc != ""
	f.HasToken = cfg.OSVMirrorToken != "" || f.TokenSaved
	if stored.Hosts != nil {
		f.Hosts.Value = *stored.Hosts // only a saved list: an empty field follows app.ini
	}
	f.HostsFromAppIni = setting.DependencyGraph.OSVMirrorHosts != ""
	if f.HostsFromAppIni && f.Hosts.Value != "" && f.Hosts.Value != setting.DependencyGraph.OSVMirrorHosts {
		f.Hosts.Default = setting.DependencyGraph.OSVMirrorHosts
	}
	return f
}

// shortDuration writes a duration as 24h or 90m, not 24h0m0s.
func shortDuration(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d >= time.Minute && d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	}
	return d.String()
}

// DependencyGraphUpdateAdvisories starts an update of the advisory mirror ("Update now").
func DependencyGraphUpdateAdvisories(ctx *context.Context) {
	switch err := vulnerability_service.UpdateNow(ctx, ctx.Doer); {
	case err == nil:
		ctx.Flash.Success(ctx.Tr("admin.dependency_graph.advisories.started"))
	case errors.Is(err, vulnerability_service.ErrNoMirror):
		ctx.Flash.Error(ctx.Tr("admin.dependency_graph.advisories.no_mirror"))
	case errors.Is(err, vulnerability_service.ErrSiteOff):
		ctx.Flash.Error(ctx.Tr("admin.dependency_graph.advisories.site_off"))
	case errors.Is(err, vulnerability_service.ErrAlreadyRunning):
		ctx.Flash.Error(ctx.Tr("admin.dependency_graph.advisories.running"))
	case errors.Is(err, vulnerability_service.ErrTooSoon):
		ctx.Flash.Error(ctx.Tr("admin.dependency_graph.advisories.too_soon"))
	default:
		ctx.ServerError("UpdateNow", err)
		return
	}
	ctx.Redirect(setting.AppSubURL + "/admin/config/dependency-graph")
}

// DependencyGraphPost stores the site switch; off deletes the stored package lists.
func DependencyGraphPost(ctx *context.Context) {
	if err := dependency_service.SetSiteEnabled(ctx, ctx.Doer, ctx.FormBool("enabled")); err != nil {
		ctx.ServerError("SetSiteEnabled", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("repo.settings.dependency_graph.saved"))
	ctx.Redirect(setting.AppSubURL + "/admin/config/dependency-graph")
}

// dependencyGraphFormUnits is the unit of a limit in the form, counted in its stored unit (bytes or seconds); a
// limit that isn't listed is a plain number.
var dependencyGraphFormUnits = map[string]int64{
	"scan_timeout": 1, "update_interval": 3600, "osv_ecosystem_timeout": 60,
	"max_manifest_size": 1 << 20, "osv_max_download": 1 << 20, "osv_max_entry_size": 1 << 20, "osv_max_uncompressed": 1 << 20,
}

// DependencyGraphSettingsPost saves the dependency graph settings and the site switch. An empty limit or host list,
// or a value equal to app.ini, is the app.ini value; an unchanged field keeps what it is; an empty token keeps the one
// in force. A refused save shows the form again with the posted values (never the token).
func DependencyGraphSettingsPost(ctx *context.Context) {
	in := vulnerability_service.SettingsInput{
		Limits:      map[string]int64{},
		Source:      ctx.FormString("source"),
		MirrorURL:   ctx.FormString("mirror_url"),
		SignIn:      ctx.FormString("sign_in"),
		User:        ctx.FormString("user"),
		Token:       strings.TrimSpace(ctx.FormString("token")),
		RemoveToken: ctx.FormBool("remove_token"),
		Hosts:       ctx.FormString("allowed_hosts"),
	}
	if rev := ctx.FormString("revision"); rev != "" {
		in.Revision = &rev
	}
	stored := setting.Config().DependencyGraphConfig.Value(ctx)
	cfg := stored.Merge()
	var err error
	for _, l := range setting.DependencyGraphLimits {
		text := strings.TrimSpace(ctx.FormString(l.Name))
		if text == "" {
			continue
		}
		if text == dependencyGraphLimitText(l.Name, l.Get(&cfg)) {
			// an unchanged field keeps what it is: saved, or the app.ini value
			if v, ok := stored.Limits[l.Name]; ok && l.Check(v) == nil {
				in.Limits[l.Name] = v
			}
			continue
		}
		v, ok := parseDependencyGraphLimit(l.Name, text)
		if !ok {
			err = &vulnerability_service.SettingsError{Field: l.Name, Reason: vulnerability_service.SettingsInvalid}
			break
		}
		in.Limits[l.Name] = v
	}
	changed := false
	if err == nil {
		changed, err = vulnerability_service.SaveSettings(ctx, ctx.Doer, in)
	}
	// the switch is on the same form (enabled_shown tells that it was): saved after the settings, when it changes
	if on := ctx.FormBool("enabled"); err == nil && ctx.FormString("enabled_shown") != "" && on != dependency_service.SiteEnabled(ctx) {
		if err = dependency_service.SetSiteEnabled(ctx, ctx.Doer, on); err == nil {
			changed = true
		}
	}
	var serr *vulnerability_service.SettingsError
	switch {
	case errors.As(err, &serr):
		refuseDependencyGraphSettings(ctx, serr.Field, dependencyGraphSettingsError(ctx, serr))
		return
	case errors.Is(err, vulnerability_service.ErrSettingsChanged):
		refuseDependencyGraphSettings(ctx, "", ctx.Tr("admin.dependency_graph.settings.error.changed"))
		return
	case err != nil:
		ctx.ServerError("SaveSettings", err)
		return
	case changed:
		ctx.Flash.Success(ctx.Tr("admin.dependency_graph.settings.saved"))
	default:
		ctx.Flash.Info(ctx.Tr("admin.dependency_graph.settings.unchanged"))
	}
	ctx.Redirect(setting.AppSubURL + "/admin/config/dependency-graph")
}

// parseDependencyGraphLimit reads a limit in its form unit: a count is a whole number, a size or time may have
// decimals and is rounded to the byte or second. The bounds are the save's check.
func parseDependencyGraphLimit(name, text string) (int64, bool) {
	unit, ok := dependencyGraphFormUnits[name]
	if !ok {
		v, err := strconv.ParseInt(text, 10, 64)
		return v, err == nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	v := math.Round(f * float64(unit))
	if v >= math.MaxInt64 || v <= math.MinInt64 {
		return 0, false
	}
	return int64(v), true
}

// refuseDependencyGraphSettings shows the form again with the posted values (never the token) and the message at the
// refused field and next to Save. The values in force and the revision are read again, so a save over someone
// else's change shows theirs as the app.ini hints and can be made again on purpose.
func refuseDependencyGraphSettings(ctx *context.Context, field string, msg template.HTML) {
	stored := setting.Config().DependencyGraphConfig.Value(ctx)
	cfg := stored.Merge()
	f := dependencyGraphForm(stored, &cfg)
	for _, l := range setting.DependencyGraphLimits {
		if text := strings.TrimSpace(ctx.FormString(l.Name)); text != "" {
			f.Limits[l.Name] = dependencyGraphField{Value: text, Default: f.Limits[l.Name].Default}
		}
	}
	switch source := ctx.FormString("source"); source {
	case setting.OSVSourcePublic, setting.OSVSourceMirror, setting.OSVSourceNone:
		f.Source = source
	}
	switch signIn := ctx.FormString("sign_in"); signIn {
	case setting.OSVSignInNone, setting.OSVSignInToken, setting.OSVSignInBasic:
		f.SignIn = signIn
	}
	f.MirrorURL.Value, f.User.Value, f.Hosts.Value = ctx.FormString("mirror_url"), ctx.FormString("user"), ctx.FormString("allowed_hosts")
	f.TokenAgain = strings.TrimSpace(ctx.FormString("token")) != ""
	f.RemoveToken = ctx.FormBool("remove_token")
	if ctx.FormString("enabled_shown") != "" {
		on := ctx.FormBool("enabled")
		f.PostedEnabled = &on
	}
	f.ErrorField, f.ErrorMessage = field, msg
	renderDependencyGraph(ctx, f, http.StatusUnprocessableEntity)
}

// dependencyGraphSettingsError is the message of a refused save, from literal keys only.
func dependencyGraphSettingsError(ctx *context.Context, e *vulnerability_service.SettingsError) template.HTML {
	field := dependencyGraphFieldLabel(ctx, e.Field)
	switch e.Reason {
	case vulnerability_service.SettingsOutOfRange:
		l, _ := setting.DependencyGraphLimitByName(e.Field)
		maxText := dependencyGraphLimitText(e.Field, l.Max)
		if unit := dependencyGraphUnitLabel(ctx, e.Field); unit != "" {
			maxText += " " + unit
		}
		if unit := dependencyGraphFormUnits[e.Field]; unit > 1 && l.Min < unit {
			return ctx.Tr("admin.dependency_graph.settings.error.out_of_range_max", field, maxText)
		}
		return ctx.Tr("admin.dependency_graph.settings.error.out_of_range", field, dependencyGraphLimitText(e.Field, l.Min), maxText)
	case vulnerability_service.SettingsOwnHost:
		return ctx.Tr("admin.dependency_graph.settings.error.own_host")
	case vulnerability_service.SettingsTokenRequired:
		return ctx.Tr("admin.dependency_graph.settings.error.token_required")
	case vulnerability_service.SettingsTokenHostChanged:
		return ctx.Tr("admin.dependency_graph.settings.error.token_host_changed")
	case vulnerability_service.SettingsUserRequired:
		return ctx.Tr("admin.dependency_graph.settings.error.user_required")
	case vulnerability_service.SettingsHostsNotAllowed:
		return ctx.Tr("admin.dependency_graph.settings.error.hosts_not_allowed", field)
	case vulnerability_service.SettingsTokenNeedsHTTPS:
		return ctx.Tr("admin.dependency_graph.settings.error.token_needs_https")
	}
	return ctx.Tr("admin.dependency_graph.settings.error.invalid", field)
}

// dependencyGraphUnitLabel is the unit of a limit in the form ("" for a count), as the form shows it.
func dependencyGraphUnitLabel(ctx *context.Context, name string) string {
	switch dependencyGraphFormUnits[name] {
	case 1:
		return ctx.Locale.TrString("admin.dependency_graph.settings.unit.seconds")
	case 60:
		return ctx.Locale.TrString("admin.dependency_graph.settings.unit.minutes")
	case 3600:
		return ctx.Locale.TrString("admin.dependency_graph.settings.unit.hours")
	case 1 << 20:
		return ctx.Locale.TrString("admin.dependency_graph.settings.unit.mib")
	}
	return ""
}

// dependencyGraphFieldLabel is the label of a field of the settings form.
func dependencyGraphFieldLabel(ctx *context.Context, field string) string {
	switch field {
	case "max_concurrent_scans":
		return ctx.Locale.TrString("admin.dependency_graph.settings.max_concurrent_scans")
	case "scan_timeout":
		return ctx.Locale.TrString("admin.dependency_graph.settings.scan_timeout")
	case "max_manifest_size":
		return ctx.Locale.TrString("admin.dependency_graph.settings.max_manifest_size")
	case "max_manifests":
		return ctx.Locale.TrString("admin.dependency_graph.settings.max_manifests")
	case "max_dependencies":
		return ctx.Locale.TrString("admin.dependency_graph.settings.max_dependencies")
	case "max_tree_entries":
		return ctx.Locale.TrString("admin.dependency_graph.settings.max_tree_entries")
	case "update_interval":
		return ctx.Locale.TrString("admin.dependency_graph.settings.update_interval")
	case "osv_max_download":
		return ctx.Locale.TrString("admin.dependency_graph.settings.osv_max_download")
	case "osv_max_entries":
		return ctx.Locale.TrString("admin.dependency_graph.settings.osv_max_entries")
	case "osv_max_entry_size":
		return ctx.Locale.TrString("admin.dependency_graph.settings.osv_max_entry_size")
	case "osv_max_uncompressed":
		return ctx.Locale.TrString("admin.dependency_graph.settings.osv_max_uncompressed")
	case "osv_ecosystem_timeout":
		return ctx.Locale.TrString("admin.dependency_graph.settings.osv_ecosystem_timeout")
	case "source":
		return ctx.Locale.TrString("admin.dependency_graph.settings.source")
	case "mirror_url":
		return ctx.Locale.TrString("admin.dependency_graph.settings.mirror_url")
	case "sign_in":
		return ctx.Locale.TrString("admin.dependency_graph.settings.sign_in")
	case "user":
		return ctx.Locale.TrString("admin.dependency_graph.settings.user")
	case "token":
		return ctx.Locale.TrString("admin.dependency_graph.settings.token")
	case "allowed_hosts":
		return ctx.Locale.TrString("admin.dependency_graph.settings.allowed_hosts")
	}
	return field
}

// DependencyGraphTestConnection tests the saved mirror settings; the answer is a class, never error text. With
// inline=1 (the page's script) the message comes back as JSON, else as a flash.
func DependencyGraphTestConnection(ctx *context.Context) {
	class, err := vulnerability_service.TestConnection(ctx)
	var msg template.HTML
	switch {
	case errors.Is(err, vulnerability_service.ErrNoMirror):
		msg = ctx.Tr("admin.dependency_graph.test.no_mirror")
	case errors.Is(err, vulnerability_service.ErrSiteOff):
		msg = ctx.Tr("admin.dependency_graph.advisories.site_off")
	case errors.Is(err, vulnerability_service.ErrTestTooSoon):
		msg = ctx.Tr("admin.dependency_graph.test.too_soon")
	case err != nil:
		ctx.ServerError("TestConnection", err)
		return
	case class == vulnerability_service.ConnectionOK:
		msg = ctx.Tr("admin.dependency_graph.test.ok")
	default:
		msg = dependencyGraphTestError(ctx, class)
	}
	ok := err == nil && class == vulnerability_service.ConnectionOK
	if ctx.FormString("inline") == "1" {
		ctx.JSON(http.StatusOK, map[string]any{"ok": ok, "message": string(msg)})
		return
	}
	if ok {
		ctx.Flash.Success(msg)
	} else {
		ctx.Flash.Error(msg)
	}
	ctx.Redirect(setting.AppSubURL + "/admin/config/dependency-graph")
}

func dependencyGraphTestError(ctx *context.Context, class string) template.HTML {
	switch class {
	case vulnerability_model.ErrClassAuthFailed:
		return ctx.Tr("admin.dependency_graph.test.auth_failed")
	case vulnerability_model.ErrClassBlockedHost:
		return ctx.Tr("admin.dependency_graph.test.blocked_host")
	case vulnerability_model.ErrClassTimeout:
		return ctx.Tr("admin.dependency_graph.test.timeout")
	case vulnerability_model.ErrClassStatus4xx:
		return ctx.Tr("admin.dependency_graph.test.status_4xx")
	case vulnerability_model.ErrClassStatus5xx:
		return ctx.Tr("admin.dependency_graph.test.status_5xx")
	case vulnerability_model.ErrClassRedirectRefused:
		return ctx.Tr("admin.dependency_graph.test.redirect_refused")
	case vulnerability_model.ErrClassConfigInvalid:
		return ctx.Tr("admin.dependency_graph.test.config_invalid")
	}
	return ctx.Tr("admin.dependency_graph.test.connection_failed")
}
