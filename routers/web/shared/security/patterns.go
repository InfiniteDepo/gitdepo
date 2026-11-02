// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package security

import (
	"errors"
	"html"
	"net/http"
	"regexp/syntax"
	"strings"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/setting"
	"forgejo.org/services/context"
	secretscan_service "forgejo.org/services/secretscan"

	"xorm.io/builder"
)

// PatternRow is a pattern of the page. Text is the pattern itself: empty unless the viewer may read it (owners of the
// pattern's level), the others see the name and the keywords.
type PatternRow struct {
	*secretscan_model.CustomPattern
	Keywords  []string
	Text      string
	Site      bool // a site pattern on an organization's page: shown, never changed there
	CreatedBy string
	Alerts    int64 // open alerts the viewer sees
}

// PatternForm is what the add form sends, kept for a refused save. The sample is never kept.
type PatternForm struct {
	Name     string
	Pattern  string
	Keywords string
}

// PatternErr is the refusal of a save, shown above the form; Field is the form field to mark.
type PatternErr struct {
	Title string
	Text  string
	Field string
}

// PatternsPage is the data of the patterns box, as ctx.Data["Patterns"].
type PatternsPage struct {
	Link, ListLink string // the box posts to Link; ListLink is the alert list, which takes ?type=
	Rows           []PatternRow
	CanWrite       bool
	ShowText       bool
	Locked         string // why a viewer who could write can't: "archived" or "maintenance"
	Site           bool   // the site's page
	On, Cap        int    // the patterns that are on (in an organization, its own and the site's) and the limit
	Form           PatternForm
	Err            *PatternErr
}

// LoadPatterns sets ctx.Data["Patterns"]. org is nil for the site's page. scope decides which alerts the counts
// cover. A refused add keeps its form and error from ctx.Data["PatternForm"] and ["PatternErr"].
func LoadPatterns(ctx *context.Context, org *user_model.User, scope secretscan_service.Scope, link, listLink string, canWrite, showText bool) error {
	owners := []int64{0}
	if org != nil {
		owners = append(owners, org.ID)
	}
	patterns, err := secretscan_model.FindLiveCustomPatterns(ctx, builder.In("owner_id", owners), len(owners)*secretscan_service.MaxLivePatterns)
	if err != nil {
		return err
	}
	var ruleIDs []string
	var userIDs []int64
	for _, p := range patterns {
		ruleIDs = append(ruleIDs, p.RuleID())
		userIDs = append(userIDs, p.CreatedByID)
	}
	users, err := user_model.GetUsersByIDsWithBots(ctx, userIDs)
	if err != nil {
		return err
	}
	counts := map[string]int64{}
	if cond, empty, err := scope.RepoCond(ctx); err != nil {
		return err
	} else if !empty {
		if counts, err = secretscan_model.CountOpenAlertsByRule(ctx, cond, ruleIDs); err != nil {
			return err
		}
	}
	on, err := secretscan_model.CountActiveCustomPatterns(ctx, owners...)
	if err != nil {
		return err
	}
	page := &PatternsPage{Link: link, ListLink: listLink, CanWrite: canWrite, ShowText: showText, Site: org == nil, On: int(on), Cap: secretdetection.MaxCustomRules}
	for _, p := range patterns {
		row := PatternRow{CustomPattern: p, Keywords: p.KeywordList(), Site: p.OwnerID == 0 && org != nil, Alerts: counts[p.RuleID()]}
		if showText && !row.Site {
			row.Text = p.Pattern
		}
		if _, u := user_model.GetUserFromMap(p.CreatedByID, users); u != nil && p.CreatedByID > 0 {
			row.CreatedBy = u.GetDisplayName()
		}
		page.Rows = append(page.Rows, row)
	}
	switch {
	case org != nil && org.IsArchived:
		page.Locked = "archived"
	case setting.GetMaintenance(ctx).ReadOnly():
		page.Locked = "maintenance"
	}
	if f, ok := ctx.Data["PatternForm"].(PatternForm); ok {
		page.Form = f
	}
	if e, ok := ctx.Data["PatternErr"].(*PatternErr); ok {
		page.Err = e
	}
	if page.Locked != "" {
		page.CanWrite = false
	}
	ctx.Data["Patterns"] = page
	return nil
}

func splitKeywords(s string) []string {
	var out []string
	for k := range strings.SplitSeq(s, ",") {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func patternInput(ctx *context.Context) secretscan_service.PatternInput {
	return secretscan_service.PatternInput{
		Name: ctx.FormString("name"), Pattern: ctx.FormString("pattern"),
		Keywords: splitKeywords(ctx.FormString("keywords")), Sample: ctx.FormString("sample"),
	}
}

// patternRefusal says why a save or a test was refused: a locale key under secret_pattern.err_title. and the key of
// its text under secret_pattern.err_text. (most often the same), the form field to mark, and the arguments of the
// text.
func patternRefusal(err error) (key, textKey, field string, args []any) {
	var holds *secretdetection.HoldsSecretError
	switch {
	case errors.Is(err, secretdetection.ErrCustomNameInvalid):
		key, field = "name", "name"
	case errors.Is(err, secretscan_service.ErrPatternNameTaken):
		key, field = "name_taken", "name"
	case errors.Is(err, secretdetection.ErrPatternTooLong):
		key, field = "too_long", "pattern"
	case errors.Is(err, secretdetection.ErrPatternInvalid):
		key, field = "invalid", "pattern"
		textKey, args = invalidText(err)
	case errors.Is(err, secretdetection.ErrPatternTooComplex):
		key, field = "complex", "pattern"
	case errors.Is(err, secretdetection.ErrPatternMatchesEmpty):
		key, field = "empty", "pattern"
	case errors.Is(err, secretdetection.ErrPatternMatchesTooMuch):
		key, field = "common", "pattern"
	case errors.Is(err, secretdetection.ErrKeywordNotInMatch):
		key, field = "keywords_match", "keywords"
	case errors.Is(err, secretdetection.ErrKeywordMissing):
		key, field = "keywords", "keywords"
	case errors.Is(err, secretdetection.ErrKeywordTooCommon):
		key, field = "keyword_common", "keywords"
	case errors.As(err, &holds):
		key, field, args = "holds_secret", holds.Field, []any{holds.Format}
		textKey = "holds_secret_" + holds.Field
	case errors.Is(err, secretdetection.ErrPatternHoldsSecret):
		key, field = "holds_secret", "pattern"
	case errors.Is(err, secretdetection.ErrPatternNoMatchInTest):
		key, field = "no_match", "sample"
	case errors.Is(err, secretdetection.ErrSecretTooShort):
		key, field = "short", "sample"
	case errors.Is(err, secretdetection.ErrTestStringTooLong):
		key, field = "sample_long", "sample"
	case errors.Is(err, secretscan_service.ErrPatternLimit):
		key, args = "limit", []any{secretdetection.MaxCustomRules}
	case errors.Is(err, secretscan_service.ErrLivePatternLimit):
		key, args = "live_limit", []any{secretscan_service.MaxLivePatterns}
	}
	if textKey == "" {
		textKey = key
	}
	return key, textKey, field, args
}

// invalidText is the text of a pattern that doesn't parse, in plain words: the parser's own message is never shown.
// It may quote a part of the pattern, which is the doer's own input.
func invalidText(err error) (string, []any) {
	var serr *syntax.Error
	if !errors.As(err, &serr) {
		return "invalid", nil
	}
	switch serr.Code {
	case syntax.ErrMissingParen:
		return "invalid_paren", nil
	case syntax.ErrUnexpectedParen:
		return "invalid_unexpected_paren", nil
	case syntax.ErrMissingBracket:
		return "invalid_bracket", nil
	case syntax.ErrInvalidRepeatOp, syntax.ErrMissingRepeatArgument:
		return "invalid_repeat", []any{serr.Expr}
	case syntax.ErrInvalidRepeatSize:
		return "invalid_repeat_size", []any{serr.Expr}
	case syntax.ErrInvalidPerlOp:
		return "invalid_perl", nil
	case syntax.ErrInvalidEscape:
		if len(serr.Expr) == 2 && serr.Expr[1] >= '1' && serr.Expr[1] <= '9' { // \1: a backreference
			return "invalid_perl", nil
		}
		return "invalid_escape", []any{serr.Expr}
	}
	return "invalid_near", []any{serr.Expr}
}

// refusal builds the PatternErr of an error. The texts take the masked match (never the sample) and the limits.
func refusal(ctx *context.Context, err error, res *secretscan_service.TestResult) *PatternErr {
	key, textKey, field, args := patternRefusal(err)
	if key == "" {
		return nil
	}
	if (key == "keywords_match" || key == "short") && res != nil {
		textKey, args = key+"_found", []any{res.Masked}
		if key == "short" {
			args = append(args, res.SecretLen)
		}
	}
	return &PatternErr{
		Field: field, Title: ctx.Locale.TrString("secret_pattern.err_title." + key),
		Text: ctx.Locale.TrString("secret_pattern.err_text."+textKey, args...),
	}
}

// maxPatternBody is the most a pattern form may send: its fields' limits (a pattern of 1024 bytes, a sample of
// 4 KiB) with room for the encoding.
const maxPatternBody = 32 << 10

// LimitPatternBody answers 413 to a pattern form that is larger than its fields can be. It must run before anything
// reads the form (FormValue reads the whole body, up to Go's own 10 MB limit), so it is the routes' group middleware,
// ahead of RateLimitHeavyPlain, which reads a form value.
func LimitPatternBody(ctx *context.Context) {
	ctx.Req.Body = http.MaxBytesReader(ctx.Resp, ctx.Req.Body, maxPatternBody)
	err := ctx.Req.ParseForm() // ParseMultipartForm drops its error for a form that isn't multipart
	if err == nil {
		err = ctx.Req.ParseMultipartForm(maxPatternBody)
	}
	if err != nil && !errors.Is(err, http.ErrNotMultipart) {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			ctx.Error(http.StatusRequestEntityTooLarge)
		} else {
			ctx.Error(http.StatusBadRequest)
		}
	}
}

// PatternTest checks a pattern against a sample and answers JSON; nothing is stored, and the answer holds at most the
// first characters of what was found. It reads and runs a user's expression, so the route is rate limited.
func PatternTest(ctx *context.Context) {
	res, err := secretscan_service.TestPattern(patternInput(ctx))
	if err == nil {
		ctx.JSON(http.StatusOK, map[string]any{
			"ok":      true,
			"title":   ctx.Locale.TrString("secret_pattern.test_ok.title"),
			"message": ctx.Locale.TrString("secret_pattern.test_ok.text", res.SecretLen, res.Masked),
		})
		return
	}
	e := refusal(ctx, err, res)
	if e == nil {
		ctx.ServerError("TestPattern", err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"ok": false, "title": e.Title, "message": e.Text, "field": e.Field})
}

// PatternAdd saves the posted pattern for the organization (nil: the site) and says whether it did. A refusal sets
// ctx.Data["PatternErr"] and ["PatternForm"] for the page to show again (the sample is not kept).
func PatternAdd(ctx *context.Context, org *user_model.User) bool {
	in := patternInput(ctx)
	_, err := secretscan_service.CreatePattern(ctx, ctx.Doer, patternOwner(org), in)
	if err == nil {
		ctx.Flash.Success(ctx.Tr("secret_pattern.added", strings.TrimSpace(in.Name)))
		return true
	}
	e := refusal(ctx, err, secretscan_service.FoundInSample(in, err))
	if e == nil {
		ctx.ServerError("CreatePattern", err)
		return false
	}
	ctx.Data["PatternErr"] = e
	ctx.Data["PatternForm"] = PatternForm{Name: in.Name, Pattern: in.Pattern, Keywords: ctx.FormString("keywords")}
	return false
}

// PatternAction runs one of rename, enable, disable and delete on the pattern of the route and redirects to page.
func PatternAction(ctx *context.Context, org *user_model.User, action, page string) {
	id := ctx.ParamsInt64("id")
	var err error
	switch action {
	case "rename":
		err = secretscan_service.RenamePattern(ctx, patternOwner(org), id, ctx.FormString("name"))
	case "enable":
		err = secretscan_service.SetPatternEnabled(ctx, patternOwner(org), id, true)
	case "disable":
		err = secretscan_service.SetPatternEnabled(ctx, patternOwner(org), id, false)
	case "delete":
		err = secretscan_service.DeletePatternConfirmed(ctx, patternOwner(org), id, ctx.FormString("confirm_name"))
	}
	switch {
	case errors.Is(err, secretscan_service.ErrPatternNotFound):
		ctx.NotFound("pattern", nil)
		return
	case err == nil:
		ctx.Flash.Success(ctx.Tr("secret_pattern.done." + action))
	case errors.Is(err, secretscan_service.ErrConfirmName):
		ctx.Flash.Error(ctx.Tr("secret_pattern.delete_confirm_failed"))
	default:
		e := refusal(ctx, err, nil)
		if e == nil {
			ctx.ServerError("pattern "+action, err)
			return
		}
		ctx.Flash.Error(html.EscapeString(e.Title + ": " + e.Text)) // Flash.Error renders sanitized HTML
	}
	ctx.Redirect(page)
}

// patternOwner is the site for a nil organization.
func patternOwner(org *user_model.User) secretscan_service.PatternOwner {
	if org == nil {
		return secretscan_service.SitePatterns
	}
	return secretscan_service.OrgPatterns(org)
}

// maxInstanceTypes is how many custom patterns the instance list's type filter offers.
const maxInstanceTypes = 1000

// customSecretTypes are the choices of the type filter for custom patterns, on or off, names only: in an
// organization's list the site's and the organization's; in the instance list the site's and those of every
// organization the viewer isn't kept out of by its 2FA requirement, with the organization's name. A deleted pattern's
// alerts are still listed, just not offered. cut says the instance list was cut at maxInstanceTypes.
func customSecretTypes(ctx *context.Context, scope secretscan_service.Scope) (types []SecretType, cut bool, err error) {
	if scope.Org != nil {
		patterns, err := secretscan_model.FindLiveCustomPatterns(ctx, builder.In("owner_id", 0, scope.Org.ID), 2*secretscan_service.MaxLivePatterns)
		if err != nil {
			return nil, false, err
		}
		out := make([]SecretType, len(patterns))
		for i, p := range patterns {
			out[i] = SecretType{p.RuleID(), p.Name}
		}
		return out, false, nil
	}
	orgs := builder.Select("id").From("`user`").Where(builder.Eq{"type": user_model.UserTypeOrganization, "trashed_unix": 0}.
		And(builder.NotIn("id", repo_model.TwoFactorBlockingOrgIDs(scope.Doer.ID))))
	patterns, err := secretscan_model.FindLiveCustomPatterns(ctx, builder.Eq{"owner_id": 0}.Or(builder.In("owner_id", orgs)), maxInstanceTypes+1)
	if err != nil {
		return nil, false, err
	}
	if len(patterns) > maxInstanceTypes {
		patterns, cut = patterns[:maxInstanceTypes], true
	}
	var ownerIDs []int64
	for _, p := range patterns {
		if p.OwnerID != 0 {
			ownerIDs = append(ownerIDs, p.OwnerID)
		}
	}
	owners, err := db.GetByIDs(ctx, "id", ownerIDs, &user_model.User{})
	if err != nil {
		return nil, false, err
	}
	out := make([]SecretType, len(patterns))
	for i, p := range patterns {
		out[i] = SecretType{p.RuleID(), p.Name}
		if o := owners[p.OwnerID]; o != nil {
			out[i].Name += " (" + o.Name + ")"
		}
	}
	return out, cut, nil
}
