// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"forgejo.org/models/auth"
	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/eventsource"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web/middleware"
	"forgejo.org/routers/common"
	auth_service "forgejo.org/services/auth"
	saml_source "forgejo.org/services/auth/source/saml"
	"forgejo.org/services/context"

	"github.com/crewjam/saml"
)

const tplSAMLPost base.TplName = "user/auth/saml_post"

// samlCrossOrigin tells the IdP's cross-site POST to the ACS, which carries no session cookie, from the same-site
// POST of the page that posts it again.
var samlCrossOrigin = http.NewCrossOriginProtection()

// samlSource returns the active SAML source named in the path, or answers 404.
func samlSource(ctx *context.Context) (*auth.Source, *saml_source.Source) {
	authSource, err := auth.GetActiveSSOSourceByName(ctx, ctx.Params(":source"))
	if err != nil || !authSource.IsSAML() {
		if err != nil && !errors.Is(err, util.ErrNotExist) {
			ctx.ServerError("GetActiveSSOSourceByName", err)
			return nil, nil
		}
		ctx.NotFound("SAML source", nil)
		return nil, nil
	}
	return authSource, authSource.Cfg.(*saml_source.Source)
}

// loadSAMLSources sets SAMLSources, the active SAML sources shown as sign-in buttons.
func loadSAMLSources(ctx *context.Context) ([]*auth.Source, bool) {
	sources, err := db.Find[auth.Source](ctx, auth.FindSourcesOptions{IsActive: optional.Some(true), LoginType: auth.SAML})
	if err != nil {
		ctx.ServerError("FindSources", err)
		return nil, false
	}
	slices.SortFunc(sources, func(a, b *auth.Source) int { return strings.Compare(a.Name, b.Name) })
	ctx.Data["SAMLSources"] = sources
	return sources, true
}

// SAMLMetadata serves the SP metadata, for the IdP to import.
func SAMLMetadata(ctx *context.Context) {
	_, source := samlSource(ctx)
	if source == nil {
		return
	}
	md, err := source.SPMetadata()
	if err != nil {
		ctx.ServerError("SPMetadata", err)
		return
	}
	data, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		ctx.ServerError("MarshalIndent", err)
		return
	}
	ctx.Resp.Header().Set("Content-Type", "application/samlmetadata+xml")
	ctx.Resp.WriteHeader(http.StatusOK)
	_, _ = ctx.Resp.Write(append([]byte(xml.Header), data...))
}

// samlUnavailable tells the user the source can't be used and logs why.
func samlUnavailable(ctx *context.Context, authSource *auth.Source, err error) {
	log.Error("SAML source %q: %v", authSource.Name, err)
	ctx.Flash.Error(ctx.Tr("auth.saml.unavailable", authSource.Name))
	ctx.Redirect(setting.AppSubURL + "/user/login")
}

// SAMLSignIn sends the browser to the IdP with an authentication request.
func SAMLSignIn(ctx *context.Context) {
	authSource, source := samlSource(ctx)
	if source == nil {
		return
	}
	if redirectTo := ctx.FormString("redirect_to"); redirectTo != "" {
		middleware.SetRedirectToCookie(ctx.Resp, redirectTo)
	}

	sp, err := source.ServiceProvider(ctx)
	if err != nil {
		samlUnavailable(ctx, authSource, err)
		return
	}
	binding := saml.HTTPRedirectBinding
	location := sp.GetSSOBindingLocation(binding)
	if location == "" {
		binding = saml.HTTPPostBinding
		location = sp.GetSSOBindingLocation(binding)
	}
	req, err := sp.MakeAuthenticationRequest(location, binding, saml.HTTPPostBinding)
	if err != nil {
		samlUnavailable(ctx, authSource, err)
		return
	}

	// the response must answer this request: it binds the sign-in to this browser
	if err := ctx.Session.Set("samlRequestID", req.ID); err != nil {
		ctx.ServerError("Session.Set", err)
		return
	}
	if err := ctx.Session.Set("samlRequestSource", authSource.ID); err != nil {
		ctx.ServerError("Session.Set", err)
		return
	}
	if err := ctx.Session.Release(); err != nil {
		ctx.ServerError("Session.Release", err)
		return
	}

	if binding == saml.HTTPPostBinding {
		ctx.Resp.Header().Set("Content-Type", "text/html; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-store")
		ctx.Resp.WriteHeader(http.StatusOK)
		_, _ = ctx.Resp.Write(req.Post(""))
		return
	}
	u, err := req.Redirect("", sp)
	if err != nil {
		samlUnavailable(ctx, authSource, err)
		return
	}
	// not ctx.Redirect: it drops the cookie of a session that starts here, and the session holds the request ID
	ctx.Resp.Header().Set("Cache-Control", "no-store")
	http.Redirect(ctx.Resp, ctx.Req, u.String(), http.StatusSeeOther)
}

// SAMLACS receives the IdP's response and signs the user in.
func SAMLACS(ctx *context.Context) {
	authSource, source := samlSource(ctx)
	if source == nil {
		return
	}
	samlResponse := ctx.Req.PostFormValue("SAMLResponse")
	if samlResponse == "" || base64.StdEncoding.DecodedLen(len(samlResponse)) > saml_source.MaxResponseSize {
		ctx.Error(http.StatusBadRequest, "no SAMLResponse")
		return
	}

	// The IdP's POST comes from another site, so the browser leaves out the session cookie (SameSite=Lax). Post the
	// response again from this site: that request carries the session, which holds the ID of the request it answers.
	if samlCrossOrigin.Check(ctx.Req) != nil {
		ctx.Resp.Header().Set("Cache-Control", "no-store")
		ctx.Data["Action"] = setting.AppSubURL + "/user/saml/" + url.PathEscape(authSource.Name) + "/acs"
		ctx.Data["SAMLResponse"] = samlResponse
		ctx.HTML(http.StatusOK, tplSAMLPost)
		return
	}

	requestID := ""
	if id, _ := ctx.Session.Get("samlRequestSource").(int64); id == authSource.ID {
		requestID, _ = ctx.Session.Get("samlRequestID").(string)
	}
	// a request is answered once
	_ = ctx.Session.Delete("samlRequestID")
	_ = ctx.Session.Delete("samlRequestSource")
	if requestID == "" {
		// A response this browser didn't ask for may have been planted by someone else, so it never signs anyone in.
		// A sign-in started at the IdP starts one of ours instead, which the IdP answers for this browser's own user.
		if !source.AllowIDPInitiated {
			auth_service.RecordSignInFailure(ctx, 0, "saml_unsolicited")
			ctx.Flash.Error(ctx.Tr("auth.saml.idp_initiated_unknown", authSource.Name))
			ctx.Redirect(setting.AppSubURL + "/user/login")
			return
		}
		ctx.Redirect(setting.AppSubURL + "/user/saml/" + url.PathEscape(authSource.Name) + "/login")
		return
	}

	attempt := common.StartAuthAttempt(ctx)
	if attempt == nil {
		return
	}

	sp, err := source.ServiceProvider(ctx)
	if err != nil {
		samlUnavailable(ctx, authSource, err)
		return
	}
	a, err := source.ParseResponse(sp, samlResponse, requestID)
	if err != nil {
		log.Info("SAML source %q refused a response from %s: %v", authSource.Name, ctx.RemoteAddr(), err)
		auth_service.RecordSignInFailure(ctx, 0, "saml_failed")
		ctx.Flash.Error(ctx.Tr("auth.saml.signin_failed", authSource.Name))
		ctx.Redirect(setting.AppSubURL + "/user/login")
		return
	}
	attempt.Succeeded()
	gothUser := a.User

	u, err := oAuth2GothUserToUser(ctx, authSource, gothUser)
	if err == nil {
		err = checkRequiredClaim(source.ClaimSettings(), &gothUser)
	}
	if err != nil {
		if uplerr, ok := err.(user_model.ErrUserProhibitLogin); ok {
			auth_service.RecordSignInFailure(ctx, uplerr.UID, "prohibited")
			log.Info("Failed authentication attempt for %s from %s: %v", uplerr.Name, ctx.RemoteAddr(), err)
			ctx.Data["Title"] = ctx.Tr("auth.prohibit_login")
			ctx.HTML(http.StatusOK, "user/auth/prohibit_login")
			return
		}
		ctx.ServerError("UserSignIn", err)
		return
	}

	// remembered for single logout, with the account ID it belongs to
	for k, v := range map[string]any{
		"samlSourceID":     authSource.ID,
		"samlUserID":       gothUser.UserID,
		"samlNameID":       a.NameID,
		"samlNameIDFormat": a.NameIDFormat,
		"samlSessionIndex": a.SessionIndex,
	} {
		if err := ctx.Session.Set(k, v); err != nil {
			ctx.ServerError("Session.Set", err)
			return
		}
	}
	signInExternalUser(ctx, authSource, u, gothUser)
}

// samlSessionIdentity returns the SAML source and NameID that signed in the current user, if any. A sign-in that was
// left unfinished (link, 2FA) or went to another account leaves them in the session, so they count only while the
// signed-in user is the account of that SAML user.
func samlSessionIdentity(ctx *context.Context) (int64, string) {
	sourceID, _ := ctx.Session.Get("samlSourceID").(int64)
	userID, _ := ctx.Session.Get("samlUserID").(string)
	nameID, _ := ctx.Session.Get("samlNameID").(string)
	if ctx.Doer == nil || sourceID == 0 || userID == "" || nameID == "" {
		return 0, ""
	}
	if ctx.Doer.LoginType == auth.SAML && ctx.Doer.LoginSource == sourceID && ctx.Doer.LoginName == userID {
		return sourceID, nameID
	}
	linked, err := db.GetEngine(ctx).Exist(&user_model.ExternalLoginUser{LoginSourceID: sourceID, UserID: ctx.Doer.ID, ExternalID: userID})
	if err != nil {
		log.Error("SAML single logout: %v", err)
	}
	if !linked {
		return 0, ""
	}
	return sourceID, nameID
}

// samlLogoutURL returns where to send the browser after signing out: the IdP's single logout when the session was
// started by a SAML source that has one, else "".
func samlLogoutURL(ctx *context.Context) string {
	sourceID, nameID := samlSessionIdentity(ctx)
	if sourceID == 0 {
		return ""
	}
	format, _ := ctx.Session.Get("samlNameIDFormat").(string)
	sessionIndex, _ := ctx.Session.Get("samlSessionIndex").(string)

	authSource, err := auth.GetSourceByID(ctx, sourceID)
	if err != nil || !authSource.IsActive || !authSource.IsSAML() {
		return ""
	}
	sp, err := authSource.Cfg.(*saml_source.Source).ServiceProvider(ctx)
	if err != nil {
		log.Error("SAML source %q: %v", authSource.Name, err)
		return ""
	}
	u, err := saml_source.LogoutRequestURL(sp, nameID, format, sessionIndex)
	if err != nil {
		log.Error("SAML source %q: logout request: %v", authSource.Name, err)
		return ""
	}
	return u
}

// SAMLSLO handles single logout: the IdP's answer to a logout request sent by SignOut, or a logout request from the
// IdP, which signs this browser out when its session belongs to that IdP user.
func SAMLSLO(ctx *context.Context) {
	authSource, source := samlSource(ctx)
	if source == nil {
		return
	}
	query := ctx.Req.URL.Query()
	switch {
	case query.Has("SAMLResponse"):
		// the session ended before the logout request was sent
		ctx.Redirect(setting.AppSubURL + "/")
	case query.Has("SAMLRequest"):
		sp, err := source.ServiceProvider(ctx)
		if err != nil {
			log.Error("SAML source %q: %v", authSource.Name, err)
			ctx.Error(http.StatusServiceUnavailable)
			return
		}
		req, relayState, err := source.ParseLogoutRequest(sp, ctx.Req.URL.RawQuery)
		if err != nil {
			log.Info("SAML source %q refused a logout request from %s: %v", authSource.Name, ctx.RemoteAddr(), err)
			ctx.Error(http.StatusBadRequest, "invalid logout request")
			return
		}
		if sourceID, nameID := samlSessionIdentity(ctx); sourceID == authSource.ID && nameID == req.NameID.Value {
			if ctx.Doer != nil {
				eventsource.GetManager().SendMessage(ctx.Doer.ID, &eventsource.Event{
					Name: "logout",
					Data: ctx.Session.ID(),
				})
			}
			HandleSignOut(ctx)
		}
		u, err := saml_source.LogoutResponseURL(sp, req.ID, relayState)
		if err != nil {
			log.Error("SAML source %q: logout response: %v", authSource.Name, err)
			ctx.Redirect(setting.AppSubURL + "/")
			return
		}
		ctx.Redirect(u)
	default:
		ctx.Error(http.StatusBadRequest, "no SAMLRequest or SAMLResponse")
	}
}
