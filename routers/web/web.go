// Copyright 2017 The Gitea Authors. All rights reserved.
// Copyright 2024 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package web

import (
	gocontext "context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/perm"
	quota_model "forgejo.org/models/quota"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/modules/avatar"
	"forgejo.org/modules/log"
	"forgejo.org/modules/metrics"
	"forgejo.org/modules/public"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/storage"
	"forgejo.org/modules/structs"
	"forgejo.org/modules/templates"
	"forgejo.org/modules/validation"
	"forgejo.org/modules/web"
	"forgejo.org/modules/web/middleware"
	"forgejo.org/modules/web/routing"
	"forgejo.org/routers/common"
	"forgejo.org/routers/web/admin"
	"forgejo.org/routers/web/auth"
	"forgejo.org/routers/web/demo"
	"forgejo.org/routers/web/events"
	"forgejo.org/routers/web/explore"
	"forgejo.org/routers/web/feed"
	"forgejo.org/routers/web/healthcheck"
	"forgejo.org/routers/web/misc"
	"forgejo.org/routers/web/moderation"
	"forgejo.org/routers/web/org"
	org_setting "forgejo.org/routers/web/org/setting"
	"forgejo.org/routers/web/repo"
	"forgejo.org/routers/web/repo/actions"
	"forgejo.org/routers/web/repo/badges"
	repo_flags "forgejo.org/routers/web/repo/flags"
	repo_setting "forgejo.org/routers/web/repo/setting"
	shared_actions "forgejo.org/routers/web/shared/actions"
	"forgejo.org/routers/web/shared/project"
	shared_security "forgejo.org/routers/web/shared/security"
	"forgejo.org/routers/web/user"
	user_setting "forgejo.org/routers/web/user/setting"
	"forgejo.org/routers/web/user/setting/security"
	auth_service "forgejo.org/services/auth"
	auth_method "forgejo.org/services/auth/method"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
	"forgejo.org/services/lfs"

	_ "forgejo.org/modules/session" // to registers all internal adapters

	"code.forgejo.org/go-chi/binding"
	"code.forgejo.org/go-chi/captcha"
	chi_middleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/klauspost/compress/gzhttp"
	"github.com/prometheus/client_golang/prometheus"
)

var GzipMinSize = gzhttp.DefaultMinSize

// optionsCorsHandler return a http handler which sets CORS options if enabled by config, it blocks non-CORS OPTIONS requests.
func optionsCorsHandler() func(next http.Handler) http.Handler {
	var corsHandler func(next http.Handler) http.Handler
	if setting.CORSConfig.Enabled {
		corsHandler = cors.Handler(cors.Options{
			AllowedOrigins:   setting.CORSConfig.AllowDomain,
			AllowedMethods:   setting.CORSConfig.Methods,
			AllowCredentials: setting.CORSConfig.AllowCredentials,
			AllowedHeaders:   setting.CORSConfig.Headers,
			MaxAge:           int(setting.CORSConfig.MaxAge.Seconds()),
		})
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				if corsHandler != nil && r.Header.Get("Access-Control-Request-Method") != "" {
					corsHandler(next).ServeHTTP(w, r)
				} else {
					// it should explicitly deny OPTIONS requests if CORS handler is not executed, to avoid the next GET/POST handler being incorrectly called by the OPTIONS request
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
				return
			}
			// for non-OPTIONS requests, call the CORS handler to add some related headers like "Vary"
			if corsHandler != nil {
				corsHandler(next).ServeHTTP(w, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// Authentication methods that are applied to all the web URL routes.  They are processed in the order defined; an
// earlier authentication success would prevent later authentication methods from being attempted.
func buildAuthGroup() *auth_method.Group {
	group := auth_method.NewGroup()
	if setting.Service.EnableReverseProxyAuth {
		// reverseproxy should before Session, otherwise the header will be ignored if user has login
		group.Add(&auth_method.ReverseProxy{
			CreateSession: true,
		})
	}
	group.Add(&auth_method.Session{})
	return group
}

// Authentication methods that are applied to "mixed" web URL routes.  Mixed routes are those that are primarily
// designed for web browser access, but can also be accessed by API consumers.
func buildMixedAuthGroup() *auth_method.Group {
	group := auth_method.NewGroup()
	group.Add(&auth_method.OAuth2{})
	group.Add(&auth_method.AccessToken{
		PermitBasic:  true,
		PermitBearer: true,
	})
	group.Add(&auth_method.ActionRuntimeToken{})
	group.Add(&auth_method.ActionTaskToken{
		PermitBasic:  true,
		PermitBearer: true,
	})
	group.Add(&auth_method.AuthorizedIntegration{})
	if setting.Service.EnableReverseProxyAuth {
		group.Add(&auth_method.ReverseProxy{}) // reverseproxy should before Session, otherwise the header will be ignored if user has login
	}
	group.Add(&auth_method.Session{})
	group.Add(&auth_method.Basic{})
	return group
}

// Authentication methods that are applied to Git LFS HTTP routes.  They are processed in the order defined; an earlier
// authentication success would prevent later authentication methods from being attempted.
func buildGitLfsAuthGroup() *auth_method.Group {
	group := auth_method.NewGroup()
	group.Add(&auth_method.LFSToken{})
	group.Add(&auth_method.OAuth2{})
	group.Add(&auth_method.AccessToken{
		PermitBasic: true,
		// PermitBearer is left at default `false`.  This behaviour is maintained from when one auth method performed
		// all the "Basic ..." handling, and one performed all the "Bearer ..." handling, and access to LFS paths
		// weren't permitted in the bearer codepath.  There isn't a clear reason from Forgejo's perspective to deny
		// usage in this case, it's just maintained because it previously worked that way.
	})
	group.Add(&auth_method.ActionTaskToken{
		PermitBasic: true,
		// PermitBearer is left at default `false` -- same explanation as above for AccessToken.
	})
	group.Add(&auth_method.AuthorizedIntegration{
		// "Authorization: Basic ..." is easier to use for git operations, and already supported for other tokens, so it
		// is enabled for Authorized Integrations as well:
		PermitBasic: true,
	})
	if setting.Service.EnableReverseProxyAuth {
		// reverseproxy should before Session, otherwise the header will be ignored if user has login
		group.Add(&auth_method.ReverseProxy{
			CreateSession: true,
		})
	}
	group.Add(&auth_method.Basic{})
	return group
}

// Authentication methods that are applied to Git HTTP routes.  They are processed in the order defined; an earlier
// authentication success would prevent later authentication methods from being attempted.
func buildGitAuthGroup() *auth_method.Group {
	group := auth_method.NewGroup()
	group.Add(&auth_method.OAuth2{})
	group.Add(&auth_method.AccessToken{
		PermitBasic:  true,
		PermitBearer: true,
	})
	group.Add(&auth_method.ActionRuntimeToken{})
	group.Add(&auth_method.ActionTaskToken{
		PermitBasic:  true,
		PermitBearer: true,
	})
	group.Add(&auth_method.AuthorizedIntegration{
		// "Authorization: Basic ..." is easier to use for git operations, and already supported for other tokens, so it
		// is enabled for Authorized Integrations as well:
		PermitBasic: true,
	})
	if setting.Service.EnableReverseProxyAuth {
		// reverseproxy should before Session, otherwise the header will be ignored if user has login
		group.Add(&auth_method.ReverseProxy{
			CreateSession: true,
		})
	}
	group.Add(&auth_method.Basic{})
	return group
}

func webAuth(authMethod auth_service.Method) func(*context.Context) {
	return func(ctx *context.Context) {
		output := common.AuthShared(ctx.Base, ctx.Session, authMethod)
		var ar auth_service.AuthenticationResult
		switch v := output.(type) {
		case *auth_service.AuthenticationSuccess:
			ar = v.Result
		case *auth_service.AuthenticationNotAttempted:
			ar = &auth_service.UnauthenticatedResult{}
		case *auth_service.AuthenticationAttemptedIncorrectCredential:
			common.RecordAuthFailure(ctx.Base, v)
			if common.WriteIfRateLimited(ctx.Base, v.Error, false) {
				return
			}
			ctx.Error(http.StatusUnauthorized, ctx.Locale.TrString("auth.unauthorized_credentials", "https://codeberg.org/forgejo/forgejo/issues/2809"))
			return
		case *auth_service.AuthenticationError:
			// Don't reveal the internal server error details to the user as they may contain sensitive details -- log
			// the details, return a generic error.
			log.Error("internal error during authentication: %v", v.Error)
			ctx.ServerError("authentication error", errors.New("internal server error in authentication"))
			return
		default:
			ctx.ServerError("authentication error", errors.New("unexpected result from common.AuthShared"))
			return
		}
		if ar == nil {
			ctx.ServerError("nil authentication result", errors.New("nil authentication result"))
			return
		}
		ctx.Doer = ar.User()
		ctx.IsSigned = ar.User() != nil
		ctx.Authentication = ar
		common.SetAuditActor(ctx.Base, ar)
		if rp, ok := ar.(interface{ NewSession() bool }); ok && rp.NewSession() {
			auth_service.RecordSignIn(ctx, ctx.Doer, "reverse_proxy", "")
		}
		if ctx.Doer == nil && ctx.InteractiveReauthenticationPossible {
			// The request is not authenticated, and session authentication was attempted. Clear "uid" from the session.
			// The purpose of this behaviour isn't clear as it is retained through multiple refactorings, originally
			// introduced in https://codeberg.org/forgejo/forgejo/commit/17c5c654a57ecf51c8c7c8ecfc6c86ae313d4000; it
			// may not be meaningful with separated auth methods on different HTTP routes.  It is retained here as it
			// seems like a reasonable security precaution.
			//
			// Session value is only removed when InteractiveReauthenticationPossible is set, which indicates session
			// auth was attempted on this request.  Without this check, an in-browser extension using git http w/ basic
			// auth (example: Floccus) will clear the session every time it receives a 401 response (example: starting
			// an auth workflow).
			_ = ctx.Session.Delete("uid")
		}
	}
}

// verifyAuthWithOptions checks authentication according to options
func verifyAuthWithOptions(options *common.VerifyOptions) func(ctx *context.Context) {
	crossOriginProtection := http.NewCrossOriginProtection()
	return func(ctx *context.Context) {
		// Check prohibit login users.
		if ctx.IsSigned {
			if !ctx.Doer.IsActive && setting.Service.RegisterEmailConfirm {
				ctx.Data["Title"] = ctx.Tr("auth.active_your_account")
				ctx.HTML(http.StatusOK, "user/auth/activate")
				return
			}
			if !ctx.Doer.IsActive || ctx.Doer.ProhibitLogin {
				log.Info("Failed authentication attempt for %s from %s", ctx.Doer.Name, ctx.RemoteAddr())
				ctx.Data["Title"] = ctx.Tr("auth.prohibit_login")
				ctx.HTML(http.StatusOK, "user/auth/prohibit_login")
				return
			}

			if ctx.Doer.MustChangePassword {
				if ctx.Req.URL.Path != "/user/settings/change_password" {
					if strings.HasPrefix(ctx.Req.UserAgent(), "git") {
						ctx.Error(http.StatusUnauthorized, ctx.Locale.TrString("auth.must_change_password"))
						return
					}
					ctx.Data["Title"] = ctx.Tr("auth.must_change_password")
					ctx.Data["ChangePasscodeLink"] = setting.AppSubURL + "/user/change_password"
					if ctx.Req.URL.Path != "/user/events" {
						middleware.SetRedirectToCookie(ctx.Resp, setting.AppSubURL+ctx.Req.URL.RequestURI())
					}
					ctx.Redirect(setting.AppSubURL + "/user/settings/change_password")
					return
				}
			} else if ctx.Req.URL.Path == "/user/settings/change_password" {
				if ctx.Doer.MustHaveTwoFactor() {
					ctx.Redirect(setting.AppSubURL + "/user/settings/security")
					return
				}
				// make sure that the form cannot be accessed by users who don't need this
				ctx.Redirect(setting.AppSubURL + "/")
				return
			} else if ctx.Doer.MustHaveTwoFactor() && !strings.HasPrefix(ctx.Req.URL.Path, "/user/settings/security") {
				hasTwoFactor, err := auth_model.HasTwoFactorByUID(ctx, ctx.Doer.ID)
				if err != nil {
					log.Error("Error getting 2fa: %s", err)
					ctx.Error(http.StatusInternalServerError, "HasTwoFactorByUID", err.Error())
					return
				}
				if !hasTwoFactor {
					ctx.Redirect(setting.AppSubURL + "/user/settings/security")
					return
				}
			}
		}

		// Redirect to dashboard (or alternate location) if user tries to visit any non-login page.
		if options.SignOutRequired && ctx.IsSigned && ctx.Req.URL.RequestURI() != "/" {
			ctx.RedirectToFirst(ctx.FormString("redirect_to"))
			return
		}

		if !options.SignOutRequired && !options.DisableCSRF {
			if err := crossOriginProtection.Check(ctx.Req); err != nil {
				http.Error(ctx.Resp, err.Error(), http.StatusForbidden)
				return
			}
		}

		if options.SignInRequired != nil && options.SignInRequired() {
			if !ctx.IsSigned {
				if ctx.Req.URL.Path != "/user/events" {
					middleware.SetRedirectToCookie(ctx.Resp, setting.AppSubURL+ctx.Req.URL.RequestURI())
				}
				ctx.Redirect(setting.AppSubURL + "/user/login")
				return
			} else if !ctx.Doer.IsActive && setting.Service.RegisterEmailConfirm {
				ctx.Data["Title"] = ctx.Tr("auth.active_your_account")
				ctx.HTML(http.StatusOK, "user/auth/activate")
				return
			}
		}

		// Redirect to log in page if auto-signin info is provided and has not signed in.
		if !options.SignOutRequired && !ctx.IsSigned && ctx.InteractiveReauthenticationPossible &&
			ctx.GetSiteCookie(setting.CookieRememberName) != "" {
			if ctx.Req.URL.Path != "/user/events" {
				middleware.SetRedirectToCookie(ctx.Resp, setting.AppSubURL+ctx.Req.URL.RequestURI())
			}
			ctx.Redirect(setting.AppSubURL + "/user/login")
			return
		}

		if options.AdminRequired {
			if !ctx.Doer.IsAdmin {
				ctx.Error(http.StatusForbidden)
				return
			}
			ctx.Data["PageIsAdmin"] = true
			admin.SetSecuritySearchNav(ctx)
		}
	}
}

func ctxDataSet(args ...any) func(ctx *context.Context) {
	return func(ctx *context.Context) {
		for i := 0; i < len(args); i += 2 {
			ctx.Data[args[i].(string)] = args[i+1]
		}
	}
}

// Routes returns all web routes
func Routes() *web.Route {
	routes := web.NewRoute()

	routes.Use(chi_middleware.GetHead)
	routes.Use(context.RepoGroupResolver)

	routes.Head("/", misc.DummyOK) // for health check - doesn't need to be passed through gzip handler
	routes.Methods("GET, HEAD", "/assets/ide/*", public.IDEFileHandlerFunc())
	routes.Methods("GET, HEAD, OPTIONS", "/assets/*", optionsCorsHandler(), public.FileHandlerFunc())
	routes.Methods("GET, HEAD", "/avatars/*", resizingHandler("avatars", storage.Avatars, avatar.AllowedResizedAvatarSizes))
	routes.Methods("GET, HEAD", "/repo-avatars/*", resizingHandler("repo-avatars", storage.RepoAvatars, avatar.AllowedResizedAvatarSizes))
	routes.Methods("GET, HEAD", "/apple-touch-icon.png", misc.StaticRedirect("/assets/img/apple-touch-icon.png"))
	routes.Methods("GET, HEAD", "/apple-touch-icon-precomposed.png", misc.StaticRedirect("/assets/img/apple-touch-icon.png"))
	routes.Methods("GET, HEAD", "/favicon.ico", misc.StaticRedirect("/assets/img/favicon.png"))

	_ = templates.HTMLRenderer()

	var gzipMid any
	if setting.EnableGzip {
		wrapper, err := gzhttp.NewWrapper(gzhttp.RandomJitter(32, 0, false), gzhttp.MinSize(GzipMinSize))
		if err != nil {
			log.Fatal("gzhttp.NewWrapper failed: %v", err)
		}
		gzipMid = wrapper
	}

	if setting.Service.EnableCaptcha {
		// The captcha http.Handler should only fire on /captcha/* so we can just mount this on that url
		routes.Methods("GET,HEAD", "/captcha/*", gzipMid, captcha.Server(captcha.StdWidth, captcha.StdHeight).ServeHTTP)
	}

	if setting.Metrics.Enabled {
		prometheus.MustRegister(metrics.NewCollector(), metrics.NewLogShippingCollector(), metrics.NewAuditCollector())
		routes.Get("/metrics", gzipMid, Metrics)
	}

	routes.Methods("GET,HEAD", "/robots.txt", gzipMid, misc.RobotsTxt)
	routes.Methods("GET,HEAD", "/llms.txt", gzipMid, misc.LlmsTxt)
	routes.Methods("GET,HEAD", "/manifest.json", gzipMid, misc.ManifestJSON)
	routes.Get("/ssh_info", misc.SSHInfo)
	routes.Get("/api/healthz", healthcheck.Check)

	if setting.API.EnableSwagger {
		routes.Group("", func() {
			// Note: The route is here but no in API routes because it renders a web page
			routes.Get("/api/swagger", misc.Swagger) // Render V1 by default
			routes.Get("/api/forgejo/swagger", misc.SwaggerForgejo)
		}, gzipMid, context.Contexter())
	}

	// When the session provider is "memory", the session middleware contains its in-memory storage -- don't create
	// multiple instances of the middleware for the different routing groups or else they'll have independent session
	// storage, preventing user sessions from working across them.
	sessioner := common.Sessioner()

	routes.Group("",
		func() {
			registerRoutes(routes)
		},
		gzipMid, sessioner, context.Contexter(), webAuth(buildAuthGroup()), common.RateLimit(ratelimit.Web), common.MaintenanceWeb, common.IPAllowlistWeb, common.CredentialUsed("web"),
		// TODO: GetNotificationCount & GetActiveStopwatch really seem like things that could be folded into Contexter or as helper functions
		user.GetNotificationCount, repo.GetActiveStopwatch, user.GetAnnouncements,
		goGet)
	routes.Group("",
		func() {
			registerMixedRoutes(routes)
		}, gzipMid, sessioner, context.Contexter(), webAuth(buildMixedAuthGroup()), common.RateLimit(ratelimit.Web), common.MaintenanceWeb, common.IPAllowlistMixed, common.CredentialUsed("web"), goGet)
	routes.Group("",
		func() {
			registerGitLFSRoutes(routes)
		}, gzipMid, sessioner, context.Contexter(), webAuth(buildGitLfsAuthGroup()), common.RateLimit(ratelimit.Git), common.MaintenanceGit, common.IPAllowlistPlain(setting.IPAllowlistSurfaceGit), common.CredentialUsed("lfs"), goGet)
	routes.Group("",
		func() {
			registerGitRoutes(routes)
		}, gzipMid, sessioner, context.Contexter(), webAuth(buildGitAuthGroup()), common.RateLimit(ratelimit.Git), common.MaintenanceGit, common.IPAllowlistPlain(setting.IPAllowlistSurfaceGit), common.CredentialUsed("git"), goGet)

	// The only endpoint which can only be accessed with the OAuth2 authentication method is /userinfo, extracted here
	// so that other auth methods can't be applied to it
	routes.Methods(
		"GET, POST, OPTIONS",
		"/login/oauth/userinfo",
		gzipMid, sessioner, context.Contexter(),
		oauth2Enabled, optionsCorsHandler(), ignoreCSRF, webAuth(&auth_method.OAuth2{}), common.IPAllowlistMixed,
		auth.InfoOAuth,
	)

	routes.NotFound(
		gzipMid, sessioner, context.Contexter(), webAuth(buildAuthGroup()), common.RateLimit(ratelimit.Web), common.MaintenanceWeb, common.IPAllowlistWeb,
		// TODO: GetNotificationCount & GetActiveStopwatch really seem like things that could be folded into Contexter or as helper functions
		user.GetNotificationCount, repo.GetActiveStopwatch, user.GetAnnouncements,
		goGet,
		func(w http.ResponseWriter, req *http.Request) {
			ctx := context.GetWebContext(req)
			if ctx == nil {
				panic("missing middleware context.Contexter()")
			}
			if ctx.ResolveRepoGroupPath() {
				return
			}
			ctx.NotFound("", nil)
		},
	)

	return routes
}

var (
	ignoreCSRF = verifyAuthWithOptions(&common.VerifyOptions{DisableCSRF: true})
	reqSignIn  = verifyAuthWithOptions(&common.VerifyOptions{SignInRequired: func() bool { return true }})
	reqSignOut = verifyAuthWithOptions(&common.VerifyOptions{SignOutRequired: true})
	// TODO: rename them to "optSignIn", which means that the "sign-in" could be optional, depends on the VerifyOptions (RequireSignInView)
	ignSignIn = verifyAuthWithOptions(&common.VerifyOptions{
		SignInRequired: func() bool {
			return setting.Service.RequireSignInView
		},
	})
	ignExploreSignIn = verifyAuthWithOptions(&common.VerifyOptions{
		SignInRequired: func() bool {
			return setting.Service.RequireSignInView || setting.Service.Explore.RequireSigninView
		},
	})

	reqRepoAdmin               = context.RequireRepoAdmin()
	reqRepoCodeWriter          = context.RequireRepoWriter(unit.TypeCode)
	canEnableEditor            = context.CanEnableEditor()
	reqRepoCodeReader          = context.RequireRepoReader(unit.TypeCode)
	reqRepoReleaseWriter       = context.RequireRepoWriter(unit.TypeReleases)
	reqRepoReleaseReader       = context.RequireRepoReader(unit.TypeReleases)
	reqRepoWikiWriter          = context.RequireRepoWriter(unit.TypeWiki)
	reqRepoIssueReader         = context.RequireRepoReader(unit.TypeIssues)
	reqRepoPullsReader         = context.RequireRepoReader(unit.TypePullRequests)
	reqRepoIssuesOrPullsWriter = context.RequireRepoWriterOr(unit.TypeIssues, unit.TypePullRequests)
	reqRepoIssuesOrPullsReader = context.RequireRepoReaderOr(unit.TypeIssues, unit.TypePullRequests)
	reqRepoProjectsReader      = context.RequireRepoReader(unit.TypeProjects)
	reqRepoProjectsWriter      = context.RequireRepoWriter(unit.TypeProjects)
	reqRepoActionsReader       = context.RequireRepoReader(unit.TypeActions)
	reqRepoActionsWriter       = context.RequireRepoWriter(unit.TypeActions)
	reqRepoDelegateActionTrust = context.RequireRepoDelegateActionTrust()

	linkAccountEnabled = func(ctx *context.Context) {
		if !setting.Service.EnableOpenIDSignIn && !setting.Service.EnableOpenIDSignUp && !setting.OAuth2.Enabled {
			ctx.Error(http.StatusForbidden)
			return
		}
	}

	requiredTwoFactor = func(ctx *context.Context) {
		if !ctx.Doer.MustHaveTwoFactor() {
			return
		}

		hasTwoFactor, err := auth_model.HasTwoFactorByUID(ctx, ctx.Doer.ID)
		if err != nil {
			ctx.Error(http.StatusInternalServerError, fmt.Sprintf("Error getting 2fa: %s", err))
			return
		}
		ctx.Data["MustEnableTwoFactor"] = !hasTwoFactor
		ctx.Data["HideNavbarLinks"] = !hasTwoFactor
	}

	openIDSignInEnabled = func(ctx *context.Context) {
		if !setting.Service.EnableOpenIDSignIn {
			ctx.Error(http.StatusForbidden)
			return
		}
	}

	openIDSignUpEnabled = func(ctx *context.Context) {
		if !setting.Service.EnableOpenIDSignUp {
			ctx.Error(http.StatusForbidden)
			return
		}
	}

	oauth2Enabled = func(ctx *context.Context) {
		if !setting.OAuth2.Enabled {
			ctx.Error(http.StatusForbidden)
			return
		}
	}

	reqMilestonesDashboardPageEnabled = func(ctx *context.Context) {
		if !setting.Service.ShowMilestonesDashboardPage {
			ctx.Error(http.StatusForbidden)
			return
		}
	}

	// webhooksEnabled requires webhooks to be enabled by admin.
	webhooksEnabled = func(ctx *context.Context) {
		if setting.DisableWebhooks {
			ctx.Error(http.StatusForbidden)
			return
		}
	}

	federationEnabled = func(ctx *context.Context) {
		if !setting.Federation.Enabled {
			ctx.Error(http.StatusNotFound)
			return
		}
	}

	sitemapEnabled = func(ctx *context.Context) {
		if !setting.Other.EnableSitemap {
			ctx.Error(http.StatusNotFound)
			return
		}
	}

	packagesEnabled = func(ctx *context.Context) {
		if !setting.Packages.Enabled {
			ctx.Error(http.StatusForbidden)
			return
		}
	}

	feedEnabled = func(ctx *context.Context) {
		if !setting.Other.EnableFeed {
			ctx.Error(http.StatusNotFound)
			return
		}
	}

	reqUnitAccess = func(unitType unit.Type, accessMode perm.AccessMode, ignoreGlobal bool) func(ctx *context.Context) {
		return func(ctx *context.Context) {
			// only check global disabled units when ignoreGlobal is false
			if !ignoreGlobal && unitType.UnitGlobalDisabled() {
				ctx.NotFound(unitType.String(), nil)
				return
			}

			if ctx.ContextUser == nil {
				ctx.NotFound(unitType.String(), nil)
				return
			}

			if ctx.ContextUser.IsOrganization() {
				if ctx.Org.Organization.UnitPermission(ctx, ctx.Doer, unitType) < accessMode {
					ctx.NotFound(unitType.String(), nil)
					return
				}
			}
		}
	}
)

// registerRoutes register routes
func registerRoutes(m *web.Route) {
	validation.AddBindingRules()

	addSettingsVariablesRoutes := func() {
		m.Group("/variables", func() {
			m.Get("", repo_setting.Variables)
			m.Post("/new", web.Bind(forms.EditVariableForm{}), repo_setting.VariableCreate)
			m.Post("/{variable_id}/edit", web.Bind(forms.EditVariableForm{}), repo_setting.VariableUpdate)
			m.Post("/{variable_id}/delete", repo_setting.VariableDelete)
		})
	}

	addSettingsSecretsRoutes := func() {
		m.Group("/secrets", func() {
			m.Get("", repo_setting.Secrets)
			m.Post("", web.Bind(forms.CreateSecretForm{}), repo_setting.SecretsCreatePost)
			m.Post("/{secret_id}/edit", web.Bind(forms.EditSecretForm{}), repo_setting.SecretsEditPost)
			m.Post("/{secret_id}/delete", repo_setting.SecretsDeletePost)
		})
	}

	// the environments of a repository and of an organization share the handlers (repo_setting.RequireEnvironmentManager)
	addSettingsEnvironmentsRoutes := func(notArchived func(*context.Context)) {
		m.Group("/environments", func() {
			m.Get("", repo_setting.Environments)
			m.Combo("/new").Get(repo_setting.EnvironmentNew).
				Post(notArchived, web.Bind(forms.EnvironmentForm{}), repo_setting.EnvironmentNewPost)
			m.Group("/{environment_id}", func() {
				m.Combo("").Get(repo_setting.EnvironmentEdit).
					Post(notArchived, web.Bind(forms.EnvironmentForm{}), repo_setting.EnvironmentEditPost)
				m.Post("/delete", notArchived, repo_setting.EnvironmentDeletePost)
				m.Group("/secrets", func() {
					m.Post("", web.Bind(forms.CreateSecretForm{}), repo_setting.EnvironmentSecretCreate)
					m.Post("/{secret_id}/edit", web.Bind(forms.EditSecretForm{}), repo_setting.EnvironmentSecretEdit)
					m.Post("/{secret_id}/delete", repo_setting.EnvironmentSecretDelete)
				}, notArchived)
				m.Group("/variables", func() {
					m.Post("/new", web.Bind(forms.EditVariableForm{}), repo_setting.EnvironmentVariableCreate)
					m.Post("/{variable_id}/edit", web.Bind(forms.EditVariableForm{}), repo_setting.EnvironmentVariableUpdate)
					m.Post("/{variable_id}/delete", repo_setting.EnvironmentVariableDelete)
				}, notArchived)
			}, repo_setting.EnvironmentAssignment)
		}, repo_setting.RequireEnvironmentManager)
	}

	addSettingsRunnersRoutes := func() {
		m.Group("/runners", func() {
			m.Get("", shared_actions.RunnersList)
			m.Combo("/new").
				Get(shared_actions.RunnerCreate).
				Post(web.Bind(forms.CreateRunnerForm{}), shared_actions.RunnerCreatePost)
			m.Get("/{runnerid}", shared_actions.RunnerDetails)
			m.Combo("/{runnerid}/edit").
				Get(shared_actions.RunnerEdit).
				Post(web.Bind(forms.EditRunnerForm{}), shared_actions.RunnerEditPost)
			m.Post("/{runnerid}/delete", shared_actions.RunnerDeletePost)
			m.Get("/reset_registration_token", shared_actions.RunnerResetRegistrationToken)
		})
	}

	// FIXME: not all routes need go through same middleware.
	// Especially some AJAX requests, we can reduce middleware number to improve performance.

	m.Get("/", Home)
	m.Get("/sitemap.xml", sitemapEnabled, ignExploreSignIn, HomeSitemap)
	m.Group("/.well-known", func() {
		m.Get("/openid-configuration", auth.OIDCWellKnown)
		m.Group("", func() {
			m.Get("/nodeinfo", NodeInfoLinks)
			m.Get("/webfinger", WebfingerQuery)
		}, federationEnabled)
		m.Get("/change-password", func(ctx *context.Context) {
			ctx.Redirect(setting.AppSubURL + "/user/settings/account")
		})
		m.Methods("GET, HEAD", "/*", public.FileHandlerFunc())
	}, optionsCorsHandler())

	m.Group("/explore", func() {
		m.Get("", func(ctx *context.Context) {
			ctx.Redirect(setting.AppSubURL + "/explore/repos")
		})
		m.Get("/repos", explore.Repos)
		m.Get("/repos/sitemap-{idx}.xml", sitemapEnabled, explore.Repos)
		m.Get("/users", explore.Users)
		m.Get("/users/sitemap-{idx}.xml", sitemapEnabled, explore.Users)
		m.Get("/organizations", explore.Organizations)
		m.Get("/organizations/sitemap-{idx}.xml", sitemapEnabled, explore.Organizations)
		m.Get("/groups", explore.RepoGroups)
		m.Get("/code", func(ctx *context.Context) {
			if unit.TypeCode.UnitGlobalDisabled() {
				ctx.NotFound(unit.TypeCode.String(), nil)
				return
			}
		}, explore.Code)
		m.Get("/topics/search", explore.TopicSearch)
	}, ignExploreSignIn)
	m.Group("/issues", func() {
		m.Get("", user.Issues)
		m.Get("/search", repo.SearchIssues)
	}, reqSignIn)

	if setting.Moderation.Enabled {
		m.Get("/report_abuse", reqSignIn, moderation.NewReport)
		m.Post("/report_abuse", reqSignIn, web.Bind(forms.ReportAbuseForm{}), moderation.CreatePost)
	}

	m.Get("/pulls", reqSignIn, user.Pulls)
	m.Get("/milestones", reqSignIn, reqMilestonesDashboardPageEnabled, user.Milestones)

	// ***** START: User *****
	// "user/login" doesn't need signOut, then logged-in users can still access this route for redirection purposes by "/user/login?redirec_to=..."
	m.Get("/user/login", auth.SignIn)
	m.Group("/user", func() {
		m.Post("/login", web.Bind(forms.SignInForm{}), auth.SignInPost)
		m.Group("", func() {
			m.Combo("/login/openid").
				Get(auth.SignInOpenID).
				Post(web.Bind(forms.SignInOpenIDForm{}), auth.SignInOpenIDPost)
		}, openIDSignInEnabled)
		m.Group("/openid", func() {
			m.Combo("/connect").
				Get(auth.ConnectOpenID).
				Post(web.Bind(forms.ConnectOpenIDForm{}), auth.ConnectOpenIDPost)
			m.Group("/register", func() {
				m.Combo("").
					Get(auth.RegisterOpenID, openIDSignUpEnabled).
					Post(web.Bind(forms.SignUpOpenIDForm{}), auth.RegisterOpenIDPost)
			}, openIDSignUpEnabled)
		}, openIDSignInEnabled)
		m.Get("/sign_up", auth.SignUp)
		m.Post("/sign_up", common.RateLimitAuthIP, web.Bind(forms.RegisterForm{}), auth.SignUpPost)
		m.Get("/link_account", linkAccountEnabled, auth.LinkAccount)
		m.Post("/link_account_signin", linkAccountEnabled, web.Bind(forms.SignInForm{}), auth.LinkAccountPostSignIn)
		m.Post("/link_account_signup", linkAccountEnabled, web.Bind(forms.RegisterForm{}), auth.LinkAccountPostRegister)
		m.Group("/two_factor", func() {
			m.Get("", auth.TwoFactor)
			m.Post("", web.Bind(forms.TwoFactorAuthForm{}), auth.TwoFactorPost)
			m.Get("/scratch", auth.TwoFactorScratch)
			m.Post("/scratch", web.Bind(forms.TwoFactorScratchAuthForm{}), auth.TwoFactorScratchPost)
		})
		m.Group("/webauthn", func() {
			m.Get("", auth.WebAuthn)
			m.Get("/assertion", auth.WebAuthnLoginAssertion)
			m.Post("/assertion", auth.WebAuthnLoginAssertionPost)
		})
	}, reqSignOut)

	m.Any("/user/events", routing.MarkLongPolling, events.Events)

	m.Group("/login/oauth", func() {
		m.Group("", func() {
			m.Get("/authorize", web.Bind(forms.AuthorizationForm{}), auth.AuthorizeOAuth)
			m.Post("/grant", web.Bind(forms.GrantApplicationForm{}), auth.GrantApplicationOAuth)
			// TODO manage redirection
			m.Post("/authorize", web.Bind(forms.AuthorizationForm{}), auth.AuthorizeOAuth)
		}, reqSignIn)

		m.Group("", func() {
			m.Methods("POST, OPTIONS", "/access_token", web.Bind(forms.AccessTokenForm{}), auth.AccessTokenOAuth)
			m.Methods("GET, OPTIONS", "/keys", auth.OIDCKeys)
			m.Methods("POST, OPTIONS", "/introspect", web.Bind(forms.IntrospectTokenForm{}), auth.IntrospectOAuth)
		}, optionsCorsHandler(), ignoreCSRF)
	}, oauth2Enabled)

	m.Group("/user/settings", func() {
		m.Get("", user_setting.Profile)
		m.Post("", web.Bind(forms.UpdateProfileForm{}), user_setting.ProfilePost)
		m.Get("/change_password", auth.MustChangePassword)
		m.Post("/change_password", web.Bind(forms.MustChangePasswordForm{}), auth.MustChangePasswordPost)
		m.Post("/avatar", web.Bind(forms.AvatarForm{}), user_setting.AvatarPost)
		m.Post("/avatar/delete", user_setting.DeleteAvatar)
		m.Group("/account", func() {
			m.Combo("").Get(user_setting.Account).Post(web.Bind(forms.ChangePasswordForm{}), user_setting.AccountPost)
			m.Post("/email", web.Bind(forms.AddEmailForm{}), user_setting.EmailPost)
			m.Post("/email/delete", user_setting.DeleteEmail)
			m.Post("/delete", user_setting.DeleteAccount)
		})
		m.Combo("/notifications").Get(user_setting.Notifications).Post(user_setting.NotificationsPost)
		m.Group("/appearance", func() {
			m.Get("", user_setting.Appearance)
			m.Post("/language", web.Bind(forms.UpdateLanguageForm{}), user_setting.UpdateUserLang)
			m.Post("/time_zone", web.Bind(forms.UpdateTimeZoneForm{}), user_setting.UpdateUserTimeZone)
			m.Post("/hints", web.Bind(forms.UpdateHintsForm{}), user_setting.UpdateUserHints)
			m.Post("/hidden_comments", user_setting.UpdateUserHiddenComments)
			m.Post("/theme", web.Bind(forms.UpdateThemeForm{}), user_setting.UpdateUIThemePost)
		})
		m.Group("/security", func() {
			m.Get("", security.Security)
			m.Group("/two_factor", func() {
				m.Post("/regenerate_scratch", security.RegenerateScratchTwoFactor)
				m.Post("/disable", security.DisableTwoFactor)
				m.Get("/enroll", security.EnrollTwoFactor)
				m.Post("/enroll", web.Bind(forms.TwoFactorAuthForm{}), security.EnrollTwoFactorPost)
				m.Get("/reenroll", security.ReenrollTwoFactor)
				m.Post("/reenroll", web.Bind(forms.TwoFactorAuthForm{}), security.ReenrollTwoFactorPost)
			})
			m.Group("/webauthn", func() {
				m.Post("/request_register", web.Bind(forms.WebauthnRegistrationForm{}), security.WebAuthnRegister)
				m.Post("/register", security.WebauthnRegisterPost)
				m.Post("/delete", web.Bind(forms.WebauthnDeleteForm{}), security.WebauthnDelete)
			})
			m.Group("/openid", func() {
				m.Post("", web.Bind(forms.AddOpenIDForm{}), security.OpenIDPost)
				m.Post("/delete", security.DeleteOpenID)
				m.Post("/toggle_visibility", security.ToggleOpenIDVisibility)
			}, openIDSignInEnabled)
			m.Post("/account_link", linkAccountEnabled, security.DeleteAccountLink)
		}, requiredTwoFactor)

		m.Group("/applications", func() {
			// oauth2 applications
			m.Group("/oauth2", func() {
				m.Get("/{id}", user_setting.OAuth2ApplicationShow)
				m.Post("/{id}", web.Bind(forms.EditOAuth2ApplicationForm{}), user_setting.OAuthApplicationsEdit)
				m.Post("/{id}/regenerate_secret", user_setting.OAuthApplicationsRegenerateSecret)
				m.Post("", web.Bind(forms.EditOAuth2ApplicationForm{}), user_setting.OAuthApplicationsPost)
				m.Post("/{id}/delete", user_setting.DeleteOAuth2Application)
				m.Post("/{id}/revoke/{grantId}", user_setting.RevokeOAuth2Grant)
			}, oauth2Enabled)

			m.Get("", user_setting.Applications)
		})

		m.Group("/authorized-integrations", func() {
			m.Group("/{ui}", func() {
				m.Combo("/new").
					Get(user_setting.NewAuthorizedIntegration).
					Post(user_setting.NewAuthorizedIntegrationPost)
				m.Combo("/{id}").
					Get(user_setting.EditAuthorizedIntegration).
					Post(user_setting.EditAuthorizedIntegrationPost)
			}, user_setting.BindAuthorizedIntegrationUI, user_setting.DynamicBindAuthorizedIntegrationForm)
			m.Post("/delete", user_setting.DeleteAuthorizedIntegration)
			m.Get("", user_setting.ListAuthorizedIntegrations)
		})

		m.Combo("/keys").Get(user_setting.Keys).
			Post(web.Bind(forms.AddKeyForm{}), user_setting.KeysPost)
		m.Post("/keys/delete", user_setting.DeleteKey)
		m.Group("/keys/tokens", func() {
			m.Combo("/new").
				Get(web.Bind(forms.NewAccessTokenGetForm{}), user_setting.AccessTokenCreate).
				Post(web.Bind(forms.NewAccessTokenPostForm{}), user_setting.AccessTokenCreatePost)
			m.Post("/delete", user_setting.DeleteAccessToken)
			m.Post("/regenerate", user_setting.RegenerateAccessToken)
		})
		m.Group("/packages", func() {
			m.Get("", user_setting.Packages)
			m.Group("/rules", func() {
				m.Group("/add", func() {
					m.Get("", user_setting.PackagesRuleAdd)
					m.Post("", web.Bind(forms.PackageCleanupRuleForm{}), user_setting.PackagesRuleAddPost)
				})
				m.Group("/{id}", func() {
					m.Get("", user_setting.PackagesRuleEdit)
					m.Post("", web.Bind(forms.PackageCleanupRuleForm{}), user_setting.PackagesRuleEditPost)
					m.Get("/preview", user_setting.PackagesRulePreview)
				})
			})
			m.Group("/cargo", func() {
				m.Post("/initialize", user_setting.InitializeCargoIndex)
				m.Post("/rebuild", user_setting.RebuildCargoIndex)
			})
			m.Post("/chef/regenerate_keypair", user_setting.RegenerateChefKeyPair)
		}, packagesEnabled)

		m.Group("/actions", func() {
			m.Get("", user_setting.RedirectToDefaultSetting)
			addSettingsRunnersRoutes()
			addSettingsSecretsRoutes()
			addSettingsVariablesRoutes()
		}, actions.MustEnableActions)

		m.Get("/organization", user_setting.Organization)
		m.Get("/repos", user_setting.Repos)
		m.Post("/repos/unadopted", user_setting.AdoptOrDeleteRepository)

		m.Group("/hooks", func() {
			m.Get("", user_setting.Webhooks)
			m.Post("/delete", user_setting.DeleteWebhook)
			m.Get("/{type}/new", repo_setting.WebhookNew)
			m.Post("/{type}/new", repo_setting.WebhookCreate)
			m.Group("/{id}", func() {
				m.Get("", repo_setting.WebhookEdit)
				m.Post("", repo_setting.WebhookUpdate)
				m.Post("/replay/{uuid}", repo_setting.WebhookReplay)
			})
		}, webhooksEnabled)

		m.Group("/blocked_users", func() {
			m.Get("", user_setting.BlockedUsers)
			m.Post("/unblock", user_setting.UnblockUser)
		})
		m.Get("/storage_overview", user_setting.StorageOverview)
	}, reqSignIn, ctxDataSet("PageIsUserSettings", true, "EnablePackages", setting.Packages.Enabled, "EnableQuota", setting.Quota.Enabled))

	m.Group("/user", func() {
		m.Get("/activate", auth.Activate)
		m.Post("/activate", common.RateLimitAuthIP, auth.ActivatePost)
		m.Any("/activate_email", auth.ActivateEmail)
		m.Get("/avatar/{username}/{size}", user.AvatarByUserName)
		m.Get("/recover_account", auth.ResetPasswd)
		m.Post("/recover_account", common.RateLimitAuthIP, auth.ResetPasswdPost)
		m.Get("/forgot_password", auth.ForgotPasswd)
		m.Post("/forgot_password", common.RateLimitAuthIP, auth.ForgotPasswdPost)
		m.Post("/logout", auth.SignOut)
		m.Get("/task/{task}", reqSignIn, user.TaskStatus)
		m.Get("/stopwatches", reqSignIn, user.GetStopwatches)
		m.Get("/search_candidates", ignExploreSignIn, user.SearchCandidates)
		m.Group("/oauth2", func() {
			m.Get("/{provider}", auth.SignInOAuth)
			m.Get("/{provider}/callback", auth.SignInOAuthCallback)
		})
		m.Group("/saml/{source}", func() {
			m.Get("/metadata", auth.SAMLMetadata)
			m.Get("/login", auth.SAMLSignIn)
			m.Post("/acs", auth.SAMLACS)
			m.Get("/slo", auth.SAMLSLO)
		})
	})
	// ***** END: User *****

	m.Get("/avatar/{hash}", user.AvatarByEmailHash)

	adminReq := verifyAuthWithOptions(&common.VerifyOptions{SignInRequired: func() bool { return true }, AdminRequired: true})

	// ***** START: Admin *****
	// the audit log is outside adminReq for the auditor; only GET routes may be (TestAdminAuditRoutes)
	m.Get("/admin/audit", reqSignIn, admin.AuditReq, admin.Audit)
	m.Get("/admin/config/dependency-graph", reqSignIn, admin.AuditReq, admin.DependencyGraph)
	m.Get("/admin/config/secret-scanning", reqSignIn, admin.AuditReq, admin.SecretScanning)
	m.Get("/admin/security/patterns", reqSignIn, admin.AuditReq, admin.SecretPatterns) // read-only for auditors; changes are below
	// the secret alerts of every repository: site admins and auditors, while secret scanning is on
	m.Group("/admin/security/secrets", func() {
		m.Get("", admin.AuditReq, admin.SecretAlerts) // a banner while secret scanning is off
		m.Post("/export", admin.AuditExportReq, admin.MustEnableSecretAlerts, common.RateLimitHeavy, admin.SecretAlertsExport)
	}, reqSignIn)
	// the dependency and vulnerability search is read-only: the auditor searches and, as the audited download is no
	// change, posts it too (TestAdminAuditRoutes)
	m.Group("/admin/config/dependency-graph", func() {
		m.Get("/vulnerabilities", admin.AuditReq, admin.MustEnableSecuritySearch, admin.SecurityVulnerabilities)
		m.Get("/dependencies", admin.AuditReq, admin.MustEnableSecuritySearch, admin.SecurityDependencies)
		m.Post("/vulnerabilities/export", admin.AuditExportReq, admin.MustEnableSecuritySearch, common.RateLimitHeavy, admin.SecurityVulnerabilitiesExport)
		m.Post("/dependencies/export", admin.AuditExportReq, admin.MustEnableSecuritySearch, common.RateLimitHeavy, admin.SecurityDependenciesExport)
	}, reqSignIn)
	m.Group("/admin", func() {
		m.Get("", admin.Dashboard)
		m.Get("/system_status", admin.SystemStatus)
		m.Post("", web.Bind(forms.AdminDashboardForm{}), admin.DashboardPost)
		m.Combo("/maintenance").Get(admin.Maintenance).Post(admin.MaintenancePost)
		m.Combo("/webhook-types").Get(admin.WebhookTypes).Post(admin.WebhookTypesPost)
		m.Combo("/repo-units").Get(admin.RepoUnits).Post(admin.RepoUnitsPost)
		m.Combo("/audit/retention").Get(admin.AuditRetention).Post(admin.AuditRetentionPost)
		m.Combo("/personal-repos").Get(admin.PersonalRepos).Post(admin.PersonalReposPost)
		m.Combo("/ip-allowlist").Get(admin.IPAllowlist).Post(admin.IPAllowlistPost)
		m.Group("/log-shipping", func() {
			m.Get("", admin.LogShipping)
			m.Post("/destinations", admin.LogShippingPost)
			m.Group("/destinations/{id}", func() {
				m.Combo("").Get(admin.EditLogShipping).Post(admin.LogShippingPost)
				m.Post("/delete", admin.LogShippingDelete)
				m.Post("/test", admin.LogShippingTest)
			})
		})

		if setting.Database.Type.IsMySQL() {
			m.Get("/self_check", admin.SelfCheck)
		}

		m.Group("/config", func() {
			m.Get("", admin.Config)
			m.Post("", admin.ChangeConfig)
			m.Post("/test_mail", admin.SendTestMail)
			m.Post("/test_cache", admin.TestCache)
			m.Get("/settings", admin.ConfigSettings)
			m.Post("/dependency-graph", admin.DependencyGraphPost)
			m.Post("/dependency-graph/update-advisories", admin.DependencyGraphUpdateAdvisories)
			m.Post("/dependency-graph/settings", admin.DependencyGraphSettingsPost)
			m.Post("/dependency-graph/test-connection", admin.DependencyGraphTestConnection)
			m.Post("/secret-scanning/switches", admin.SecretScanningSwitchesPost)
			m.Post("/secret-scanning/limits", admin.SecretScanningLimitsPost)
		})

		// add, test and rename run the engine's checks (rename: the known token formats), so they are heavy
		m.Group("/security/patterns", func() {
			m.Post("", common.RateLimitHeavyPlain, admin.SecretPatternAdd)
			m.Post("/test", common.RateLimitHeavyPlain, shared_security.PatternTest)
			m.Post("/{id}/{action:rename}", common.RateLimitHeavyPlain, admin.SecretPatternAction)
			m.Post("/{id}/{action:enable|disable|delete}", admin.SecretPatternAction)
		}, shared_security.LimitPatternBody) // first: nothing may read the form before it

		m.Group("/monitor", func() {
			m.Get("/stats", admin.MonitorStats)
			m.Get("/cron", admin.CronTasks)
			m.Get("/stacktrace", admin.Stacktrace)
			m.Post("/stacktrace/cancel/{pid}", admin.StacktraceCancel)
			m.Get("/queue", admin.Queues)
			m.Group("/queue/{qid}", func() {
				m.Get("", admin.QueueManage)
				m.Post("/set", admin.QueueSet)
				m.Post("/remove-all-items", admin.QueueRemoveAllItems)
			})
			m.Get("/diagnosis", admin.MonitorDiagnosis)
		})

		m.Group("/users", func() {
			m.Get("", admin.Users)
			m.Combo("/new").Get(admin.NewUser).Post(web.Bind(forms.AdminCreateUserForm{}), admin.NewUserPost)
			m.Get("/{userid}", admin.ViewUser)
			m.Get("/{userid}/access", admin.UserAccess)
			m.Combo("/{userid}/edit").Get(admin.EditUser).Post(web.Bind(forms.AdminEditUserForm{}), admin.EditUserPost)
			m.Post("/{userid}/delete", admin.DeleteUser)
			m.Group("/{userid}/tokens", func() {
				m.Combo("/new").
					Get(web.Bind(forms.NewAccessTokenGetForm{}), admin.UserTokenNew).
					Post(web.Bind(forms.NewAccessTokenPostForm{}), admin.UserTokenNewPost)
				m.Post("/delete", admin.UserTokenDelete)
				m.Post("/regenerate", admin.UserTokenRegenerate)
			})
			m.Post("/{userid}/avatar", web.Bind(forms.AvatarForm{}), admin.AvatarPost)
			m.Post("/{userid}/avatar/delete", admin.DeleteAvatar)
		})

		m.Group("/emails", func() {
			m.Get("", admin.Emails)
			m.Post("/activate", admin.ActivateEmail)
			m.Post("/delete", admin.DeleteEmail)
		})

		m.Group("/orgs", func() {
			m.Get("", admin.Organizations)
		})

		m.Group("/org-categories", func() {
			m.Get("", admin.OrgCategories)
			m.Post("/settings", admin.OrgCategoriesSettingsPost)
			m.Combo("/new").Get(admin.NewOrgCategory).Post(web.Bind(forms.OrgCategoryForm{}), admin.NewOrgCategoryPost)
			m.Combo("/{id}").Get(admin.EditOrgCategory).Post(web.Bind(forms.OrgCategoryForm{}), admin.EditOrgCategoryPost)
			m.Post("/{id}/delete", admin.DeleteOrgCategory)
		})

		m.Group("/announcements", func() {
			m.Get("", admin.Announcements)
			m.Combo("/new").Get(admin.NewAnnouncement).Post(web.Bind(forms.AnnouncementForm{}), admin.NewAnnouncementPost)
			m.Post("/markup", web.Bind(structs.MarkupOption{}), misc.Markup)
			m.Combo("/{id}").Get(admin.EditAnnouncement).Post(web.Bind(forms.AnnouncementForm{}), admin.EditAnnouncementPost)
			m.Post("/{id}/delete", admin.DeleteAnnouncement)
		})

		m.Group("/roles/org-admin", func() {
			m.Get("", admin.OrgAdminRole)
			m.Post("/exclusions", admin.OrgAdminRoleExclusionsPost)
		})

		m.Group("/groups", func() {
			m.Get("", admin.UserGroups)
			m.Combo("/new").Get(admin.NewUserGroup).Post(web.Bind(forms.UserGroupForm{}), admin.NewUserGroupPost)
			m.Group("/{id}", func() {
				m.Get("", admin.ViewUserGroup)
				m.Post("/edit", web.Bind(forms.UserGroupForm{}), admin.EditUserGroupPost)
				m.Post("/delete", admin.DeleteUserGroup)
				m.Post("/members/add", admin.AddUserGroupMember)
				m.Post("/members/remove", admin.RemoveUserGroupMember)
			})
		})

		m.Group("/repos", func() {
			m.Get("", admin.Repos)
			m.Combo("/unadopted").Get(admin.UnadoptedRepos).Post(admin.AdoptOrDeleteRepository)
			m.Post("/delete", admin.DeleteRepo)
		})

		m.Group("/trash", func() {
			m.Get("", admin.Trash)
			m.Post("/{id}/restore", admin.RestoreTrash)
			m.Post("/{id}/purge", admin.PurgeTrash)
			m.Post("/org/{id}/restore", admin.RestoreTrashOrg)
			m.Post("/org/{id}/purge", admin.PurgeTrashOrg)
		})

		m.Get("/storage", admin.Storage)
		m.Post("/storage/recalculate", admin.StorageRecalculate)
		m.Get("/access-reports", admin.AccessReports)

		m.Group("/packages", func() {
			m.Get("", admin.Packages)
			m.Post("/delete", admin.DeletePackageVersion)
			m.Post("/cleanup", admin.CleanupExpiredData)
		}, packagesEnabled)

		m.Group("/hooks", func() {
			m.Get("", admin.DefaultOrSystemWebhooks)
			m.Post("/delete", admin.DeleteDefaultOrSystemWebhook)
			m.Group("/{id}", func() {
				m.Get("", repo_setting.WebhookEdit)
				m.Post("", repo_setting.WebhookUpdate)
				m.Post("/replay/{uuid}", repo_setting.WebhookReplay)
			})
		}, webhooksEnabled)

		m.Group("/{configType:default-hooks|system-hooks}", func() {
			m.Get("/{type}/new", repo_setting.WebhookNew)
			m.Post("/{type}/new", repo_setting.WebhookCreate)
		})

		m.Group("/auths", func() {
			m.Get("", admin.Authentications)
			m.Combo("/new").Get(admin.NewAuthSource).Post(web.Bind(forms.AuthenticationForm{}), admin.NewAuthSourcePost)
			m.Combo("/{authid}").Get(admin.EditAuthSource).
				Post(web.Bind(forms.AuthenticationForm{}), admin.EditAuthSourcePost)
			m.Post("/{authid}/delete", admin.DeleteAuthSource)
		})

		m.Group("/notices", func() {
			m.Get("", admin.Notices)
			m.Post("/delete", admin.DeleteNotices)
			m.Post("/empty", admin.EmptyNotices)
		})

		m.Group("/applications", func() {
			m.Get("", admin.Applications)
			m.Post("/policy", admin.ApplicationsPolicyPost)
			m.Post("/oauth2", web.Bind(forms.EditOAuth2ApplicationForm{}), admin.ApplicationsPost)
			m.Group("/oauth2/{id}", func() {
				m.Combo("").Get(admin.EditApplication).Post(web.Bind(forms.EditOAuth2ApplicationForm{}), admin.EditApplicationPost)
				m.Post("/regenerate_secret", admin.ApplicationsRegenerateSecret)
				m.Post("/delete", admin.DeleteApplication)
			})
		}, oauth2Enabled)

		m.Group("/actions", func() {
			m.Get("", admin.RedirectToDefaultSetting)
			m.Get("/runs", admin.ActionsRuns)
			m.Get("/runs/export", admin.ActionsRunsExport)
			m.Get("/usage", admin.ActionsUsage)
			addSettingsRunnersRoutes()
			addSettingsVariablesRoutes()
		})

		if setting.Moderation.Enabled {
			m.Group("/moderation/reports", func() {
				m.Get("", admin.AbuseReports)
				m.Get("/type/{type:1|2|3|4}/id/{id}", admin.AbuseReportDetails)
			})
			m.Post("/abuse_reports/act", admin.PerformAction)
		}

		if setting.Federation.Enabled {
			m.Group("/federation", func() {
				m.Get("/hosts", admin.FederationHosts)
				m.Get("/users", admin.FederationUsers)
				m.Get("/hosts/{id}", admin.FederationHost)
			})
		}
	}, adminReq, ctxDataSet("EnableOAuth2", setting.OAuth2.Enabled, "EnablePackages", setting.Packages.Enabled, "EnableModeration", setting.Moderation.Enabled))
	// ***** END: Admin *****

	m.Group("", func() {
		m.Get("/{username}", user.UsernameSubRoute)
	}, ignSignIn)

	m.Post("/{username}", reqSignIn, context.UserAssignmentWeb(), user.Action)

	reqPackageAccess := func(accessMode perm.AccessMode) func(ctx *context.Context) {
		return func(ctx *context.Context) {
			if ctx.Package.AccessMode < accessMode && !ctx.IsUserSiteAdmin() {
				ctx.NotFound("", nil)
			}
		}
	}

	reqRepoOrOwnerProjectReader := func(ctx *context.Context) {
		if projectID := ctx.FormInt64("id"); projectID > 0 {
			context.ReqProjectIDAssignableToIssue(ctx, projectID)
		}
	}

	individualPermsChecker := func(ctx *context.Context) {
		// org permissions have been checked in context.OrgAssignment(), but individual permissions haven't been checked.
		if ctx.ContextUser.IsIndividual() {
			switch ctx.ContextUser.Visibility {
			case structs.VisibleTypePrivate:
				if ctx.Doer == nil || (ctx.ContextUser.ID != ctx.Doer.ID && !ctx.Doer.IsAdmin) {
					ctx.NotFound("Visit Project", nil)
					return
				}
			case structs.VisibleTypeLimited:
				if ctx.Doer == nil {
					ctx.NotFound("Visit Project", nil)
					return
				}
			}
		}
	}

	// ***** START: Organization *****
	m.Group("/org", func() {
		m.Group("/{org}", func() {
			m.Get("/members", org.Members)
			m.Get("/groups", org.RepoGroups)
		}, context.OrgAssignment())
		m.Get("/{org}/groups/{id}", context.OrgAssignment(), context.RepoGroupAssignment, org.RepoGroupHome)
	}, ignSignIn)

	// projects: org owners (and site admins) only
	m.Group("/org/{org}/groups", func() {
		m.Combo("/new").Get(org.NewRepoGroup).Post(web.Bind(forms.RepoGroupForm{}), org.NewRepoGroupPost)
		m.Group("/{id}/settings", func() {
			m.Combo("").Get(org.RepoGroupSettings).Post(web.Bind(forms.RepoGroupForm{}), org.RepoGroupSettingsPost)
			m.Post("/delete", org.RepoGroupDeletePost)
			m.Combo("/delete_merged").Get(common.RateLimitHeavy, org.RepoGroupDeleteMerged).Post(org.RepoGroupDeleteMergedPost)
			m.Post("/teams/link", org.RepoGroupTeamLink)
			m.Post("/teams/unlink", org.RepoGroupTeamUnlink)
			m.Group("/hooks", func() {
				m.Get("", org.RepoGroupWebhooks)
				m.Post("/delete", org.RepoGroupDeleteWebhook)
				m.Get("/{type}/new", repo_setting.WebhookNew)
				m.Post("/{type}/new", repo_setting.WebhookCreate)
				m.Group("/{hook}", func() { // ":id" is the project
					m.Get("", repo_setting.WebhookEdit)
					m.Post("", repo_setting.WebhookUpdate)
					m.Post("/replay/{uuid}", repo_setting.WebhookReplay)
				})
			}, webhooksEnabled, func(ctx *context.Context) {
				ctx.Data["PageIsRepoGroupSettings"] = true
				ctx.Data["PageIsViewRepoGroups"] = true
			})
			m.Group("", func() {
				m.Group("/secrets", func() {
					m.Get("", org.RepoGroupSecrets)
					m.Post("", web.Bind(forms.CreateSecretForm{}), org.RepoGroupSecretCreate)
					m.Post("/{secret_id}/edit", web.Bind(forms.EditSecretForm{}), org.RepoGroupSecretEdit)
					m.Post("/{secret_id}/delete", org.RepoGroupSecretDelete)
				})
				m.Group("/variables", func() {
					m.Get("", org.RepoGroupVariables)
					m.Post("/new", web.Bind(forms.EditVariableForm{}), org.RepoGroupVariableCreate)
					m.Post("/{variable_id}/edit", web.Bind(forms.EditVariableForm{}), org.RepoGroupVariableUpdate)
					m.Post("/{variable_id}/delete", org.RepoGroupVariableDelete)
				})
			}, actions.MustEnableActions)
			m.Group("/keys", func() {
				m.Combo("").Get(org_setting.DeployKeys).Post(web.Bind(forms.AddKeyForm{}), org_setting.DeployKeysPost)
				m.Post("/delete", org_setting.DeleteDeployKey)
				m.Post("/tokens/new", org_setting.AccessTokenNew)
				m.Post("/tokens/rotate", org_setting.AccessTokenRotate)
				m.Post("/tokens/delete", org_setting.AccessTokenDelete)
			})
			m.Group("/branches", func() {
				m.Combo("/edit").Get(org_setting.SettingsProtectedBranch).
					Post(web.Bind(forms.ProtectBranchForm{}), org_setting.SettingsProtectedBranchPost)
				m.Post("/{rule}/delete", org_setting.DeleteProtectedBranchRulePost)
			})
		}, context.RepoGroupAssignment)
	}, reqSignIn, context.OrgAssignment(true, true))

	m.Group("/org", func() {
		m.Group("", func() {
			m.Get("/create", org.Create)
			m.Post("/create", web.Bind(forms.CreateOrgForm{}), org.CreatePost)
		})

		m.Group("/invite/{token}", func() {
			m.Get("", org.TeamInvite)
			m.Post("", org.TeamInvitePost)
			m.Post("/decline", org.DeclineTeamInvite)
		})

		m.Group("/{org}", func() {
			m.Get("/dashboard", user.Dashboard)
			m.Get("/dashboard/{team}", user.Dashboard)
			m.Get("/issues", user.Issues)
			m.Get("/issues/{team}", user.Issues)
			m.Get("/pulls", user.Pulls)
			m.Get("/pulls/{team}", user.Pulls)
			m.Get("/milestones", reqMilestonesDashboardPageEnabled, user.Milestones)
			m.Get("/milestones/{team}", reqMilestonesDashboardPageEnabled, user.Milestones)
			m.Post("/members/action/{action}", org.MembersAction)
			m.Get("/teams", org.Teams)
			m.Get("/actions", org.Runs)
			m.Get("/actions/overview", org.Overview)
		}, context.OrgAssignment(true, false, true))

		m.Group("/{org}", func() {
			m.Get("/teams/{team}", org.TeamMembers)
			m.Get("/teams/{team}/repositories", org.TeamRepositories)
			m.Post("/teams/{team}/action/{action}", org.TeamsAction)
			m.Post("/teams/{team}/action/repo/{action}", org.TeamsRepoAction)
			m.Post("/teams/{team}/action/group/{action}", org.TeamsUserGroupAction)
			m.Get("/teams/{team}/groups/search", org.SearchTeamUserGroups)
		}, context.OrgAssignment(true, false, true))

		// owners, site admins, auditors and members (a member sees the repositories they can write)
		// context.isAuditorSecretExport matches the export's pattern: keep the two in step
		m.Group("/{org}/security/secrets", func() {
			m.Get("", org.SecurityAlerts)
			m.Post("/export", common.RateLimitHeavy, org.SecurityAlertsExport)
			m.Get("/patterns", org.SecurityPatterns)
		}, context.OrgAssignment(), org.MustSeeSecretAlerts)

		// owner or site admin; the handlers answer 403 (not 404) for visible organizations
		m.Group("/{org}/settings", func() {
			m.Post("/archive", org.ArchivePost)
			m.Post("/unarchive", org.UnarchivePost)
		}, context.OrgAssignment())

		// require admin permission
		m.Group("/{org}", func() {
			m.Get("/teams/-/search", org.SearchTeam)
		}, context.OrgAssignment(true, false, false, true))

		// require owner permission
		m.Group("/{org}", func() {
			m.Get("/members/{username}/access", org.MemberAccess)
			m.Get("/teams/new", org.NewTeam)
			m.Post("/teams/new", web.Bind(forms.CreateTeamForm{}), org.NewTeamPost)
			m.Get("/teams/{team}/edit", org.EditTeam)
			m.Post("/teams/{team}/edit", web.Bind(forms.CreateTeamForm{}), org.EditTeamPost)
			m.Post("/teams/{team}/delete", org.DeleteTeam)

			m.Group("/settings", func() {
				m.Combo("").Get(org.Settings).
					Post(web.Bind(forms.UpdateOrgSettingForm{}), org.SettingsPost)
				m.Post("/avatar", web.Bind(forms.AvatarForm{}), org.SettingsAvatar)
				m.Post("/avatar/delete", org.SettingsDeleteAvatar)
				m.Group("/applications", func() {
					m.Get("", org.Applications)
					m.Post("/oauth2", web.Bind(forms.EditOAuth2ApplicationForm{}), org.OAuthApplicationsPost)
					m.Group("/oauth2/{id}", func() {
						m.Combo("").Get(org.OAuth2ApplicationShow).Post(web.Bind(forms.EditOAuth2ApplicationForm{}), org.OAuth2ApplicationEdit)
						m.Post("/regenerate_secret", org.OAuthApplicationsRegenerateSecret)
						m.Post("/delete", org.DeleteOAuth2Application)
					})
				}, oauth2Enabled)

				m.Group("/hooks", func() {
					m.Get("", org.Webhooks)
					m.Post("/delete", org.DeleteWebhook)
					m.Get("/{type}/new", repo_setting.WebhookNew)
					m.Post("/{type}/new", repo_setting.WebhookCreate)
					m.Group("/{id}", func() {
						m.Get("", repo_setting.WebhookEdit)
						m.Post("", repo_setting.WebhookUpdate)
						m.Post("/replay/{uuid}", repo_setting.WebhookReplay)
					})
				}, webhooksEnabled)

				m.Group("/labels", func() {
					m.Get("", org.RetrieveLabels, org.Labels)
					m.Post("/new", web.Bind(forms.CreateLabelForm{}), org.NewLabel)
					m.Post("/edit", web.Bind(forms.CreateLabelForm{}), org.UpdateLabel)
					m.Post("/delete", org.DeleteLabel)
					m.Post("/initialize", web.Bind(forms.InitializeLabelsForm{}), org.InitializeLabels)
				})

				m.Get("/repos", org_setting.Repos)

				m.Combo("/code_security").Get(org_setting.CodeSecurity).Post(org_setting.CodeSecurityPost)
				m.Post("/code_security/secret_scanning", org_setting.SecretScanningPost)
				m.Get("/code_security/secret_scanning/repos", org_setting.SecretScanningOff)
				m.Group("/code_security/patterns", func() {
					m.Post("", common.RateLimitHeavyPlain, org_setting.SecretPatternAdd)
					m.Post("/test", common.RateLimitHeavyPlain, shared_security.PatternTest)
					m.Post("/{id}/{action:rename}", common.RateLimitHeavyPlain, org_setting.SecretPatternAction)
					m.Post("/{id}/{action:enable|disable|delete}", org_setting.SecretPatternAction)
				}, shared_security.LimitPatternBody) // first: nothing may read the form before it
				m.Combo("/branch_workflow").Get(org_setting.BranchWorkflow).
					Post(web.Bind(forms.BranchWorkflowForm{}), org_setting.BranchWorkflowPost)
				m.Post("/branch_workflow/branching_model", web.Bind(forms.BranchingModelForm{}), org_setting.BranchingModelPost)
				m.Combo("/branch_workflow/delete_merged").Get(common.RateLimitHeavy, org_setting.BranchWorkflowDeleteMerged).
					Post(org_setting.BranchWorkflowDeleteMergedPost)

				m.Group("/branches", func() {
					m.Get("", org_setting.ProtectedBranchRules)
					m.Combo("/edit").Get(org_setting.SettingsProtectedBranch).
						Post(web.Bind(forms.ProtectBranchForm{}), org_setting.SettingsProtectedBranchPost)
					m.Post("/{rule}/delete", org_setting.DeleteProtectedBranchRulePost)
				})

				m.Group("/actions", func() {
					m.Get("", org_setting.RedirectToDefaultSetting)
					m.Combo("/retention").Get(org_setting.ActionsRetention).Post(org_setting.ActionsRetentionPost)
					addSettingsRunnersRoutes()
					addSettingsSecretsRoutes()
					addSettingsVariablesRoutes()
					// writes in an archived organization are refused for every route (context.IsArchivedOrgWrite)
					addSettingsEnvironmentsRoutes(func(*context.Context) {})
				}, actions.MustEnableActions)

				m.Methods("GET,POST", "/delete", org.SettingsDelete)

				m.Group("/blocked_users", func() {
					m.Get("", org_setting.BlockedUsers)
					m.Post("/block", org_setting.BlockedUsersBlock)
					m.Post("/unblock", org_setting.BlockedUsersUnblock)
				})
				m.Combo("/units").Get(org_setting.Units).Post(org_setting.UnitsPost)
				m.Group("/verified_domains", func() {
					m.Get("", org.VerifiedDomains)
					m.Post("/verify", org.VerifiedDomainsVerify)
					m.Post("/remove", org.VerifiedDomainsRemove)
					m.Post("/require", org.VerifiedDomainsRequire)
				})
				m.Group("/keys", func() {
					m.Combo("").Get(org_setting.DeployKeys).Post(web.Bind(forms.AddKeyForm{}), org_setting.DeployKeysPost)
					m.Post("/{id}/repos", org_setting.DeployKeyReposPost)
					m.Post("/delete", org_setting.DeleteDeployKey)
					m.Post("/tokens/new", org_setting.AccessTokenNew)
					m.Post("/tokens/rotate", org_setting.AccessTokenRotate)
					m.Post("/tokens/delete", org_setting.AccessTokenDelete)
				})
				m.Group("/redirects", func() {
					m.Get("", org.Redirects)
					m.Post("/delete", org.RedirectsDelete)
				})
				m.Get("/storage_overview", org_setting.StorageOverview)
				m.Get("/access-report", org_setting.AccessReport)

				m.Group("/packages", func() {
					m.Get("", org.Packages)
					m.Group("/rules", func() {
						m.Group("/add", func() {
							m.Get("", org.PackagesRuleAdd)
							m.Post("", web.Bind(forms.PackageCleanupRuleForm{}), org.PackagesRuleAddPost)
						})
						m.Group("/{id}", func() {
							m.Get("", org.PackagesRuleEdit)
							m.Post("", web.Bind(forms.PackageCleanupRuleForm{}), org.PackagesRuleEditPost)
							m.Get("/preview", org.PackagesRulePreview)
						})
					})
					m.Group("/cargo", func() {
						m.Post("/initialize", org.InitializeCargoIndex)
						m.Post("/rebuild", org.RebuildCargoIndex)
					})
				}, packagesEnabled, org.MustEnablePackages)
			}, ctxDataSet("EnableOAuth2", setting.OAuth2.Enabled, "EnableQuota", setting.Quota.Enabled, "PageIsOrgSettings", true), org.SettingsMenu)

			// the dependency and vulnerability search: acting owners and site admins, while the dependency graph is on
			m.Group("/security", func() {
				m.Get("", org.SecurityIndex)
				m.Get("/vulnerabilities", org.SecurityVulnerabilities)
				m.Get("/dependencies", org.SecurityDependencies)
				m.Post("/vulnerabilities/export", common.RateLimitHeavy, org.SecurityVulnerabilitiesExport)
				m.Post("/dependencies/export", common.RateLimitHeavy, org.SecurityDependenciesExport)
			}, org.MustEnableSecurity)
		}, context.OrgAssignment(true, true))
	}, reqSignIn)
	// ***** END: Organization *****

	// ***** START: Repository *****
	m.Group("/repo", func() {
		m.Get("/create", repo.Create)
		m.Post("/create", web.Bind(forms.CreateRepoForm{}), repo.CreatePost)
		m.Get("/migrate", repo.Migrate)
		m.Post("/migrate", web.Bind(forms.MigrateRepoForm{}), repo.MigratePost)
		if !setting.Repository.DisableForks {
			m.Get("/fork/{repoid}", context.RepoIDAssignment(), context.UnitTypes(), reqRepoCodeReader, repo.ForkByID)
		}
		m.Get("/search", repo.SearchRepo)
	}, reqSignIn)

	m.Group("/{username}/-", func() {
		if setting.Packages.Enabled {
			m.Group("/packages", func() {
				m.Get("", user.ListPackages)
				m.Group("/{type}/{name}", func() {
					m.Get("", user.RedirectToLastVersion)
					m.Get("/versions", user.ListPackageVersions)
					m.Group("/{version}", func() {
						m.Get("", user.ViewPackageVersion)
						m.Get("/files/{fileid}", user.DownloadPackageFile)
						m.Group("/settings", func() {
							m.Get("", user.PackageSettings)
							m.Post("", web.Bind(forms.PackageSettingForm{}), user.PackageSettingsPost)
						}, reqPackageAccess(perm.AccessModeWrite))
					})
				})
			}, context.PackageAssignment(), reqPackageAccess(perm.AccessModeRead))
		}

		m.Group("/projects", func() {
			m.Group("", func() {
				m.Get("", org.Projects)
				m.Get("/{id}", org.ViewProject)
			}, reqUnitAccess(unit.TypeProjects, perm.AccessModeRead, true))
			m.Group("", func() { //nolint:dupl
				m.Get("/new", org.RenderNewProject)
				m.Post("/new", web.Bind(forms.CreateProjectForm{}), org.CreateProject)
				m.Group("/{id}", func() {
					m.Post("", web.Bind(forms.EditProjectColumnForm{}), org.CreateColumnInProject)
					m.Post("/move", project.MoveColumns)
					m.Post("/delete", org.DeleteProject)

					m.Get("/edit", org.RenderEditProject)
					m.Post("/edit", web.Bind(forms.CreateProjectForm{}), org.EditProjectPost)
					m.Post("/{action:open|close}", org.ChangeProjectStatus)

					m.Group("/{columnID}", func() {
						m.Put("", web.Bind(forms.EditProjectColumnForm{}), org.EditProjectColumn)
						m.Delete("", org.DeleteProjectColumn)
						m.Post("/default", org.SetDefaultProjectColumn)

						m.Post("/move", org.MoveIssues)
					})
				})
			}, reqSignIn, reqUnitAccess(unit.TypeProjects, perm.AccessModeWrite, true), func(ctx *context.Context) {
				if ctx.ContextUser.IsIndividual() && ctx.ContextUser.ID != ctx.Doer.ID {
					ctx.NotFound("NewProject", nil)
					return
				}
			})
		}, reqUnitAccess(unit.TypeProjects, perm.AccessModeRead, true), individualPermsChecker)

		m.Group("", func() {
			m.Get("/code", user.CodeSearch)
		}, reqUnitAccess(unit.TypeCode, perm.AccessModeRead, false), individualPermsChecker)
	}, ignSignIn, context.UserAssignmentWeb(), context.OrgAssignment()) // for "/{username}/-" (packages, projects, code)

	m.Group("/{username}/{reponame}", func() {
		m.Group("/settings", func() {
			m.Group("", func() {
				m.Combo("").Get(repo_setting.Settings).
					Post(web.Bind(forms.RepoSettingForm{}), repo_setting.SettingsPost)
			}, repo_setting.SettingsCtxData)
			m.Combo("/units").Get(repo_setting.Units).
				Post(web.Bind(forms.RepoUnitSettingForm{}), repo_setting.UnitsPost)
			m.Post("/code_search", web.Bind(forms.RepoCodeSearchForm{}), repo_setting.CodeSearchPost)
			m.Post("/avatar", web.Bind(forms.AvatarForm{}), repo_setting.SettingsAvatar)
			m.Post("/avatar/delete", repo_setting.SettingsDeleteAvatar)

			m.Get("/access", repo_setting.Access)
			m.Group("/collaboration", func() {
				m.Combo("").Get(repo_setting.Collaboration).Post(repo_setting.CollaborationPost)
				m.Post("/access_mode", repo_setting.ChangeCollaborationAccessMode)
				m.Post("/delete", repo_setting.DeleteCollaboration)
				m.Group("/team", func() {
					m.Post("", repo_setting.AddTeamPost)
					m.Post("/delete", repo_setting.DeleteTeam)
				})
			})

			m.Group("/branches", func() {
				m.Post("/", repo_setting.SetDefaultBranchPost)
			}, repo.MustBeNotEmpty)

			m.Group("/branches", func() {
				m.Get("/", repo_setting.ProtectedBranchRules)
				m.Combo("/edit").Get(repo_setting.SettingsProtectedBranch).
					Post(web.Bind(forms.ProtectBranchForm{}), context.RepoMustNotBeArchived(), repo_setting.SettingsProtectedBranchPost)
				m.Post("/{id}/delete", repo_setting.DeleteProtectedBranchRulePost)
			}, repo.MustBeNotEmpty)

			m.Post("/rename_branch", web.Bind(forms.RenameBranchForm{}), context.RepoMustNotBeArchived(), repo_setting.RenameBranchPost)

			m.Group("/tags", func() {
				m.Get("", repo_setting.ProtectedTags)
				m.Post("", web.Bind(forms.ProtectTagForm{}), context.RepoMustNotBeArchived(), repo_setting.NewProtectedTagPost)
				m.Post("/delete", context.RepoMustNotBeArchived(), repo_setting.DeleteProtectedTagPost)
				m.Get("/{id}", repo_setting.EditProtectedTag)
				m.Post("/{id}", web.Bind(forms.ProtectTagForm{}), context.RepoMustNotBeArchived(), repo_setting.EditProtectedTagPost)
			})

			m.Combo("/code_security").Get(repo_setting.CodeSecurity).Post(context.RepoMustNotBeArchived(), repo_setting.CodeSecurityPost)
			m.Post("/code_security/secret_scanning", context.RepoMustNotBeArchived(), repo_setting.SecretScanningPost)
			m.Combo("/branch_workflow").Get(repo_setting.BranchWorkflow).
				Post(web.Bind(forms.BranchWorkflowForm{}), context.RepoMustNotBeArchived(), repo_setting.BranchWorkflowPost)
			m.Post("/branch_workflow/branching_model", web.Bind(forms.BranchingModelForm{}), context.RepoMustNotBeArchived(), repo_setting.BranchingModelPost)
			m.Combo("/branch_workflow/delete_merged").Get(common.RateLimitHeavy, repo_setting.BranchWorkflowDeleteMerged).
				Post(context.RepoMustNotBeArchived(), repo_setting.BranchWorkflowDeleteMergedPost)

			m.Combo("/push_rules").Get(repo_setting.PushRules).
				Post(web.Bind(forms.PushRuleForm{}), context.RepoMustNotBeArchived(), repo_setting.PushRulesPost)

			m.Group("/hooks/git", func() {
				m.Get("", repo_setting.GitHooks)
				m.Combo("/{name}").Get(repo_setting.GitHooksEdit).
					Post(repo_setting.GitHooksEditPost)
			}, context.GitHookService())

			m.Group("/hooks", func() {
				m.Get("", repo_setting.WebhookList)
				m.Post("/delete", repo_setting.WebhookDelete)
				m.Get("/{type}/new", repo_setting.WebhookNew)
				m.Post("/{type}/new", repo_setting.WebhookCreate)
				m.Group("/{id}", func() {
					m.Get("", repo_setting.WebhookEdit)
					m.Post("", repo_setting.WebhookUpdate)
					m.Post("/test", repo_setting.WebhookTest)
					m.Post("/replay/{uuid}", repo_setting.WebhookReplay)
				})
			}, webhooksEnabled)

			m.Group("/keys", func() {
				m.Combo("").Get(repo_setting.DeployKeys).
					Post(web.Bind(forms.AddKeyForm{}), repo_setting.DeployKeysPost)
				m.Post("/delete", repo_setting.DeleteDeployKey)
				m.Post("/tokens/new", repo_setting.AccessTokenNew)
				m.Post("/tokens/rotate", repo_setting.AccessTokenRotate)
				m.Post("/tokens/delete", repo_setting.AccessTokenDelete)
			})

			m.Group("/lfs", func() {
				m.Get("/", repo_setting.LFSFiles)
				m.Get("/show/{oid}", repo_setting.LFSFileGet)
				m.Post("/delete/{oid}", repo_setting.LFSDelete)
				m.Get("/pointers", repo_setting.LFSPointerFiles)
				m.Post("/pointers/associate", repo_setting.LFSAutoAssociate)
				m.Get("/find", repo_setting.LFSFileFind)
				m.Group("/locks", func() {
					m.Get("/", repo_setting.LFSLocks)
					m.Post("/", repo_setting.LFSLockFile)
					m.Post("/{lid}/unlock", repo_setting.LFSUnlock)
				})
			})
			m.Group("/actions", func() {
				m.Get("", shared_actions.RedirectToDefaultSetting)
				m.Combo("/general").Get(repo_setting.ActionsGeneral).Post(context.RepoMustNotBeArchived(), repo_setting.ActionsGeneralPost)
				m.Post("/retention", context.RepoMustNotBeArchived(), repo_setting.ActionsRetentionPost)
				m.Combo("/runs/delete").Get(repo_setting.ActionsDeleteRuns).Post(context.RepoMustNotBeArchived(), repo_setting.ActionsDeleteRunsPost)
				addSettingsRunnersRoutes()
				addSettingsSecretsRoutes()
				addSettingsVariablesRoutes()
				addSettingsEnvironmentsRoutes(context.RepoMustNotBeArchived())
			}, actions.MustEnableActions)
			// the follow handler must be under "settings", otherwise this incomplete repo can't be accessed
			m.Group("/migrate", func() {
				m.Post("/retry", repo.MigrateRetryPost)
				m.Post("/cancel", repo.MigrateCancelPost)
			})
		}, ctxDataSet("PageIsRepoSettings", true, "LFSStartServer", setting.LFS.StartServer))
	}, reqSignIn, context.RepoAssignment, context.UnitTypes(), reqRepoAdmin, context.RepoRef())

	m.Group("/{username}/{reponame}/action", func() {
		m.Post("/watch/select", repo.ActionWatch)
		m.Post("/watch", repo.ActionWatchConst(repo_model.WatchAllSelection))
		m.Post("/unwatch", repo.ActionWatchConst(repo_model.WatchNoneSelection))
		m.Post("/accept_transfer", repo.ActionTransfer(true))
		m.Post("/reject_transfer", repo.ActionTransfer(false))
		if !setting.Repository.DisableStars {
			m.Post("/star", repo.ActionStar(true))
			m.Post("/unstar", repo.ActionStar(false))
		}
	}, reqSignIn, context.RepoAssignment, context.UnitTypes())

	// Grouping for those endpoints not requiring authentication (but should respect ignSignIn)
	m.Group("/{username}/{reponame}", func() {
		m.Group("/milestone", func() {
			m.Get("/{id}", repo.MilestoneIssuesAndPulls)
		}, reqRepoIssuesOrPullsReader, context.RepoRef())
		m.Get("/find/*", repo.FindFiles)
		m.Group("/tree-list", func() {
			m.Get("/branch/*", context.RepoRefByType(context.RepoRefBranch), repo.TreeList)
			m.Get("/tag/*", context.RepoRefByType(context.RepoRefTag), repo.TreeList)
			m.Get("/commit/*", context.RepoRefByType(context.RepoRefCommit), repo.TreeList)
		})
		m.Get("/compare", repo.MustBeNotEmpty, reqRepoCodeReader, common.RateLimitHeavy, repo.SetEditorconfigIfExists, ignSignIn, repo.SetDiffViewStyle, repo.SetWhitespaceBehavior, repo.CompareDiff)
		m.Combo("/compare/*", repo.MustBeNotEmpty, reqRepoCodeReader, repo.SetEditorconfigIfExists).
			Get(common.RateLimitHeavy, repo.SetDiffViewStyle, repo.SetWhitespaceBehavior, repo.CompareDiff).
			Post(reqSignIn, context.RepoMustNotBeArchived(), reqRepoPullsReader, repo.MustAllowPulls, web.Bind(forms.CreateIssueForm{}), repo.SetWhitespaceBehavior, repo.CompareAndPullRequestPost)
		m.Group("/{type:^(issues|pulls)$}", func() {
			m.Group("/{index}", func() {
				m.Get("/info", repo.GetIssueInfo)
				m.Get("/summary-card", repo.DrawIssueSummaryCard)
			})
		})
		m.Group("/pulls/{index}", func() {
			m.Get(".rss", feedEnabled, repo.IssueFeedRSS)
			m.Get(".atom", feedEnabled, repo.IssueFeedAtom)
		}, ctxDataSet("EnableFeed", setting.Other.EnableFeed))
		m.Group("/issues/{index}", func() {
			m.Get(".rss", feedEnabled, repo.IssueFeedRSS)
			m.Get(".atom", feedEnabled, repo.IssueFeedAtom)
		}, ctxDataSet("EnableFeed", setting.Other.EnableFeed))
		m.Get("/summary-card", repo.DrawRepoSummaryCard) // served at /-/summary-card too, see context.RepoGroupResolver
	}, ignSignIn, context.RepoAssignment, context.UnitTypes()) // for "/{username}/{reponame}" which doesn't require authentication

	// Grouping for those endpoints that do require authentication
	m.Group("/{username}/{reponame}", func() {
		if !setting.Repository.DisableForks {
			m.Combo("/fork", reqRepoCodeReader).Get(repo.Fork).
				Post(web.Bind(forms.CreateRepoForm{}), repo.ForkPost)
		}
		m.Group("/issues", func() {
			m.Group("/new", func() {
				m.Combo("", context.EnsureOrg()).Get(context.RepoRef(), repo.NewIssue).
					Post(web.Bind(forms.CreateIssueForm{}), repo.NewIssuePost)
				m.Get("/choose", context.RepoRef(), repo.NewIssueChooseTemplate)
			})
			m.Get("/search", repo.ListIssues)
		}, context.RepoMustNotBeArchived(), reqRepoIssueReader)
		// FIXME: should use different URLs but mostly same logic for comments of issue and pull request.
		// So they can apply their own enable/disable logic on routers.
		m.Group("/{type:^(issues|pulls)$}", func() {
			m.Group("/{index}", func() {
				m.Post("/title", repo.UpdateIssueTitle)
				m.Post("/action-user-trust", reqRepoActionsReader, actions.MustEnableActions, reqRepoDelegateActionTrust, repo.UpdateTrustWithPullRequestActions)
				m.Post("/content", repo.UpdateIssueContent)
				m.Post("/deadline", web.Bind(structs.EditDeadlineOption{}), repo.UpdateIssueDeadline)
				m.Post("/watch", repo.IssueWatch)
				m.Post("/ref", repo.UpdateIssueRef)
				m.Post("/pin", reqRepoAdmin, repo.IssuePinOrUnpin)
				m.Post("/viewed-files", repo.UpdateViewedFiles)
				m.Group("/dependency", func() {
					m.Post("/add", repo.AddDependency)
					m.Post("/delete", repo.RemoveDependency)
				})
				m.Combo("/comments").Post(repo.MustAllowUserComment, web.Bind(forms.CreateCommentForm{}), repo.NewComment)
				m.Group("/times", func() {
					m.Post("/add", web.Bind(forms.AddTimeManuallyForm{}), repo.AddTimeManually)
					m.Post("/{timeid}/delete", repo.DeleteTime)
					m.Group("/stopwatch", func() {
						m.Post("/toggle", repo.IssueStopwatch)
						m.Post("/cancel", repo.CancelStopwatch)
					})
				})
				m.Post("/reactions/{action}", web.Bind(forms.ReactionForm{}), repo.ChangeIssueReaction)
				m.Post("/lock", reqRepoIssuesOrPullsWriter, web.Bind(forms.IssueLockForm{}), repo.LockIssue)
				m.Post("/unlock", reqRepoIssuesOrPullsWriter, repo.UnlockIssue)
				m.Post("/delete", reqRepoAdmin, repo.DeleteIssue)
			}, context.RepoMustNotBeArchived())
			m.Group("/{index}", func() {
				m.Get("/attachments", repo.GetIssueAttachments)
				m.Get("/attachments/{uuid}", repo.GetAttachment)
			})
			m.Group("/{index}", func() {
				m.Post("/content-history/soft-delete", repo.SoftDeleteContentHistory)
			})

			m.Post("/labels", reqRepoIssuesOrPullsWriter, repo.UpdateIssueLabel)
			m.Post("/milestone", reqRepoIssuesOrPullsWriter, repo.UpdateIssueMilestone)
			m.Post("/projects", reqRepoIssuesOrPullsWriter, context.EnsureOrg(), reqRepoOrOwnerProjectReader, repo.UpdateIssueProject)
			m.Post("/assignee", reqRepoIssuesOrPullsWriter, repo.UpdateIssueAssignee)
			m.Post("/request_review", reqRepoIssuesOrPullsReader, repo.UpdatePullReviewRequest)
			m.Post("/dismiss_review", reqRepoAdmin, web.Bind(forms.DismissReviewForm{}), repo.DismissReview)
			m.Post("/status", reqRepoIssuesOrPullsWriter, repo.UpdateIssueStatus)
			m.Post("/delete", reqRepoAdmin, repo.BatchDeleteIssues)
			m.Post("/resolve_conversation", reqRepoIssuesOrPullsReader, repo.SetShowOutdatedComments, repo.UpdateResolveConversation)
			m.Post("/attachments", context.EnforceQuotaWeb(quota_model.LimitSubjectSizeAssetsAttachmentsIssues, context.QuotaTargetRepo), repo.UploadIssueAttachment)
			m.Post("/attachments/remove", repo.DeleteAttachment)
			m.Delete("/unpin/{index}", reqRepoAdmin, repo.IssueUnpin)
			m.Post("/move_pin", reqRepoAdmin, repo.IssuePinMove)
		}, context.RepoMustNotBeArchived())
		m.Group("/comments/{id}", func() {
			m.Post("", repo.UpdateCommentContent)
			m.Post("/delete", repo.DeleteComment)
			m.Post("/reactions/{action}", web.Bind(forms.ReactionForm{}), repo.ChangeCommentReaction)
		}, context.RepoMustNotBeArchived())
		m.Group("/comments/{id}", func() {
			m.Get("/attachments", repo.GetCommentAttachments)
		})
		m.Post("/markup", web.Bind(structs.MarkupOption{}), misc.Markup)
		m.Group("/labels", func() {
			m.Post("/new", web.Bind(forms.CreateLabelForm{}), repo.NewLabel)
			m.Post("/edit", web.Bind(forms.CreateLabelForm{}), repo.UpdateLabel)
			m.Post("/delete", repo.DeleteLabel)
			m.Post("/initialize", web.Bind(forms.InitializeLabelsForm{}), repo.InitializeLabels)
		}, context.RepoMustNotBeArchived(), reqRepoIssuesOrPullsWriter, context.RepoRef())
		m.Group("/milestones", func() {
			m.Combo("/new").Get(repo.NewMilestone).
				Post(web.Bind(forms.CreateMilestoneForm{}), repo.NewMilestonePost)
			m.Get("/{id}/edit", repo.EditMilestone)
			m.Post("/{id}/edit", web.Bind(forms.CreateMilestoneForm{}), repo.EditMilestonePost)
			m.Post("/{id}/{action}", repo.ChangeMilestoneStatus)
			m.Post("/delete", repo.DeleteMilestone)
		}, context.RepoMustNotBeArchived(), reqRepoIssuesOrPullsWriter, context.RepoRef())
		m.Group("/pull", func() {
			m.Post("/{index}/target_branch", repo.UpdatePullRequestTarget)
		}, context.RepoMustNotBeArchived())

		m.Group("", func() {
			m.Group("", func() {
				m.Combo("/_edit/*").Get(repo.EditFile).
					Post(web.Bind(forms.EditRepoFileForm{}), repo.EditFilePost)
				m.Combo("/_new/*").Get(repo.NewFile).
					Post(web.Bind(forms.EditRepoFileForm{}), repo.NewFilePost)
				m.Post("/_preview/*", web.Bind(forms.EditPreviewDiffForm{}), repo.DiffPreviewPost)
				m.Combo("/_upload/*", repo.MustBeAbleToUpload).
					Get(repo.UploadFile).
					Post(BindUpload(), repo.UploadFilePost)
				m.Combo("/_diffpatch/*").Get(repo.NewDiffPatch).
					Post(web.Bind(forms.EditRepoFileForm{}), repo.NewDiffPatchPost)
				m.Combo("/_cherrypick/{sha:([a-f0-9]{4,64})}/*").Get(repo.CherryPick).
					Post(web.Bind(forms.CherryPickForm{}), repo.CherryPickPost)
			}, repo.MustBeEditable, repo.CommonEditorData, context.EnforceQuotaWeb(quota_model.LimitSubjectSizeReposAll, context.QuotaTargetRepo))
			// deletes stay allowed while the size limit of personal repositories is reached (DeleteFilePost)
			m.Combo("/_delete/*", repo.MustBeEditable, repo.CommonEditorData, context.EnforceQuotaGroupsWeb(quota_model.LimitSubjectSizeReposAll, context.QuotaTargetRepo)).Get(repo.DeleteFile).
				Post(web.Bind(forms.DeleteRepoFileForm{}), repo.DeleteFilePost)
			m.Group("", func() {
				m.Post("/upload-file", context.EnforceQuotaWeb(quota_model.LimitSubjectSizeReposAll, context.QuotaTargetRepo), repo.UploadFileToServer)
				m.Post("/upload-remove", web.Bind(forms.RemoveUploadFileForm{}), repo.RemoveUploadFileFromServer)
			}, repo.MustBeEditable, repo.MustBeAbleToUpload)
		}, context.RepoRef(), canEnableEditor, context.RepoMustNotBeArchived())

		m.Group("/ide", func() {
			m.Get("/branch/*", context.RepoRefByType(context.RepoRefBranch), repo.WebIDE)
			m.Post("/branch/*", context.RepoRefByType(context.RepoRefBranch), context.RepoMustNotBeArchived(), repo.MustBeEditable, context.EnforceQuotaWeb(quota_model.LimitSubjectSizeReposAll, context.QuotaTargetRepo), repo.WebIDECommit)
			m.Get("/tag/*", context.RepoRefByType(context.RepoRefTag), repo.WebIDE)
			m.Get("/commit/*", context.RepoRefByType(context.RepoRefCommit), repo.WebIDE)
			// "-" is no valid branch name, so these never shadow a branch
			m.Get("/-/tree/{sha}", repo.WebIDETree)
			m.Get("/-/search/{sha}", common.RateLimitHeavy, repo.WebIDESearch)
			m.Get("/*", context.RepoRefByType(context.RepoRefLegacy), repo.WebIDE)
		}, repo.MustEnableIDE, repo.MustBeNotEmpty, reqRepoCodeReader)

		m.Group("/branches", func() {
			m.Group("/_new", func() {
				m.Post("/branch/*", context.RepoRefByType(context.RepoRefBranch), repo.CreateBranch)
				m.Post("/tag/*", context.RepoRefByType(context.RepoRefTag), repo.CreateBranch)
				m.Post("/commit/*", context.RepoRefByType(context.RepoRefCommit), repo.CreateBranch)
			}, web.Bind(forms.NewBranchForm{}), context.EnforceQuotaWeb(quota_model.LimitSubjectSizeReposAll, context.QuotaTargetRepo))
			m.Post("/delete", repo.DeleteBranchPost)
			m.Post("/restore", repo.RestoreBranchPost)
		}, context.RepoMustNotBeArchived(), reqRepoCodeWriter, repo.MustBeNotEmpty)
	}, reqSignIn, context.RepoAssignment, context.UnitTypes())

	// Tags
	m.Group("/{username}/{reponame}", func() {
		m.Group("/tags", func() {
			m.Get("", repo.TagsList)
			m.Get("/list", repo.GetTagList)
			m.Get(".rss", feedEnabled, repo.TagsListFeedRSS)
			m.Get(".atom", feedEnabled, repo.TagsListFeedAtom)
		}, ctxDataSet("EnableFeed", setting.Other.EnableFeed),
			repo.MustBeNotEmpty, reqRepoCodeReader, context.RepoRefByType(context.RepoRefTag, true))
		m.Post("/tags/delete", reqSignIn, repo.MustBeNotEmpty, context.RepoMustNotBeArchived(), reqRepoCodeWriter,
			context.RepoRef(), repo.DeleteTag)
	}, ignSignIn, context.RepoAssignment, context.UnitTypes())

	// Releases
	m.Group("/{username}/{reponame}", func() {
		m.Group("/releases", func() {
			m.Get("/", repo.Releases)
			m.Get("/tag/*", repo.SingleRelease)
			m.Get("/latest", repo.LatestRelease)
			m.Get(".rss", feedEnabled, repo.ReleasesFeedRSS)
			m.Get(".atom", feedEnabled, repo.ReleasesFeedAtom)
			m.Get("/summary-card/*", repo.DrawReleaseSummaryCard)
		}, ctxDataSet("EnableFeed", setting.Other.EnableFeed),
			repo.MustBeNotEmpty, context.RepoRefByType(context.RepoRefTag, true))
		m.Get("/releases/attachments/{uuid}", repo.MustBeNotEmpty, repo.GetAttachment)
		m.Group("/releases", func() {
			m.Combo("/new", context.EnforceQuotaWeb(quota_model.LimitSubjectSizeReposAll, context.QuotaTargetRepo)).
				Get(repo.NewRelease).
				Post(web.Bind(forms.NewReleaseForm{}), repo.NewReleasePost)
			m.Post("/delete", repo.DeleteRelease)
			m.Post("/generate-notes", reqRepoCodeReader, reqRepoPullsReader, web.Bind(forms.GenerateReleaseNotesForm{}), repo.GenerateReleaseNotes)
			m.Post("/attachments", context.EnforceQuotaWeb(quota_model.LimitSubjectSizeAssetsAttachmentsReleases, context.QuotaTargetRepo), repo.UploadReleaseAttachment)
			m.Post("/attachments/remove", repo.DeleteAttachment)
		}, reqSignIn, repo.MustBeNotEmpty, context.RepoMustNotBeArchived(), reqRepoReleaseWriter, context.RepoRef())
		m.Group("/releases", func() {
			// the edit page stays open while the size limit of personal repositories is reached: its Delete button is
			// the web UI's way to delete a release
			m.Get("/edit/*", repo.EditRelease)
			m.Post("/edit/*", web.Bind(forms.EditReleaseForm{}), context.EnforceQuotaWeb(quota_model.LimitSubjectSizeReposAll, context.QuotaTargetRepo), repo.EditReleasePost)
		}, reqSignIn, repo.MustBeNotEmpty, context.RepoMustNotBeArchived(), reqRepoReleaseWriter, repo.CommitInfoCache)
	}, ignSignIn, context.RepoAssignment, context.UnitTypes(), reqRepoReleaseReader)

	m.Group("/{username}/{reponame}", func() {
		m.Post("/topics", repo.TopicsPost)
	}, context.RepoAssignment, context.RepoMustNotBeArchived(), reqRepoAdmin)

	m.Group("/{username}/{reponame}", func() {
		m.Group("", func() {
			m.Get("/issues/posters", repo.IssuePosters) // it can't use {type:issues|pulls} because other routes like "/pulls/{index}" has higher priority
			m.Get("/{type:^(issues|pulls)$}", repo.Issues)
			m.Get("/{type:^(issues|pulls)$}/{index}", context.EnsureOrg(), repo.ViewIssue)
			m.Group("/{type:^(issues|pulls)$}/{index}/content-history", func() {
				m.Get("/overview", repo.GetContentHistoryOverview)
				m.Get("/list", repo.GetContentHistoryList)
				m.Get("/detail", repo.GetContentHistoryDetail)
			})
			m.Get("/labels", reqRepoIssuesOrPullsReader, repo.RetrieveLabels, repo.Labels)
			m.Get("/milestones", reqRepoIssuesOrPullsReader, repo.Milestones)
			m.Get("/issues/suggestions", reqRepoIssuesOrPullsReader, repo.IssueSuggestions)
		}, context.RepoRef())

		if setting.Packages.Enabled {
			m.Get("/packages", repo.Packages)
		}

		if setting.Badges.Enabled {
			m.Group("/badges", func() {
				m.Get("/workflows/{workflow_name}/badge.svg", badges.GetWorkflowBadge)
				m.Group("/issues", func() {
					m.Get(".svg", badges.GetTotalIssuesBadge)
					m.Get("/open.svg", badges.GetOpenIssuesBadge)
					m.Get("/closed.svg", badges.GetClosedIssuesBadge)
				})
				m.Group("/pulls", func() {
					m.Get(".svg", badges.GetTotalPullsBadge)
					m.Get("/open.svg", badges.GetOpenPullsBadge)
					m.Get("/closed.svg", badges.GetClosedPullsBadge)
				})
				if !setting.Repository.DisableStars {
					m.Get("/stars.svg", badges.GetStarsBadge)
				}
				m.Get("/release.svg", badges.GetLatestReleaseBadge)
			})
		}

		m.Group("/projects", func() {
			m.Get("", repo.Projects)
			m.Get("/{id}", repo.ViewProject)
			m.Group("", func() { //nolint:dupl
				m.Get("/new", repo.RenderNewProject)
				m.Post("/new", web.Bind(forms.CreateProjectForm{}), repo.CreateProject)
				m.Group("/{id}", func() {
					m.Post("", web.Bind(forms.EditProjectColumnForm{}), repo.CreateColumnInProject)
					m.Post("/move", project.MoveColumns)
					m.Post("/delete", repo.DeleteProject)

					m.Get("/edit", repo.RenderEditProject)
					m.Post("/edit", web.Bind(forms.CreateProjectForm{}), repo.EditProjectPost)
					m.Post("/{action:open|close}", repo.ChangeProjectStatus)

					m.Group("/{columnID}", func() {
						m.Put("", web.Bind(forms.EditProjectColumnForm{}), repo.EditProjectColumn)
						m.Delete("", repo.DeleteProjectColumn)
						m.Post("/default", repo.SetDefaultProjectColumn)

						m.Post("/move", repo.MoveIssues)
					})
				})
			}, reqRepoProjectsWriter, context.RepoMustNotBeArchived())
		}, reqRepoProjectsReader, repo.MustEnableProjects)

		m.Group("/actions", func() {
			m.Get("", actions.List)
			m.Post("/disable", reqRepoAdmin, actions.DisableWorkflowFile)
			m.Post("/enable", reqRepoAdmin, actions.EnableWorkflowFile)
			m.Post("/manual", reqRepoActionsWriter, context.RepoMustNotBeArchived(), actions.ManualRunWorkflow)
			m.Group("/scheduled/{id}", func() {
				m.Post("/cancel", actions.CancelScheduled)
				m.Post("/time", actions.ChangeScheduledTime)
			}, reqRepoActionsWriter, context.RepoMustNotBeArchived())

			m.Get("/deployments", actions.Deployments)
			m.Group("/runs", func() {
				m.Get("/latest", actions.ViewLatest)
				m.Group("/{run}", func() {
					m.Combo("").
						Get(actions.RedirectToLatestAttempt).
						Post(web.Bind(actions.ViewRequest{}), actions.ViewPost)
					m.Group("/jobs/{job}", func() {
						m.Combo("").
							Get(actions.RedirectToLatestAttempt).
							Post(web.Bind(actions.ViewRequest{}), actions.ViewPost)
						m.Post("/rerun", reqRepoActionsWriter, actions.Rerun)
						m.Group("/attempt/{attempt}", func() {
							m.Combo("").
								Get(actions.View).
								Post(web.Bind(actions.ViewRequest{}), actions.ViewPost)
							m.Get("/logs", actions.Logs)
						})
					})
					m.Post("/cancel", reqRepoActionsWriter, actions.Cancel)
					m.Post("/deployments/review", reqSignIn, context.RepoMustNotBeArchived(), actions.ReviewDeploymentsPost)
					m.Post("/delete", reqRepoAdmin, actions.DeleteRun)
					m.Post("/keep", reqRepoAdmin, actions.KeepRun)
					m.Post("/unkeep", reqRepoAdmin, actions.UnkeepRun)
					m.Get("/artifacts", actions.ArtifactsView)
					m.Get("/artifacts/{artifact_name_or_id}", actions.ArtifactsDownloadView)
					m.Delete("/artifacts/{artifact_name}", reqRepoActionsWriter, actions.ArtifactsDeleteView)
					m.Post("/rerun", reqRepoActionsWriter, actions.Rerun)
					m.Post("/prioritize", reqRepoActionsWriter, actions.PrioritizeRun)
					m.Post("/deprioritize", reqRepoActionsWriter, actions.DeprioritizeRun)
				})
			})

			m.Group("/workflows/{workflow_name}", func() {
				m.Get("/badge.svg", badges.GetWorkflowBadge)
				m.Get("/runs/latest", actions.ViewLatestWorkflowRun)
			})
		}, reqRepoActionsReader, actions.MustEnableActions)

		m.Group("/wiki", func() {
			m.Combo("/").
				Get(repo.Wiki).
				Post(context.RepoMustNotBeArchived(), reqSignIn, reqRepoWikiWriter, web.Bind(forms.NewWikiForm{}), repo.EnforceWikiQuota, repo.WikiPost)
			m.Combo("/*").
				Get(repo.Wiki).
				Post(context.RepoMustNotBeArchived(), reqSignIn, reqRepoWikiWriter, web.Bind(forms.NewWikiForm{}), repo.EnforceWikiQuota, repo.WikiPost)
			m.Get("/commit/{sha:[a-f0-9]{4,64}}", repo.WikiNotFromFolder, repo.SetEditorconfigIfExists, repo.SetDiffViewStyle, repo.SetWhitespaceBehavior, repo.Diff)
			m.Get("/commit/{sha:[a-f0-9]{4,64}}.{ext:patch|diff}", repo.WikiNotFromFolder, repo.RawDiff)
		}, repo.MustEnableWiki, func(ctx *context.Context) {
			ctx.Data["PageIsWiki"] = true
			ctx.Data["CloneButtonOriginLink"] = ctx.Repo.Repository.WikiCloneLink()
		})

		m.Group("/wiki", func() {
			m.Get("/search", repo.WikiNotFromFolder, repo.WikiSearchContent)
			m.Get("/raw/*", repo.WikiRaw)
		}, repo.MustEnableWiki)

		m.Group("/activity", func() {
			m.Get("", repo.Activity)
			m.Get("/{period}", repo.Activity)
			m.Group("/contributors", func() {
				m.Get("", repo.Contributors)
				m.Get("/data", repo.ContributorsData)
			}, repo.MustBeNotEmpty, context.RequireRepoReaderOr(unit.TypeCode))
			m.Group("/code-frequency", func() {
				m.Get("", repo.CodeFrequency)
				m.Get("/data", repo.CodeFrequencyData)
			}, repo.MustBeNotEmpty, context.RequireRepoReaderOr(unit.TypeCode))
			m.Group("/recent-commits", func() {
				m.Get("", repo.RecentCommits)
				m.Get("/data", repo.CodeFrequencyData)
			}, repo.MustBeNotEmpty, context.RequireRepoReaderOr(unit.TypeCode))
			m.Group("/dependencies", func() {
				m.Get("", common.RateLimitHeavy, repo.Dependencies)
				m.Get("/sbom", common.RateLimitHeavyPlain, repo.DependenciesSBOM)
			}, context.RequireRepoReaderOr(unit.TypeCode), repo.MustEnableDependencyGraph, repo.MustBeNotEmpty)
		}, context.RepoRef(), repo.SetDependencyGraphNav, context.RequireRepoReaderOr(unit.TypeCode, unit.TypePullRequests, unit.TypeIssues, unit.TypeReleases))

		m.Group("/security/alerts", func() {
			m.Get("", repo.SecurityAlerts)
			m.Group("/{id}", func() {
				m.Get("", repo.SecurityAlert)
				m.Post("/dismiss", context.RepoMustNotBeArchived(), repo.SecurityAlertDismiss)
				m.Post("/reopen", context.RepoMustNotBeArchived(), repo.SecurityAlertReopen)
			})
		}, repo.MustSeeAlerts)

		m.Group("/security/secrets", func() {
			m.Get("", repo.SecretAlerts)
			m.Post("/close", context.RepoMustNotBeArchived(), repo.SecretAlertsClose)
			m.Post("/rescan", context.RepoMustNotBeArchived(), repo.SecretRescan)
			m.Group("/{index}", func() {
				m.Get("", repo.SecretAlert)
				m.Post("/close", context.RepoMustNotBeArchived(), repo.SecretAlertClose)
				m.Post("/reopen", context.RepoMustNotBeArchived(), repo.SecretAlertReopen)
				m.Post("/redact", context.RepoMustNotBeArchived(), repo.SecretAlertRedact)
			}, repo.MustScanSecrets)
		}, repo.MustSeeSecretAlerts)

		m.Group("/activity_author_data", func() {
			m.Get("", repo.ActivityAuthors)
			m.Get("/{period}", repo.ActivityAuthors)
		}, context.RepoRef(), repo.MustBeNotEmpty, context.RequireRepoReaderOr(unit.TypeCode))

		m.Group("/branches", func() {
			m.Get("/list", repo.GetBranchesList)
			m.Get("", repo.Branches)
		}, repo.MustBeNotEmpty, context.RepoRef(), reqRepoCodeReader)

		m.Group("/blob_excerpt", func() {
			m.Get("/{sha}", common.RateLimitHeavyPlain, repo.SetEditorconfigIfExists, repo.SetDiffViewStyle, repo.ExcerptBlob)
		}, func(ctx *context.Context) gocontext.CancelFunc {
			if ctx.FormBool("wiki") {
				ctx.Data["PageIsWiki"] = true
				repo.MustEnableWiki(ctx)
				return nil
			}

			reqRepoCodeReader(ctx)
			if ctx.Written() {
				return nil
			}
			cancel := context.RepoRef()(ctx)
			if ctx.Written() {
				return cancel
			}

			repo.MustBeNotEmpty(ctx)
			return cancel
		})

		m.Get("/pulls/posters", repo.PullPosters)
		m.Get("/merge-queue/*", reqRepoPullsReader, repo.MustAllowPulls, repo.MergeQueue)
		m.Group("/pulls/{index}", func() {
			m.Get("", repo.SetWhitespaceBehavior, repo.GetPullDiffStats, context.EnsureOrg(), repo.ViewIssue)
			m.Get(".diff", common.RateLimitHeavyPlain, repo.DownloadPullDiff)
			m.Get(".patch", common.RateLimitHeavyPlain, repo.DownloadPullPatch)
			m.Group("/commits", func() {
				m.Get("", context.RepoRef(), repo.SetWhitespaceBehavior, repo.GetPullDiffStats, repo.ViewPullCommits)
				m.Get("/list", context.RepoRef(), repo.GetPullCommits)
				m.Group("/{sha:[a-f0-9]{4,64}}", func() {
					m.Get("", common.RateLimitHeavy, context.RepoRef(), repo.SetEditorconfigIfExists, repo.SetDiffViewStyle, repo.SetWhitespaceBehavior, repo.SetShowOutdatedComments, repo.ViewPullFilesForSingleCommit)
					m.Post("/reviews/submit", context.RepoMustNotBeArchived(), reqSignIn, repo.MustAllowUserComment, web.Bind(forms.SubmitReviewForm{}), repo.SubmitReview)
				})
				m.Group("/{sha:([a-f0-9]{4,64})$}/notes", func() {
					m.Post("", context.RepoMustNotBeArchived(), web.Bind(forms.CommitNotesForm{}), context.EnforceQuotaWeb(quota_model.LimitSubjectSizeGitAll, context.QuotaTargetRepo), repo.SetCommitNotesPullRequest)
					m.Post("/remove", context.RepoMustNotBeArchived(), repo.RemoveCommitNotesPullRequest)
				}, reqSignIn, reqRepoCodeWriter)
			})
			m.Post("/merge", context.RepoMustNotBeArchived(), web.Bind(forms.MergePullRequestForm{}), context.EnforceQuotaWeb(quota_model.LimitSubjectSizeGitAll, context.QuotaTargetRepo), repo.MergePullRequest)
			m.Post("/merge_stack", context.RepoMustNotBeArchived(), web.Bind(forms.MergeStackForm{}), context.EnforceQuotaWeb(quota_model.LimitSubjectSizeGitAll, context.QuotaTargetRepo), repo.MergeStack)
			m.Post("/cancel_auto_merge", context.RepoMustNotBeArchived(), repo.CancelAutoMergePullRequest)
			m.Post("/merge_queue/remove", context.RepoMustNotBeArchived(), repo.RemoveFromMergeQueue)
			m.Post("/change_auto_merge_time", context.RepoMustNotBeArchived(), web.Bind(forms.ChangeAutoMergeTimeForm{}), repo.ChangeAutoMergeTimePullRequest)
			m.Post("/revert", context.RepoMustNotBeArchived(), context.EnforceQuotaWeb(quota_model.LimitSubjectSizeGitAll, context.QuotaTargetRepo), repo.RevertPullRequest)
			m.Post("/update", repo.UpdatePullRequest)
			m.Post("/set_allow_maintainer_edit", web.Bind(forms.UpdateAllowEditsForm{}), repo.SetAllowEdits)
			m.Post("/cleanup", context.RepoMustNotBeArchived(), context.RepoRef(), repo.CleanUpPullRequest)
			m.Group("/tasks", func() {
				m.Post("/new", web.Bind(forms.PullTaskForm{}), repo.CreatePullTask)
				m.Post("/{id}/status", repo.UpdatePullTaskStatus)
				m.Post("/{id}/delete", repo.DeletePullTask)
			}, reqSignIn, context.RepoMustNotBeArchived())
			m.Post("/attention/{action:add|remove}", reqSignIn, context.RepoMustNotBeArchived(), web.Bind(forms.PullAttentionForm{}), repo.UpdatePullAttention)
			m.Group("/files", func() {
				m.Get("", common.RateLimitHeavy, context.RepoRef(), repo.SetEditorconfigIfExists, repo.SetDiffViewStyle, repo.SetWhitespaceBehavior, repo.SetShowOutdatedComments, repo.ViewPullFilesForAllCommitsOfPr)
				m.Get("/{sha:[a-f0-9]{4,64}}", common.RateLimitHeavy, context.RepoRef(), repo.SetEditorconfigIfExists, repo.SetDiffViewStyle, repo.SetWhitespaceBehavior, repo.SetShowOutdatedComments, repo.ViewPullFilesStartingFromCommit)
				m.Get("/{shaFrom:[a-f0-9]{4,64}}..{shaTo:[a-f0-9]{4,64}}", common.RateLimitHeavy, context.RepoRef(), repo.SetEditorconfigIfExists, repo.SetDiffViewStyle, repo.SetWhitespaceBehavior, repo.SetShowOutdatedComments, repo.ViewPullFilesForRange)
				m.Group("/reviews", func() {
					m.Get("/new_comment", repo.RenderNewCodeCommentForm)
					m.Post("/comments", reqSignIn, repo.MustAllowUserComment, web.Bind(forms.CodeCommentForm{}), repo.SetShowOutdatedComments, repo.CreateCodeComment)
					m.Post("/submit", reqSignIn, repo.MustAllowUserComment, web.Bind(forms.SubmitReviewForm{}), repo.SubmitReview)
					m.Post("/apply_suggestion", reqSignIn, repo.ApplySuggestion)
				}, context.RepoMustNotBeArchived())
			})
		}, repo.MustAllowPulls)

		m.Group("/media", func() {
			m.Get("/branch/*", context.RepoRefByType(context.RepoRefBranch), repo.SingleDownloadOrLFS)
			m.Get("/tag/*", context.RepoRefByType(context.RepoRefTag), repo.SingleDownloadOrLFS)
			m.Get("/commit/*", context.RepoRefByType(context.RepoRefCommit), repo.SingleDownloadOrLFS)
			m.Get("/blob/{sha}", context.RepoRefByType(context.RepoRefBlob), repo.DownloadByIDOrLFS)
			// "/*" route is deprecated, and kept for backward compatibility
			m.Get("/*", context.RepoRefByType(context.RepoRefLegacy), repo.SingleDownloadOrLFS)
		}, repo.MustBeNotEmpty, reqRepoCodeReader)

		m.Group("/render", func() {
			m.Get("/branch/*", context.RepoRefByType(context.RepoRefBranch), repo.RenderFile)
			m.Get("/tag/*", context.RepoRefByType(context.RepoRefTag), repo.RenderFile)
			m.Get("/commit/*", context.RepoRefByType(context.RepoRefCommit), repo.RenderFile)
			m.Get("/blob/{sha}", context.RepoRefByType(context.RepoRefBlob), repo.RenderFile)
		}, repo.MustBeNotEmpty, reqRepoCodeReader)

		m.Group("/commits", func() {
			m.Get("/branch/*", context.RepoRefByType(context.RepoRefBranch), repo.RefCommits)
			m.Get("/tag/*", context.RepoRefByType(context.RepoRefTag), repo.RefCommits)
			m.Get("/commit/*", context.RepoRefByType(context.RepoRefCommit), repo.RefCommits)
			// "/*" route is deprecated, and kept for backward compatibility
			m.Get("/*", context.RepoRefByType(context.RepoRefLegacy), repo.RefCommits)
		}, repo.MustBeNotEmpty, reqRepoCodeReader)

		m.Group("/blame", func() {
			m.Get("/branch/*", context.RepoRefByType(context.RepoRefBranch), repo.RefBlame)
			m.Get("/tag/*", context.RepoRefByType(context.RepoRefTag), repo.RefBlame)
			m.Get("/commit/*", context.RepoRefByType(context.RepoRefCommit), repo.RefBlame)
		}, repo.MustBeNotEmpty, reqRepoCodeReader, common.RateLimitHeavy)

		m.Group("", func() {
			m.Get("/graph", repo.Graph)
			m.Get("/commit/{sha:([a-f0-9]{4,64})$}", common.RateLimitHeavy, repo.SetEditorconfigIfExists, repo.SetDiffViewStyle, repo.SetWhitespaceBehavior, repo.Diff)
			m.Get("/commit/{sha:([a-f0-9]{4,64})$}/load-branches-and-tags", common.RateLimitHeavyPlain, repo.LoadBranchesAndTags)
			m.Group("/commit/{sha:([a-f0-9]{4,64})$}/notes", func() {
				m.Post("", context.RepoMustNotBeArchived(), web.Bind(forms.CommitNotesForm{}), context.EnforceQuotaWeb(quota_model.LimitSubjectSizeGitAll, context.QuotaTargetRepo), repo.SetCommitNotes)
				m.Post("/remove", context.RepoMustNotBeArchived(), repo.RemoveCommitNotes)
			}, reqSignIn, reqRepoCodeWriter)
			m.Get("/cherry-pick/{sha:([a-f0-9]{4,64})$}", repo.SetEditorconfigIfExists, repo.CherryPick)
		}, repo.MustBeNotEmpty, context.RepoRef(), reqRepoCodeReader)

		m.Group("", func() {
			m.Get("/rss/branch/*", feed.RenderBranchFeed("rss"))
			m.Get("/atom/branch/*", feed.RenderBranchFeed("atom"))
		}, repo.MustBeNotEmpty, context.RepoRefByType(context.RepoRefBranch), reqRepoCodeReader, feedEnabled)

		m.Group("/src", func() {
			m.Get("/branch/*", context.RepoRefByType(context.RepoRefBranch), repo.Home)
			m.Get("/tag/*", context.RepoRefByType(context.RepoRefTag), repo.Home)
			m.Get("/commit/*", context.RepoRefByType(context.RepoRefCommit), repo.Home)
			// "/*" route is deprecated, and kept for backward compatibility
			m.Get("/*", context.RepoRefByType(context.RepoRefLegacy), repo.Home)
		}, repo.SetEditorconfigIfExists)

		if !setting.Repository.DisableForks {
			m.Group("", func() {
				m.Get("/forks", repo.Forks)
			}, context.RepoRef(), reqRepoCodeReader)
		}
		m.Get("/commit/{sha:([a-f0-9]{4,64})}.{ext:patch|diff}", repo.MustBeNotEmpty, reqRepoCodeReader, common.RateLimitHeavyPlain, repo.RawDiff)

		m.Post("/sync_fork", context.RepoMustNotBeArchived(), repo.MustBeNotEmpty, reqRepoCodeWriter, context.EnforcePersonalRepoLimitWeb(context.QuotaTargetRepo), repo.SyncFork)
	}, ignSignIn, context.RepoAssignment, context.UnitTypes())

	m.Get("/{username}/{reponame}/lastcommit/*", ignSignIn, context.RepoAssignment, context.UnitTypes(), context.RepoRefByType(context.RepoRefCommit), reqRepoCodeReader, repo.LastCommit)

	m.Group("/{username}/{reponame}", func() {
		if !setting.Repository.DisableStars {
			m.Get("/stars", context.RepoRef(), repo.Stars)
		}
		m.Get("/watchers", context.RepoRef(), repo.Watchers)
		m.Group("/search", func() {
			m.Get("", context.RepoRef(), repo.Search)
			if !setting.Indexer.RepoIndexerEnabled {
				m.Get("/branch/*", context.RepoRefByType(context.RepoRefBranch), repo.Search)
				m.Get("/tag/*", context.RepoRefByType(context.RepoRefTag), repo.Search)
			}
		}, reqRepoCodeReader, common.RateLimitHeavy)
	}, ignSignIn, context.RepoAssignment, context.UnitTypes())

	m.Group("/{username}", func() {
		m.Group("/{reponame}", func() {
			m.Get("", repo.SetEditorconfigIfExists, repo.Home)
		}, ignSignIn, context.RepoAssignment, context.RepoRef(), context.UnitTypes())
	})

	if setting.Repository.EnableFlags {
		m.Group("/{username}/{reponame}/flags", func() {
			m.Get("", repo_flags.Manage)
			m.Post("", repo_flags.ManagePost)
		}, adminReq, context.RepoAssignment, context.UnitTypes())
	}
	// ***** END: Repository *****

	// pull request metrics (#83); ?format=csv for the CSV
	m.Get("/org/{org}/metrics", reqSignIn, context.OrgAssignment(true, false, true), org.Metrics)
	m.Get("/{username}/{reponame}/activity/metrics", ignSignIn, context.RepoAssignment, context.UnitTypes(), context.RepoRef(), reqRepoPullsReader, repo.Metrics)

	m.Group("/notifications", func() {
		m.Get("", user.Notifications)
		m.Get("/subscriptions", user.NotificationSubscriptions)
		m.Get("/watching", user.NotificationWatching)
		m.Post("/status", user.NotificationStatusPost)
		m.Post("/purge", user.NotificationPurgePost)
		m.Get("/new", user.NewAvailable)
	}, reqSignIn)

	m.Post("/-/announcements/{id}/dismiss", user.DismissAnnouncement)

	if setting.API.EnableSwagger {
		m.Get("/swagger.v1.json", SwaggerV1Json)
	}

	if !setting.IsProd {
		m.Group("/-", func() {
			m.Any("/demo", demo.List)
			m.Any("/demo/fetch-action-test", demo.FetchActionTest)
			m.Any("/demo/{sub}", demo.Tmpl)
			m.Get("/demo/error/{errcode}", demo.ErrorPage)
		}, ignSignIn)
	}
}

// Registers HTTP Git related routes, which have different top-level middleware than [registerRoutes].
func registerGitLFSRoutes(m *web.Route) {
	lfsServerEnabled := func(ctx *context.Context) {
		if !setting.LFS.StartServer {
			ctx.Error(http.StatusNotFound)
			return
		}
	}
	lfsRoutes := func() {
		m.Post("/objects/batch", lfs.CheckAcceptMediaType, lfs.BatchHandler)
		m.Put("/objects/{oid}/{size}", lfs.UploadHandler)
		m.Get("/objects/{oid}/{filename}", lfs.DownloadHandler)
		m.Get("/objects/{oid}", lfs.DownloadHandler)
		m.Post("/verify", lfs.CheckAcceptMediaType, lfs.VerifyHandler)
		m.Group("/locks", func() {
			m.Get("/", lfs.GetListLockHandler)
			m.Post("/", lfs.PostLockHandler)
			m.Post("/verify", lfs.VerifyLockHandler)
			m.Post("/{lid}/unlock", lfs.UnLockHandler)
		}, lfs.CheckAcceptMediaType)
		m.Any("/*", func(ctx *context.Context) {
			ctx.NotFound("", nil)
		})
	}
	m.Group("/{username}/{reponame}/info/lfs", lfsRoutes, ignoreCSRF, lfsServerEnabled)
	m.Group("/{username}/{groupname}/{reponame}/info/lfs", lfsRoutes, ignoreCSRF, lfsServerEnabled) // a repository in a project
}

func registerGitRoutes(m *web.Route) {
	m.Group("/{username}/{reponame}", func() {
		gitHTTPRouters(m)
	})
	// a repository in a project
	m.Group("/{username}/{groupname}/{reponame}", func() {
		gitHTTPRouters(m)
	})
}

func registerMixedRoutes(m *web.Route) {
	dlSourceEnabled := func(ctx *context.Context) {
		if setting.Repository.DisableDownloadSourceArchives {
			ctx.Error(http.StatusNotFound)
			return
		}
	}

	// root repositories, and repositories in a project in both link forms
	for _, repoPath := range []string{"/{username}/{reponame}", "/{username}/{groupname}/{reponame}", "/{username}/{groupname}/{reponame}/-"} {
		registerMixedRepoRoutes(m, repoPath, dlSourceEnabled)
	}

	m.Group("", func() {
		m.Methods("GET, OPTIONS", "/attachments/{uuid}", optionsCorsHandler(), repo.GetAttachment)
	}, ignSignIn)
}

func registerMixedRepoRoutes(m *web.Route, repoPath string, dlSourceEnabled func(ctx *context.Context)) {
	m.Group(repoPath, func() {
		m.Group("/raw", func() {
			m.Get("/branch/*", context.RepoRefByType(context.RepoRefBranch), repo.SingleDownload)
			m.Get("/tag/*", context.RepoRefByType(context.RepoRefTag), repo.SingleDownload)
			m.Get("/commit/*", context.RepoRefByType(context.RepoRefCommit), repo.SingleDownload)
			m.Get("/blob/{sha}", context.RepoRefByType(context.RepoRefBlob), repo.DownloadByID)
			// "/*" route is deprecated, and kept for backward compatibility
			m.Get("/*", context.RepoRefByType(context.RepoRefLegacy), repo.SingleDownload)
		}, repo.MustBeNotEmpty, reqRepoCodeReader)

		m.Group("/archive", func() {
			m.Get("/*", repo.Download)
			m.Post("/*", repo.InitiateDownload)
		}, repo.MustBeNotEmpty, dlSourceEnabled, reqRepoCodeReader)
	}, ignSignIn, context.RepoAssignment, context.UnitTypes())

	m.Group(repoPath, func() {
		m.Get("/releases/download/{vTag}/{fileName}", repo.MustBeNotEmpty, repo.RedirectDownload)
	}, ignSignIn, context.RepoAssignment, context.UnitTypes(), reqRepoReleaseReader)

	// to maintain compatibility with old attachments
	m.Group(repoPath, func() {
		m.Get("/attachments/{uuid}", repo.GetAttachment)
	}, ignSignIn, context.RepoAssignment, context.UnitTypes())
}

func BindUpload() http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		theObj := new(forms.UploadRepoFileForm) // create a new form obj for every request but not use obj directly
		data := middleware.GetContextData(req.Context())
		binding.Bind(req, theObj)
		files := theObj.Files
		var fullpaths []string
		for _, fileID := range files {
			fullPath := req.Form.Get("files_fullpath[" + fileID + "]")
			fullpaths = append(fullpaths, fullPath)
		}
		theObj.FullPaths = fullpaths
		data.GetData()["__form"] = theObj
		middleware.AssignForm(theObj, data)
	}
}
