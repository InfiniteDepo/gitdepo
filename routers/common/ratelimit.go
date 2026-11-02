// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package common

import (
	"errors"
	"math"
	"net/http"
	"strconv"

	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	"forgejo.org/services/auth"
	"forgejo.org/services/context"
)

const tplStatus429 = "status/429"

var rateLimitHeaders = []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"}

// checkRateLimit takes a token for the request from its traffic class and sets the X-RateLimit-* headers.
// Authenticated requests count per user (or per Actions task), anonymous ones per client IP.
func checkRateLimit(b *context.Base, class string, doer *user_model.User, ar auth.AuthenticationResult) ratelimit.Result {
	addr := ratelimit.ClientAddr(b.Req)
	if ratelimit.IsExempt(addr) {
		return ratelimit.Result{Allowed: true}
	}
	if setting.RateLimit.ExemptAdmins && doer != nil && doer.IsAdmin && doer.IsActive && !doer.ProhibitLogin {
		return ratelimit.Result{Allowed: true}
	}
	key, authenticated := ratelimit.IPKey(addr), false
	if ar != nil {
		if ok, id := ar.ActionsTaskID().Get(); ok {
			key, authenticated = "task:"+strconv.FormatInt(id, 10), true
		}
	}
	if !authenticated && doer != nil {
		key, authenticated = "u:"+strconv.FormatInt(doer.ID, 10), true
	}
	if class == ratelimit.API && authenticated {
		switch b.Req.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			class = ratelimit.APIWrite
		}
	}
	r := ratelimit.Check(class, addr, key, authenticated)
	setRateLimitHeaders(b, r)
	if !r.Allowed {
		log.Debug("Rate limit %s exceeded by %s", class, key)
		recordRateLimited(b, class, key, doer)
	}
	return r
}

// recordRateLimited records a rate limit refusal in the audit log, aggregated per bucket and class.
func recordRateLimited(b *context.Base, class, key string, doer *user_model.User) {
	var uid int64
	if doer != nil {
		uid = doer.ID
	}
	auth.RecordRefusal(b, "rate_limit", 0, uid, class+"|"+key, map[string]any{"class": class})
}

func setRateLimitHeaders(b *context.Base, r ratelimit.Result) {
	if r.Limit == 0 {
		return
	}
	h := b.Resp.Header()
	h.Set("X-RateLimit-Limit", strconv.Itoa(r.Limit))
	h.Set("X-RateLimit-Remaining", strconv.Itoa(r.Remaining))
	h.Set("X-RateLimit-Reset", strconv.Itoa(int(math.Ceil(r.Reset.Seconds()))))
	if !r.Allowed {
		h.Set("Retry-After", strconv.Itoa(r.RetryAfterSeconds()))
	}
}

func rateLimitMessage(r ratelimit.Result) string {
	return (&ratelimit.LimitedError{Result: r}).Error()
}

func renderRateLimited(ctx *context.Context, r ratelimit.Result) {
	setRateLimitHeaders(ctx.Base, r)
	ctx.Data["Title"] = ctx.Tr("error.rate_limited.title")
	ctx.HTML(http.StatusTooManyRequests, tplStatus429)
}

// RateLimit limits a web route group: web pages get the 429 page, git and packages a plain text message that git
// shows as "remote: ...".
func RateLimit(class string) func(*context.Context) {
	return func(ctx *context.Context) {
		if context.GetRepoGroupMark(ctx) != nil {
			return // the second pass of a request in a project; its first pass was charged
		}
		r := checkRateLimit(ctx.Base, class, ctx.Doer, ctx.Authentication)
		if r.Allowed {
			return
		}
		if class == ratelimit.Web {
			renderRateLimited(ctx, r)
			return
		}
		ctx.PlainText(http.StatusTooManyRequests, rateLimitMessage(r))
	}
}

// RateLimitHeavy limits expensive web pages (blame, code search, diffs) in the heavy class; it is a route
// middleware, run in addition to the web class of the route group.
func RateLimitHeavy(ctx *context.Context) {
	if ctx.FormBool("file-only") {
		// the diff pages load more files into the page with an XHR that ignores an HTML answer
		ChargeHeavyPlain(ctx)
		return
	}
	if r := checkRateLimit(ctx.Base, ratelimit.Heavy, ctx.Doer, ctx.Authentication); !r.Allowed {
		renderRateLimited(ctx, r)
	}
}

// RateLimitHeavyPlain is RateLimitHeavy for downloads (.diff and .patch), answering in plain text.
func RateLimitHeavyPlain(ctx *context.Context) {
	ChargeHeavyPlain(ctx)
}

// ChargeHeavyPlain takes a heavy token inside a handler, for work that is only sometimes expensive (archive
// builds). When the client is limited it answers 429 in plain text and returns false.
func ChargeHeavyPlain(ctx *context.Context) bool {
	r := checkRateLimit(ctx.Base, ratelimit.Heavy, ctx.Doer, ctx.Authentication)
	if !r.Allowed {
		ctx.PlainText(http.StatusTooManyRequests, rateLimitMessage(r))
	}
	return r.Allowed
}

// RateLimitAPIHeavy limits expensive API requests (code search, diffs) in the heavy class, in addition to the api
// class of the API.
func RateLimitAPIHeavy(ctx *context.APIContext) {
	ChargeHeavyAPI(ctx)
}

// ChargeHeavyAPI is ChargeHeavyPlain for the API: it answers 429 as JSON and returns false when limited.
func ChargeHeavyAPI(ctx *context.APIContext) bool {
	r := checkRateLimit(ctx.Base, ratelimit.Heavy, ctx.Doer(), ctx.Authentication())
	if r.Limit != 0 {
		ctx.AppendAccessControlExposeHeaders(rateLimitHeaders...)
	}
	if !r.Allowed {
		ctx.JSON(http.StatusTooManyRequests, map[string]string{"message": rateLimitMessage(r)})
	}
	return r.Allowed
}

// RateLimitAPI limits API requests in the api or api_write class.
func RateLimitAPI(ctx *context.APIContext) {
	r := checkRateLimit(ctx.Base, ratelimit.API, ctx.Doer(), ctx.Authentication())
	if r.Limit != 0 {
		ctx.AppendAccessControlExposeHeaders(rateLimitHeaders...)
	}
	if !r.Allowed {
		ctx.JSON(http.StatusTooManyRequests, map[string]string{"message": rateLimitMessage(r)})
	}
}

// RateLimitAuthIP counts every request per client IP in the auth class (and, for IPv6, in the shared /48 bucket), for
// endpoints that send mail or create accounts. The attempt is never marked Succeeded, so nothing is refunded.
// Credential checks use StartAuthAttempt instead, which only counts failures.
func RateLimitAuthIP(ctx *context.Context) {
	StartAuthAttempt(ctx)
}

// StartAuthAttempt starts a credential check counted per client IP and per key in the auth class. When the client
// is limited, it renders the 429 page and returns nil. Call Succeeded on the attempt after a successful check.
func StartAuthAttempt(ctx *context.Context, keys ...string) *ratelimit.AuthAttempt {
	a := ratelimit.StartAuth(ratelimit.ClientAddr(ctx.Req), keys...)
	if !a.Allowed {
		recordRateLimited(ctx.Base, ratelimit.Auth, auth.ActorIPKey(ctx, 48), nil)
		renderRateLimited(ctx, a.Result)
		return nil
	}
	return a
}

// WriteIfRateLimited answers 429 instead of 401 when an authentication method was rejected by the auth class, so
// that clients like git don't drop stored credentials.
func WriteIfRateLimited(b *context.Base, err error, asJSON bool) bool {
	var limited *ratelimit.LimitedError
	if !errors.As(err, &limited) {
		return false
	}
	recordRateLimited(b, ratelimit.Auth, auth.ActorIPKey(b, 48), nil)
	setRateLimitHeaders(b, limited.Result)
	if asJSON {
		b.JSON(http.StatusTooManyRequests, map[string]string{"message": limited.Error()})
	} else {
		b.PlainText(http.StatusTooManyRequests, limited.Error())
	}
	return true
}
