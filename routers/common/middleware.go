// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	"fmt"
	"net/http"
	"net/netip"
	"runtime/trace"
	"slices"
	"strings"
	"time"

	"forgejo.org/modules/cache"
	"forgejo.org/modules/httplib"
	"forgejo.org/modules/process"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/web/middleware"
	"forgejo.org/modules/web/routing"
	"forgejo.org/services/context"

	"code.forgejo.org/go-chi/session"
	"github.com/chi-middleware/proxy"
	chi "github.com/go-chi/chi/v5"
)

// ProtocolMiddlewares returns HTTP protocol related middlewares, and it provides a global panic recovery
func ProtocolMiddlewares() (handlers []any) {
	// first, normalize the URL path
	handlers = append(handlers, stripSlashesMiddleware)

	// prepare the ContextData and panic recovery
	handlers = append(handlers, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					if err == http.ErrAbortHandler {
						panic(err) // net/http cuts the connection; an error page would end the started body normally
					}
					RenderPanicErrorPage(resp, req, err) // it should never panic
				}
			}()
			req = req.WithContext(middleware.WithContextData(req.Context()))
			next.ServeHTTP(resp, req)
		})
	})

	// wrap the request and response, use the process context and add it to the process manager
	handlers = append(handlers, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			ctx, _, finished := process.GetManager().AddTypedContext(req.Context(), fmt.Sprintf("%s: %s", req.Method, req.RequestURI), process.RequestProcessType, true)
			defer finished()
			trace.Log(ctx, "method", req.Method)
			trace.Log(ctx, "url", req.RequestURI)

			respWriter := context.WrapResponseWriter(resp)
			next.ServeHTTP(respWriter, req.WithContext(cache.WithCacheContext(ctx)))

			trace.Logf(ctx, "status", "%d", respWriter.WrittenStatus())
		})
	})

	if setting.ReverseProxyLimit > 0 {
		opt := proxy.NewForwardedHeadersOptions().
			WithForwardLimit(setting.ReverseProxyLimit).
			ClearTrustedProxies()
		for _, n := range setting.ReverseProxyTrustedProxies {
			if !strings.Contains(n, "/") {
				opt.AddTrustedProxy(n)
			} else {
				opt.AddTrustedNetwork(n)
			}
		}
		handlers = append(handlers, joinForwardedFor(setting.ReverseProxyTrustedProxies), proxy.ForwardedHeaders(opt))
	}

	handlers = append(handlers, refuseUnparsableForm)

	// both check per request whether their logger has a writer, so that a log destination added at runtime works
	handlers = append(handlers, routing.NewLoggerHandler(), context.AccessLogger())

	return handlers
}

// refuseUnparsableForm answers 400 to a form body Go can't parse (malformed, or more fields than it parses): every
// later reader (auth, FormValue, web.Bind) would otherwise see an empty or partial form and act on it.
func refuseUnparsableForm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.Header.Get("Content-Type"), "form-urlencoded") && req.ParseForm() != nil {
			http.Error(resp, "The request could not be parsed.", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(resp, req)
	})
}

// joinForwardedFor makes proxy.ForwardedHeaders see the address a trusted proxy appended: that reads only the first
// X-Forwarded-For line and prefers X-Real-IP, both of which a client can send through a proxy that sets only the other
// header. So for a trusted peer, all X-Forwarded-For lines are joined and X-Real-IP is dropped, unless X-Real-IP
// disagrees with the last X-Forwarded-For address: then the headers are left as they are and the client IP is marked
// ambiguous, which the IP allowlist refuses.
func joinForwardedFor(trusted []string) func(http.Handler) http.Handler {
	var prefixes []netip.Prefix
	trustAll := false
	for _, n := range trusted {
		if n == "*" {
			trustAll = true
		} else if p, err := netip.ParsePrefix(n); err == nil {
			prefixes = append(prefixes, setting.NormalizeIPPrefix(p))
		} else if a, err := netip.ParseAddr(n); err == nil {
			prefixes = append(prefixes, setting.NormalizeIPPrefix(netip.PrefixFrom(a, a.BitLen())))
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			xff := req.Header.Values("X-Forwarded-For")
			if len(xff) == 0 {
				next.ServeHTTP(resp, req)
				return
			}
			peer := setting.IPFromRemoteAddr(req.RemoteAddr)
			if req.RemoteAddr == "@" { // a unix socket, which proxy.ForwardedHeaders trusts as 127.0.0.1
				peer = netip.AddrFrom4([4]byte{127, 0, 0, 1})
			}
			if trustAll || slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(peer.Unmap()) }) {
				joined := strings.Join(xff, ", ")
				last := strings.TrimSpace(joined[strings.LastIndex(joined, ",")+1:])
				if realIP := req.Header.Get("X-Real-IP"); realIP == "" || strings.TrimSpace(realIP) == last {
					req.Header.Set("X-Forwarded-For", joined)
					req.Header.Del("X-Real-IP")
				} else {
					var candidates []string
					for _, c := range []string{strings.TrimSpace(realIP), last} {
						if a, err := netip.ParseAddr(c); err == nil {
							candidates = append(candidates, a.String())
						}
					}
					req = httplib.WithAmbiguousClientIP(req, auditPeer(req.RemoteAddr, peer), candidates)
				}
			}
			next.ServeHTTP(resp, req)
		})
	}
}

// auditPeer is the peer address as the audit log stores it: "unix" for a unix socket, never "".
func auditPeer(remoteAddr string, peer netip.Addr) string {
	if remoteAddr == "@" {
		return "unix"
	} else if !peer.IsValid() {
		return "invalid"
	}
	return peer.Unmap().String()
}

// ClientIP returns the client address of the request, invalid if it can't be parsed or a trusted proxy sent
// disagreeing X-Real-IP and X-Forwarded-For headers.
func ClientIP(req *http.Request) netip.Addr {
	return httplib.ClientIP(req)
}

func stripSlashesMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		// Ensure that URL.RawPath is always set.
		req.URL.RawPath = req.URL.EscapedPath()

		sanitize := func(path string) string {
			sanitizedPath := &strings.Builder{}
			prevWasSlash := false
			for _, chr := range strings.TrimRight(path, "/") {
				if chr != '/' || !prevWasSlash {
					sanitizedPath.WriteRune(chr)
				}
				prevWasSlash = chr == '/'
			}
			return sanitizedPath.String()
		}

		// Sanitize the unescaped path for application logic.
		req.URL.Path = sanitize(req.URL.Path)
		rctx := chi.RouteContext(req.Context())
		if rctx != nil {
			// Sanitize the escaped path for routing.
			rctx.RoutePath = sanitize(req.URL.RawPath)
		}
		next.ServeHTTP(resp, req)
	})
}

// sessionWriter is the session's response writer, which has no Unwrap: it passes a write deadline
// (http.ResponseController) to the writer underneath, so a handler can bound its writes.
type sessionWriter struct {
	http.ResponseWriter
	under http.ResponseWriter
}

func (w sessionWriter) SetWriteDeadline(t time.Time) error {
	return http.NewResponseController(w.under).SetWriteDeadline(t)
}

// Flush sends the header through the session's writer first (it drops the cookie of an empty session), then
// flushes the writer underneath. No Unwrap to under: it would skip that header handling.
func (w sessionWriter) Flush() {
	w.WriteHeader(http.StatusOK) // the session writer: a no-op once the header is written
	if f, ok := w.under.(http.Flusher); ok {
		f.Flush()
	}
}

func Sessioner() func(next http.Handler) http.Handler {
	sessioner := sessionMiddleware()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			sessioner(http.HandlerFunc(func(sw http.ResponseWriter, req *http.Request) {
				if sw == w { // an event stream: the session package passes the writer through as it is
					next.ServeHTTP(w, req)
					return
				}
				next.ServeHTTP(sessionWriter{ResponseWriter: sw, under: w}, req)
			})).ServeHTTP(w, req)
		})
	}
}

func sessionMiddleware() func(next http.Handler) http.Handler {
	return session.Sessioner(session.Options{
		Provider:       setting.SessionConfig.Provider,
		ProviderConfig: setting.SessionConfig.ProviderConfig,
		CookieName:     setting.SessionConfig.CookieName,
		CookiePath:     setting.SessionConfig.CookiePath,
		Gclifetime:     setting.SessionConfig.Gclifetime,
		Maxlifetime:    setting.SessionConfig.Maxlifetime,
		Secure:         setting.SessionConfig.Secure,
		SameSite:       setting.SessionConfig.SameSite,
		Domain:         setting.SessionConfig.Domain,
		DeferSetCookie: true,
	})
}
