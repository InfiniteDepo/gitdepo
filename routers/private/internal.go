// Copyright 2017 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Package private contains all internal routes. The package name "internal" isn't usable because Golang reserves it for disabling cross-package usage.
package private

import (
	"forgejo.org/modules/private"
	"forgejo.org/modules/web"
	"forgejo.org/services/context"

	chi_middleware "github.com/go-chi/chi/v5/middleware"
)

// bind binding an obj to a handler
func bind[T any](_ T) any {
	return func(ctx *context.PrivateContext) {
		theObj := new(T) // create a new form obj for every request but not use obj directly
		if !web.BindForm(ctx.Resp, ctx.Req, theObj) {
			return
		}
		web.SetForm(ctx, theObj)
	}
}

// Routes registers all internal APIs routes to web application.
// These APIs will be invoked by internal commands for example `gitea serv` and etc.
func Routes() *web.Route {
	r := web.NewRoute()
	r.Use(context.PrivateContexter())
	// Log the real ip address of the request from SSH is really helpful for diagnosing sometimes.
	// Since internal API will be sent only from Forgejo sub commands and it's under control (checked by InternalToken), we can trust the headers.
	r.Use(chi_middleware.ClientIPFromHeader("X-Real-IP"))

	r.Post("/ssh/authorized_keys", AuthorizedPublicKeyByFingerprint)
	r.Post("/ssh/{id}/update/{repoid}", UpdatePublicKeyInRepo)
	r.Post("/ssh/log", bind(private.SSHLogOption{}), SSHLog)
	r.Post("/hook/pre-receive/{repoid}", RepoAssignment, bind(private.HookOptions{}), HookPreReceive)
	r.Post("/hook/post-receive/{repoid}", context.OverrideContext, bind(private.HookOptions{}), HookPostReceive)
	r.Post("/hook/push-audit/{repoid}", bind(private.HookOptions{}), HookPushAudit)
	r.Post("/hook/proc-receive/{repoid}", context.OverrideContext, RepoAssignment, bind(private.HookOptions{}), HookProcReceive)
	r.Post("/hook/set-default-branch/{repoid}/{branch}", RepoAssignment, SetDefaultBranch)
	r.Get("/serv/none/{keyid}", ServNoCommand)
	r.Get("/serv/command/{keyid}/{owner}/{repo}", ServCommand)
	r.Get("/serv/command/{keyid}/{owner}/{group}/{repo}", ServCommand)
	r.Get("/serv/slot", ServOperationSlot)
	r.Post("/manager/shutdown", Shutdown)
	r.Post("/manager/restart", Restart)
	r.Post("/manager/reload-templates", ReloadTemplates)
	r.Post("/manager/flush-queues", bind(private.FlushOptions{}), FlushQueues)
	r.Post("/manager/pause-logging", PauseLogging)
	r.Post("/manager/resume-logging", ResumeLogging)
	r.Post("/manager/release-and-reopen-logging", ReleaseReopenLogging)
	r.Post("/manager/set-log-sql", SetLogSQL)
	r.Post("/manager/add-logger", bind(private.LoggerOptions{}), AddLogger)
	r.Post("/manager/remove-logger/{logger}/{writer}", RemoveLogger)
	r.Get("/manager/processes", Processes)
	r.Post("/mail/send", SendEmail)
	r.Post("/restore_repo", RestoreRepo)
	r.Post("/bitbucket_import", BitbucketImport)
	r.Post("/actions/generate_actions_runner_token", GenerateActionsRunnerToken)

	return r
}
