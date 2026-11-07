// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"context"
	"strconv"
	"strings"

	"forgejo.org/modules/util"
)

const (
	ActorUser        = "user"
	ActorAnonymous   = "anonymous"
	ActorDeployKey   = "deploy_key"
	ActorActions     = "actions"
	ActorRunner      = "runner" // an Actions runner, by its own secret
	ActorSystem      = "system"
	ActorLoginSource = "login_source" // a login source syncing users, groups or keys
	ActorCLI         = "cli"
	ActorUnknown     = "unknown"
)

// Credential types.
const (
	CredentialSession               = "session"
	CredentialPassword              = "password"
	CredentialAccessToken           = "access_token"
	CredentialOAuth2Grant           = "oauth2_grant"
	CredentialAuthorizedIntegration = "authorized_integration"
	CredentialSSHKey                = "ssh_key"
	CredentialDeployKey             = "deploy_key"
	CredentialOrgDeployKey          = "org_deploy_key"
	CredentialProjectDeployKey      = "project_deploy_key"
	CredentialOAuth2App             = "oauth2_app" // only as the target of an expired client secret
	CredentialRunner                = "runner"
	CredentialRunnerToken           = "runner_token" // a registration token, by its row: the token itself is never recorded
	CredentialActionsTask           = "actions_task"
	CredentialReverseProxy          = "reverse_proxy"
	CredentialChefKey               = "chef_key"
	CredentialSystem                = "system"
	CredentialCLI                   = "cli"
	CredentialUnknown               = "unknown"
)

// Credential is the credential a request authenticated with. It comes only from server-side authentication.
type Credential struct {
	Type    string
	ID      int64
	Name    string
	OwnerID int64
	AppID   int64 // oauth2_grant: its application, named by Record when it writes
}

var credentialNamers = map[string]func(context.Context, Credential) (string, error){}

// RegisterCredentialNamer sets how Record names a credential of this type that has no name yet, so that the name is
// loaded only when an entry is written.
func RegisterCredentialNamer(typ string, namer func(context.Context, Credential) (string, error)) {
	credentialNamers[typ] = namer
}

// Actor is who does what is recorded. One Actor is stored per request; API sudo changes it in place.
type Actor struct {
	Type         string
	ID           int64
	Name         string
	SudoByID     int64
	Credential   Credential
	IP           string
	IPAmbiguous  bool
	IPCandidates []string
	UserAgent    string
	RequestID    string
	Task         string // a cron task a user started, or the account a command line import runs as; recorded as data.task
}

// SetSudo makes the user acted as the actor and keeps the admin in SudoByID; sudo to oneself records no sudoer.
func (a *Actor) SetSudo(id int64, name string) {
	if id != a.ID {
		a.SudoByID = a.ID
	}
	a.ID, a.Name = id, name
}

// CredentialClaim is the "type:id" a JWT carries for the credential that minted it, "" for one that must not be
// carried (unknown, session, system, cli, reverse proxy).
func CredentialClaim(c Credential) string {
	if !claimTypes[c.Type] {
		return ""
	}
	return c.Type + ":" + strconv.FormatInt(c.ID, 10)
}

var claimTypes = map[string]bool{
	CredentialAccessToken: true, CredentialOAuth2Grant: true, CredentialAuthorizedIntegration: true, CredentialSSHKey: true,
	CredentialDeployKey: true, CredentialOrgDeployKey: true, CredentialProjectDeployKey: true, CredentialPassword: true,
	CredentialActionsTask: true,
}

// CredentialFromClaim reads CredentialClaim back. The claim is server-signed, so it needs no lookup; anything but an
// allowed type with a positive ID (password: ID 0) is unknown.
func CredentialFromClaim(s string, ownerID int64) Credential {
	typ, idText, ok := strings.Cut(s, ":")
	id, err := strconv.ParseInt(idText, 10, 64)
	if !ok || err != nil || !claimTypes[typ] || (id <= 0 && typ != CredentialPassword) {
		return Credential{Type: CredentialUnknown, OwnerID: ownerID}
	}
	if typ == CredentialPassword {
		id = 0
	}
	return Credential{Type: typ, ID: id, OwnerID: ownerID}
}

type actorKey struct{}

// ActorContextKey is the context key of the *Actor.
var ActorContextKey = actorKey{}

func WithActor(ctx context.Context, a *Actor) context.Context {
	return context.WithValue(ctx, ActorContextKey, a)
}

func ActorFromContext(ctx context.Context) *Actor {
	a, _ := ctx.Value(ActorContextKey).(*Actor)
	return a
}

// ErrNotOwnAct refuses a change that only a person may make with a credential of their own (see IsOwnAct).
var ErrNotOwnAct = util.NewPermissionDeniedErrorf("only a person with a credential of their own may make this change")

// IsOwnAct tells that what ctx does is the actor's own act: not made under sudo, nor with a credential that another
// party holds on the user's behalf (an OAuth2 grant, or an authorized integration that workflow code can use). This is
// the rule of auth_service.IsHeldByUser, read from the actor that every authentication stores; without an actor the
// request can't be told from those, so it fails closed. It is the one rule for deployment protection: reviews of
// deployments and every change of an environment's rules, secrets and variables.
func IsOwnAct(ctx context.Context) bool {
	a := ActorFromContext(ctx)
	return a != nil && a.SudoByID == 0 && a.Credential.Type != CredentialOAuth2Grant && a.Credential.Type != CredentialAuthorizedIntegration
}

// CheckOwnAct returns ErrNotOwnAct unless IsOwnAct.
func CheckOwnAct(ctx context.Context) error {
	if !IsOwnAct(ctx) {
		return ErrNotOwnAct
	}
	return nil
}

// SystemActor is the server doing work by itself, e.g. "cron:<task>", "mirror:<repo id>", "install".
func SystemActor(name string) *Actor {
	return &Actor{Type: ActorSystem, Name: name, Credential: Credential{Type: CredentialSystem}}
}

func WithSystem(ctx context.Context, name string) context.Context {
	return WithActor(ctx, SystemActor(name))
}

// WithCLI marks a command line change. The OS user name is not recorded: it would be client input.
func WithCLI(ctx context.Context) context.Context {
	return WithActor(ctx, &Actor{Type: ActorCLI, Credential: Credential{Type: CredentialCLI}})
}

// WithLoginSource makes the login source id the actor of what ctx does, keeping the IP, user agent and request ID of
// the actor it replaces (a sign-in or a cron run). It never changes that actor.
func WithLoginSource(ctx context.Context, id int64, name string) context.Context {
	outer := ActorFromContext(ctx)
	if outer != nil && outer.Type == ActorLoginSource && outer.ID == id {
		return ctx
	}
	a := &Actor{}
	if outer != nil {
		*a = *outer
		a.SudoByID = 0
	}
	a.Type, a.ID, a.Name, a.Credential = ActorLoginSource, id, name, Credential{Type: CredentialSystem}
	return WithActor(ctx, a)
}
