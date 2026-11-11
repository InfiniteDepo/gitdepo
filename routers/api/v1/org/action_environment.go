// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package org

import (
	"net/http"

	"forgejo.org/services/auth"
	"forgejo.org/services/context"
)

// The environment routes of an organization are the repository ones (repo.ListActionEnvironments and the others),
// which take the organization of the request when there is no repository (repo.environmentScope); only their
// documentation is here.

// EnvironmentToken refuses a token limited to public or specific repositories (an organization environment applies
// to every repository of the organization) and a credential another party holds for the user (an OAuth2 grant or an
// authorized integration), on reads too: the model writers refuse those for every change anyway.
func EnvironmentToken(ctx *context.APIContext) {
	if !orgWideToken(ctx) {
		return
	}
	if !auth.IsHeldByUser(ctx.Authentication()) {
		ctx.Error(http.StatusForbidden, "EnvironmentToken", "an OAuth2 grant or an authorized integration can't manage organization environments")
	}
}

// swagger:operation GET /orgs/{org}/actions/environments organization orgListActionEnvironments
// ---
// summary: List the deployment environments of an organization, which its repositories inherit
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: page
//   in: query
//   description: page number of results to return (1-based)
//   type: integer
// - name: limit
//   in: query
//   description: page size of results
//   type: integer
// responses:
//   "200":
//     "$ref": "#/responses/ActionEnvironmentList"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"

// swagger:operation GET /orgs/{org}/actions/environments/{environment} organization orgGetActionEnvironment
// ---
// summary: Get a deployment environment of an organization
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// responses:
//   "200":
//     "$ref": "#/responses/ActionEnvironment"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"

// swagger:operation PUT /orgs/{org}/actions/environments/{environment} organization orgCreateOrUpdateActionEnvironment
// ---
// summary: Create a deployment environment of an organization, or replace the protection rules of the one with that name
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// - name: body
//   in: body
//   schema:
//     "$ref": "#/definitions/CreateOrUpdateEnvironmentOption"
// responses:
//   "200":
//     "$ref": "#/responses/ActionEnvironment"
//   "201":
//     "$ref": "#/responses/ActionEnvironment"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"

// swagger:operation DELETE /orgs/{org}/actions/environments/{environment} organization orgDeleteActionEnvironment
// ---
// summary: Delete a deployment environment of an organization with its secrets, variables and reviewers
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// responses:
//   "204":
//     "$ref": "#/responses/empty"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"

// swagger:operation GET /orgs/{org}/actions/environments/{environment}/secrets organization orgListActionEnvironmentSecrets
// ---
// summary: List the secrets of a deployment environment of an organization (never their values)
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// - name: page
//   in: query
//   description: page number of results to return (1-based)
//   type: integer
// - name: limit
//   in: query
//   description: page size of results
//   type: integer
// responses:
//   "200":
//     "$ref": "#/responses/SecretList"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"

// swagger:operation PUT /orgs/{org}/actions/environments/{environment}/secrets/{secretname} organization updateOrgEnvironmentSecret
// ---
// summary: Create or update a secret of a deployment environment of an organization
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// - name: secretname
//   in: path
//   description: name of the secret
//   type: string
//   required: true
// - name: body
//   in: body
//   schema:
//     "$ref": "#/definitions/CreateOrUpdateSecretOption"
// responses:
//   "201":
//     description: response when creating a secret
//   "204":
//     description: response when updating a secret
//   "400":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"

// swagger:operation DELETE /orgs/{org}/actions/environments/{environment}/secrets/{secretname} organization deleteOrgEnvironmentSecret
// ---
// summary: Delete a secret of a deployment environment of an organization
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// - name: secretname
//   in: path
//   description: name of the secret
//   type: string
//   required: true
// responses:
//   "204":
//     description: response when deleting a secret
//   "400":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"

// swagger:operation GET /orgs/{org}/actions/environments/{environment}/variables organization getOrgEnvironmentVariablesList
// ---
// summary: List the variables of a deployment environment of an organization
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// - name: page
//   in: query
//   description: page number of results to return (1-based)
//   type: integer
// - name: limit
//   in: query
//   description: page size of results
//   type: integer
// responses:
//   "200":
//     "$ref": "#/responses/VariableList"
//   "400":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"

// swagger:operation GET /orgs/{org}/actions/environments/{environment}/variables/{variablename} organization getOrgEnvironmentVariable
// ---
// summary: Get a variable of a deployment environment of an organization
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// - name: variablename
//   in: path
//   description: name of the variable
//   type: string
//   required: true
// responses:
//   "200":
//     "$ref": "#/responses/ActionVariable"
//   "400":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"

// swagger:operation POST /orgs/{org}/actions/environments/{environment}/variables/{variablename} organization createOrgEnvironmentVariable
// ---
// summary: Create a variable of a deployment environment of an organization
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// - name: variablename
//   in: path
//   description: name of the variable
//   type: string
//   required: true
// - name: body
//   in: body
//   schema:
//     "$ref": "#/definitions/CreateVariableOption"
// responses:
//   "201":
//     description: response when creating a variable
//   "400":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "409":
//     description: variable name already exists

// swagger:operation PUT /orgs/{org}/actions/environments/{environment}/variables/{variablename} organization updateOrgEnvironmentVariable
// ---
// summary: Update a variable of a deployment environment of an organization
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// - name: variablename
//   in: path
//   description: name of the variable
//   type: string
//   required: true
// - name: body
//   in: body
//   schema:
//     "$ref": "#/definitions/UpdateVariableOption"
// responses:
//   "201":
//     description: response when updating a variable
//   "204":
//     description: response when updating a variable
//   "400":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"

// swagger:operation DELETE /orgs/{org}/actions/environments/{environment}/variables/{variablename} organization deleteOrgEnvironmentVariable
// ---
// summary: Delete a variable of a deployment environment of an organization
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   description: name of the organization
//   type: string
//   required: true
// - name: environment
//   in: path
//   description: name of the environment, matched ignoring case
//   type: string
//   required: true
// - name: variablename
//   in: path
//   description: name of the variable
//   type: string
//   required: true
// responses:
//   "204":
//     description: response when deleting a variable
//   "400":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
