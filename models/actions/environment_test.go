// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvironmentNormalize(t *testing.T) {
	valid := func() *ActionEnvironment {
		return &ActionEnvironment{
			RepoID: 1, Name: "  Production ",
			RefPolicy: EnvironmentRefPatterns, RefPatterns: []EnvironmentRefPattern{{EnvironmentPatternBranch, "release/*"}, {EnvironmentPatternTag, "v**"}},
			WaitTimerMinutes: 5, RunnerLabels: []string{"deploy", "docker:host"},
		}
	}
	e := valid()
	require.NoError(t, e.Normalize())
	assert.Equal(t, "Production", e.Name, "the name is trimmed")
	assert.Equal(t, "production", e.LowerName)

	empty := &ActionEnvironment{RepoID: 1, Name: "x"}
	require.NoError(t, empty.Normalize())
	assert.NotNil(t, empty.RefPatterns, "stored as [], never null")
	assert.NotNil(t, empty.RunnerLabels)

	for name, change := range map[string]func(*ActionEnvironment){
		"empty name":               func(e *ActionEnvironment) { e.Name = "  " },
		"name too long":            func(e *ActionEnvironment) { e.Name = strings.Repeat("a", 256) },
		"lowercase longer":         func(e *ActionEnvironment) { e.Name = strings.Repeat("Ⱥ", 127) },
		"name with newline":        func(e *ActionEnvironment) { e.Name = "a\nb" },
		"name with NUL":            func(e *ActionEnvironment) { e.Name = "a\x00b" },
		"name not UTF-8":           func(e *ActionEnvironment) { e.Name = "a\xffb" },
		"name with zero width":     func(e *ActionEnvironment) { e.Name = "prod\u200buction" },
		"name with bidi override":  func(e *ActionEnvironment) { e.Name = "prod\u202euction" },
		"name with nbsp":           func(e *ActionEnvironment) { e.Name = "prod\u00a0uction" },
		"name with private use":    func(e *ActionEnvironment) { e.Name = "prod\ue000uction" },
		"name with Cyrillic o":     func(e *ActionEnvironment) { e.Name = "pr\u043ed" },
		"name fullwidth":           func(e *ActionEnvironment) { e.Name = "\uff30\uff52\uff4f\uff44" },
		"name with combining":      func(e *ActionEnvironment) { e.Name = "pro\u0301d" },
		"name with dotted I":       func(e *ActionEnvironment) { e.Name = "PR\u0130D" },
		"name with Kelvin sign":    func(e *ActionEnvironment) { e.Name = "\u212aprod" },
		"name with tab":            func(e *ActionEnvironment) { e.Name = "pro\td" },
		"name with unicode space":  func(e *ActionEnvironment) { e.Name = "prod\u2003" },
		"name with DEL":            func(e *ActionEnvironment) { e.Name = "pro\x7fd" },
		"name of dots":             func(e *ActionEnvironment) { e.Name = ".." },
		"name of one dot":          func(e *ActionEnvironment) { e.Name = "." },
		"name with slash":          func(e *ActionEnvironment) { e.Name = "a/b" },
		"name with question mark":  func(e *ActionEnvironment) { e.Name = "a?b" },
		"name with hash":           func(e *ActionEnvironment) { e.Name = "a#b" },
		"name with percent":        func(e *ActionEnvironment) { e.Name = "a%2fb" },
		"name with backslash":      func(e *ActionEnvironment) { e.Name = "a\\b" },
		"allowed workflow empty":   func(e *ActionEnvironment) { e.AllowedWorkflows = []string{""} },
		"allowed workflow unicode": func(e *ActionEnvironment) { e.AllowedWorkflows = []string{"d\u0435ploy.yml"} },
		"allowed workflow control": func(e *ActionEnvironment) { e.AllowedWorkflows = []string{"deploy\n.yml"} },
		"allowed workflow broken":  func(e *ActionEnvironment) { e.AllowedWorkflows = []string{"deploy[.yml"} },
		"allowed workflow long":    func(e *ActionEnvironment) { e.AllowedWorkflows = []string{strings.Repeat("a", 256)} },
		"too many allowed workflows": func(e *ActionEnvironment) {
			e.AllowedWorkflows = make([]string, MaxAllowedWorkflows+1)
			for i := range e.AllowedWorkflows {
				e.AllowedWorkflows[i] = fmt.Sprintf("w%d.yml", i)
			}
		},
		"unknown policy":          func(e *ActionEnvironment) { e.RefPolicy = 3 },
		"negative policy":         func(e *ActionEnvironment) { e.RefPolicy = -1 },
		"patterns without policy": func(e *ActionEnvironment) { e.RefPolicy = EnvironmentRefAny },
		"policy without patterns": func(e *ActionEnvironment) { e.RefPatterns = nil },
		"too many patterns": func(e *ActionEnvironment) {
			e.RefPatterns = make([]EnvironmentRefPattern, MaxRefPatterns+1)
			for i := range e.RefPatterns {
				e.RefPatterns[i] = EnvironmentRefPattern{EnvironmentPatternBranch, fmt.Sprint("b", i)}
			}
		},
		"unknown pattern type":  func(e *ActionEnvironment) { e.RefPatterns[0].Type = "commit" },
		"empty pattern":         func(e *ActionEnvironment) { e.RefPatterns[0].Pattern = "" },
		"long pattern":          func(e *ActionEnvironment) { e.RefPatterns[0].Pattern = strings.Repeat("a", 256) },
		"pattern with control":  func(e *ActionEnvironment) { e.RefPatterns[0].Pattern = "a\tb" },
		"pattern with format":   func(e *ActionEnvironment) { e.RefPatterns[0].Pattern = "a\u200bb" },
		"pattern with Cyrillic": func(e *ActionEnvironment) { e.RefPatterns[0].Pattern = "rel\u0435ase/*" },
		"pattern with Kelvin":   func(e *ActionEnvironment) { e.RefPatterns[0].Pattern = "\u212a*" },
		"pattern that doesn't compile": func(e *ActionEnvironment) {
			e.RefPatterns[0].Pattern = "a[" // an open character class
		},
		"negative timer": func(e *ActionEnvironment) { e.WaitTimerMinutes = -1 },
		"timer too long": func(e *ActionEnvironment) { e.WaitTimerMinutes = MaxWaitTimerMinutes + 1 },
		"too many labels": func(e *ActionEnvironment) {
			e.RunnerLabels = nil
			for i := 0; i <= MaxRunnerLabels; i++ {
				e.RunnerLabels = append(e.RunnerLabels, fmt.Sprint("l", i))
			}
		},
		"empty label":         func(e *ActionEnvironment) { e.RunnerLabels = []string{""} },
		"long label":          func(e *ActionEnvironment) { e.RunnerLabels = []string{strings.Repeat("l", 256)} },
		"label with CR":       func(e *ActionEnvironment) { e.RunnerLabels = []string{"a\rb"} },
		"label with nbsp":     func(e *ActionEnvironment) { e.RunnerLabels = []string{"a\u00a0b"} },
		"label with Cyrillic": func(e *ActionEnvironment) { e.RunnerLabels = []string{"d\u043ecker"} },
		"duplicate labels":    func(e *ActionEnvironment) { e.RunnerLabels = []string{"a", "b", "a"} },
	} {
		t.Run(name, func(t *testing.T) {
			e := valid()
			change(e)
			require.ErrorIs(t, e.Normalize(), util.ErrInvalidArgument)
		})
	}

	maxed := valid()
	maxed.WaitTimerMinutes = MaxWaitTimerMinutes
	maxed.Name = strings.Repeat("a", 255)
	require.NoError(t, maxed.Normalize())
}

func TestEnvironmentAllowsRef(t *testing.T) {
	patterns := func(p ...EnvironmentRefPattern) *ActionEnvironment {
		return &ActionEnvironment{RefPolicy: EnvironmentRefPatterns, RefPatterns: p}
	}
	branch := func(p string) EnvironmentRefPattern { return EnvironmentRefPattern{EnvironmentPatternBranch, p} }
	tag := func(p string) EnvironmentRefPattern { return EnvironmentRefPattern{EnvironmentPatternTag, p} }

	for _, tc := range []struct {
		name string
		env  *ActionEnvironment
		ref  string
		want bool
	}{
		{"any: branch", &ActionEnvironment{}, "refs/heads/main", true},
		{"any: pull request", &ActionEnvironment{}, "refs/pull/3/head", true},
		{"any: empty ref", &ActionEnvironment{}, "", true},
		{"protected branches is decided by the caller", &ActionEnvironment{RefPolicy: EnvironmentRefProtectedBranches}, "refs/heads/main", false},
		{"exact branch", patterns(branch("main")), "refs/heads/main", true},
		{"other branch", patterns(branch("main")), "refs/heads/main2", false},
		{"star stops at a slash", patterns(branch("release/*")), "refs/heads/release/1.0", true},
		{"star doesn't cross a slash", patterns(branch("release/*")), "refs/heads/release/a/b", false},
		{"star alone doesn't cross a slash", patterns(branch("*")), "refs/heads/feature/x", false},
		{"double star crosses a slash", patterns(branch("release/**")), "refs/heads/release/a/b", true},
		{"double star alone", patterns(branch("**")), "refs/heads/feature/x", true},
		{"the pattern is not a prefix", patterns(branch("release")), "refs/heads/release/1", false},
		{"question mark", patterns(branch("v?")), "refs/heads/v1", true},
		{"question mark isn't a slash", patterns(branch("v?x")), "refs/heads/v/x", false},
		{"a tag pattern allows a tag", patterns(tag("v*")), "refs/tags/v1", true},
		{"a tag pattern doesn't allow the branch of that name", patterns(tag("v1")), "refs/heads/v1", false},
		{"a branch pattern doesn't allow the tag of that name", patterns(branch("v1")), "refs/tags/v1", false},
		{"second pattern", patterns(branch("a"), tag("b")), "refs/tags/b", true},
		{"pull request ref matches no pattern", patterns(branch("**"), tag("**")), "refs/pull/3/head", false},
		{"the ref prefix is not part of the name", patterns(branch("refs/heads/main")), "refs/heads/main", false},
		{"a ref of another kind", patterns(branch("**")), "refs/notes/x", false},
		{"no ref", patterns(branch("**")), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.env.AllowsRef(tc.ref))
		})
	}

	// a pattern that compiles but panics when it matches counts as no match
	assert.NotPanics(t, func() { assert.False(t, matchPattern("?a{}{,*", "xa")) })
}

func TestEnvironmentLifecycle(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	since := auditMax(t)

	prod := &ActionEnvironment{RepoID: 1, Name: "Production", RefPolicy: EnvironmentRefPatterns, RefPatterns: []EnvironmentRefPattern{{EnvironmentPatternBranch, "main"}}}
	require.NoError(t, CreateEnvironment(ctx, prod, nil))
	assert.NotZero(t, prod.ID)
	assert.EqualValues(t, 0, prod.OwnerID)
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{RepoID: 1, Name: "PRODUCTION"}, nil), ErrEnvironmentExists, "a twin of another case")
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{RepoID: 1, Name: "a\nb"}, nil), util.ErrInvalidArgument)
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{Name: "x"}, nil), util.ErrInvalidArgument, "needs a repository")
	require.NoError(t, CreateEnvironment(ctx, &ActionEnvironment{RepoID: 2, Name: "Production"}, nil), "the name is per repository")

	for _, name := range []string{"production", "PRODUCTION", " Production "} {
		found, err := GetEnvironmentByName(ctx, 0, 1, name)
		require.NoError(t, err, name)
		assert.Equal(t, prod.ID, found.ID, name)
		assert.Equal(t, "Production", found.Name)
		assert.Equal(t, []EnvironmentRefPattern{{EnvironmentPatternBranch, "main"}}, found.RefPatterns)
	}
	_, err := GetEnvironmentByName(ctx, 0, 3, "production")
	require.ErrorIs(t, err, ErrEnvironmentNotFound)
	_, err = GetEnvironmentByID(ctx, 0, 2, prod.ID)
	require.ErrorIs(t, err, ErrEnvironmentNotFound, "another repository's environment")

	// auto-create: no rules, and a twin finds the environment that exists
	staging, err := GetOrCreateRepoEnvironment(ctx, 1, "Staging")
	require.NoError(t, err)
	assert.Equal(t, EnvironmentRefAny, staging.RefPolicy)
	assert.Empty(t, staging.RefPatterns)
	assert.Zero(t, staging.WaitTimerMinutes)
	assert.Empty(t, staging.RunnerLabels)
	assert.True(t, staging.CreatedByWorkflow, "a workflow created it")
	assert.False(t, prod.CreatedByWorkflow)
	twin, err := GetOrCreateRepoEnvironment(ctx, 1, "staging")
	require.NoError(t, err)
	assert.Equal(t, staging.ID, twin.ID)
	again, err := GetOrCreateRepoEnvironment(ctx, 1, "production")
	require.NoError(t, err)
	assert.Equal(t, prod.ID, again.ID, "an environment with rules is found, not replaced by an unprotected twin")
	assert.Equal(t, EnvironmentRefPatterns, again.RefPolicy)
	_, err = GetOrCreateRepoEnvironment(ctx, 1, "bad\nname")
	require.ErrorIs(t, err, util.ErrInvalidArgument)
	_, err = GetOrCreateRepoEnvironment(ctx, 1, strings.Repeat("a", 256))
	require.ErrorIs(t, err, util.ErrInvalidArgument)

	envs, count, err := FindEnvironments(ctx, 0, 1, db.ListOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 2)
	assert.EqualValues(t, 2, count)
	assert.Equal(t, "Production", envs[0].Name)
	envs, count, err = FindEnvironments(ctx, 0, 1, db.ListOptions{Page: 2, PageSize: 1})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	assert.EqualValues(t, 2, count, "the count is of every page")
	assert.Equal(t, "staging", envs[0].LowerName)

	// an update changes the rules, not the name's identity
	prod.RefPolicy, prod.RefPatterns, prod.WaitTimerMinutes, prod.Name = EnvironmentRefProtectedBranches, nil, 10, "PRODUCTION"
	require.NoError(t, UpdateEnvironment(ctx, prod, nil))
	stored, err := GetEnvironmentByID(ctx, 0, 1, prod.ID)
	require.NoError(t, err)
	assert.Equal(t, "PRODUCTION", stored.Name)
	assert.Equal(t, 10, stored.WaitTimerMinutes)
	assert.Empty(t, stored.RefPatterns)
	require.NoError(t, UpdateEnvironment(ctx, stored, nil), "an update without a change records nothing")
	renamed := *stored
	renamed.Name = "Live"
	require.ErrorIs(t, UpdateEnvironment(ctx, &renamed, nil), util.ErrInvalidArgument)

	// secrets and variables of an environment go with it; the deployments stay
	secret, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 1, prod.ID, "token", "s3cr3t-value")
	require.NoError(t, err)
	_, err = InsertEnvironmentVariable(ctx, 0, 1, prod.ID, "color", "blue")
	require.NoError(t, err)
	other, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 1, staging.ID, "token", "other")
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &ActionDeployment{RepoID: 1, EnvironmentID: prod.ID, JobID: 1, Attempt: 1, Status: DeploymentReleased}))
	require.NoError(t, DeleteEnvironment(ctx, prod, func(context.Context) error { return nil }))
	_, err = GetEnvironmentByID(ctx, 0, 1, prod.ID)
	require.ErrorIs(t, err, ErrEnvironmentNotFound)
	unittest.AssertNotExistsBean(t, &secret_model.Secret{ID: secret.ID})
	unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: other.ID})
	unittest.AssertNotExistsBean(t, &ActionVariable{EnvironmentID: prod.ID})
	unittest.AssertExistsAndLoadBean(t, &ActionDeployment{EnvironmentID: prod.ID})

	var actions []string
	var created, deleted map[string]any
	for _, e := range auditEntries(t, since) {
		if e.Action == "repo.actions_env.deleted" {
			deleted = entryData(t, e)
		}
		actions = append(actions, e.Action)
		if e.Action == "repo.actions_env.created" && e.TargetID == staging.ID {
			created = entryData(t, e)
		}
		assert.NotContains(t, e.Data, "s3cr3t-value")
	}
	assert.Equal(t, []string{
		"repo.actions_env.created", "repo.actions_env.created", "repo.actions_env.created", // Production of repository 1 and 2, Staging
		"repo.actions_env.updated",
		"repo.actions_env_secret.created", "repo.actions_env_variable.created", "repo.actions_env_secret.created",
		"repo.actions_env.deleted",
	}, actions)
	assert.Equal(t, true, created["auto"])
	assert.Equal(t, "Staging", created["name"])
	// the entry of the deletion keeps the rules that were removed, and counts what went with them
	assert.EqualValues(t, "PRODUCTION", deleted["name"])
	assert.EqualValues(t, EnvironmentRefProtectedBranches, deleted["ref_policy"])
	assert.EqualValues(t, 10, deleted["wait_timer_minutes"])
	for _, key := range []string{"ref_patterns", "prevent_self_review", "runner_labels"} {
		assert.Contains(t, deleted, key)
	}
	assert.Equal(t, map[string]any{"secrets": float64(1), "variables": float64(1)}, deleted["counts"])
}

// Concurrent first uses of one name create one environment and none fails.
func TestEnvironmentConcurrentCreate(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	var wg sync.WaitGroup
	ids := make([]int64, 6)
	errs := make([]error, len(ids))
	for i := range ids {
		wg.Go(func() {
			name := "Concurrent"
			if i%2 == 0 {
				name = "CONCURRENT"
			}
			env, err := GetOrCreateRepoEnvironment(ctx, 1, name)
			errs[i] = err
			if err == nil {
				ids[i] = env.ID
			}
		})
	}
	wg.Wait()
	for i := range ids {
		require.NoError(t, errs[i])
		assert.Equal(t, ids[0], ids[i])
	}
	count, err := db.GetEngine(ctx).Where("repo_id = 1").Count(new(ActionEnvironment))
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}

func TestEnvironmentLimit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	for i := range MaxEnvironments {
		_, err := GetOrCreateRepoEnvironment(ctx, 1, fmt.Sprint("env-", i))
		require.NoError(t, err)
	}
	_, err := GetOrCreateRepoEnvironment(ctx, 1, "one-too-many")
	require.ErrorIs(t, err, ErrEnvironmentLimit)
	require.ErrorIs(t, CreateEnvironment(ctx, &ActionEnvironment{RepoID: 1, Name: "also-too-many"}, nil), ErrEnvironmentLimit)
	existing, err := GetOrCreateRepoEnvironment(ctx, 1, "ENV-7")
	require.NoError(t, err, "an environment that exists is still found at the cap")
	assert.Equal(t, "env-7", existing.Name)
	_, err = GetOrCreateRepoEnvironment(ctx, 2, "other-repo")
	require.NoError(t, err, "the cap is per repository")
}

// No environment row shows up where the secrets and variables of a repository, project or organization are listed.
func TestEnvironmentRowsStayOutOfOtherLists(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	env, err := GetOrCreateRepoEnvironment(ctx, 1, "prod")
	require.NoError(t, err)

	_, err = secret_model.InsertEncryptedSecret(ctx, 0, 0, 1, "SHARED", "repo-value")
	require.NoError(t, err)
	_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 1, env.ID, "SHARED", "env-value")
	require.NoError(t, err, "the same name in the repository and in its environment")
	_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 1, env.ID, "ENV_ONLY", "env-value")
	require.NoError(t, err)
	_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 1, env.ID, "ENV_ONLY", "again")
	require.Error(t, err, "once per environment")
	_, err = InsertVariable(ctx, 0, 0, 1, "SHARED", "repo-value")
	require.NoError(t, err)
	_, err = InsertEnvironmentVariable(ctx, 0, 1, env.ID, "SHARED", "env-value")
	require.NoError(t, err)
	_, err = InsertEnvironmentVariable(ctx, 0, 1, env.ID, "ENV_ONLY", "env-value")
	require.NoError(t, err)

	repoSecrets, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{RepoID: 1})
	require.NoError(t, err)
	require.Len(t, repoSecrets, 1)
	assert.EqualValues(t, 0, repoSecrets[0].EnvironmentID)
	repoVariables, err := FindVariables(ctx, FindVariablesOpts{RepoID: 1})
	require.NoError(t, err)
	require.Len(t, repoVariables, 1)
	assert.Equal(t, "repo-value", repoVariables[0].Data)

	fetched, err := secret_model.FetchActionSecrets(ctx, 2, 0, 1)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"SHARED": "repo-value"}, fetched)
	vars, err := GetVariablesOfRun(ctx, &ActionRun{RepoID: 1, Repo: &repo_model.Repository{ID: 1, OwnerID: 2}})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"SHARED": "repo-value"}, vars)

	envSecrets, err := secret_model.FetchEnvironmentSecrets(ctx, 0, 1, env.ID)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"SHARED": "env-value", "ENV_ONLY": "env-value"}, envSecrets)
	other, err := secret_model.FetchEnvironmentSecrets(ctx, 0, 2, env.ID)
	require.NoError(t, err)
	assert.Empty(t, other, "an environment's secrets are read with its own repository")

	// a repository secret ID is not an environment secret ID, and the other way round
	_, err = secret_model.GetSecretByID(ctx, 0, 0, 1, repoSecrets[0].ID)
	require.NoError(t, err)
	envSecret, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{RepoID: 1, EnvironmentID: env.ID, Name: "ENV_ONLY"})
	require.NoError(t, err)
	require.Len(t, envSecret, 1)
	_, err = secret_model.GetSecretByID(ctx, 0, 0, 1, envSecret[0].ID)
	require.Error(t, err, "the repository secret endpoints can't reach an environment secret")
	_, err = secret_model.GetEnvironmentSecretByID(ctx, 0, 1, env.ID, envSecret[0].ID)
	require.NoError(t, err)
	_, err = secret_model.GetEnvironmentSecretByID(ctx, 0, 1, env.ID, repoSecrets[0].ID)
	require.Error(t, err)

	envVar, err := FindVariables(ctx, FindVariablesOpts{RepoID: 1, EnvironmentID: env.ID})
	require.NoError(t, err)
	require.Len(t, envVar, 2)
	deleted, err := DeleteVariable(ctx, envVar[0].ID, 0, 0, 1)
	require.NoError(t, err)
	assert.False(t, deleted, "the repository variable delete doesn't reach an environment variable")
	envVar[0].Data = "changed"
	updated, err := UpdateVariable(ctx, envVar[0])
	require.NoError(t, err)
	assert.True(t, updated)
	envVar[0].EnvironmentID = 0
	updated, err = UpdateVariable(ctx, envVar[0])
	require.NoError(t, err)
	assert.False(t, updated, "the same ID as a repository variable updates nothing")
}

// Every change of an environment's secrets and variables is recorded, never with a value.
func TestEnvironmentSecretVariableAudit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	env, err := GetOrCreateRepoEnvironment(ctx, 1, "prod")
	require.NoError(t, err)
	since := auditMax(t)

	secret, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 1, env.ID, "token", "first-secret-value")
	require.NoError(t, err)
	secret.SetData("second-secret-value")
	require.NoError(t, secret_model.UpdateSecret(ctx, secret, true))
	require.NoError(t, secret_model.DeleteSecret(ctx, secret))
	variable, err := InsertEnvironmentVariable(ctx, 0, 1, env.ID, "color", "first-variable-value")
	require.NoError(t, err)
	variable.Data = "second-variable-value"
	_, err = UpdateVariable(ctx, variable)
	require.NoError(t, err)
	_, err = DeleteEnvironmentVariable(ctx, variable.ID, 0, 1, env.ID)
	require.NoError(t, err)

	var actions []string
	for _, e := range auditEntries(t, since) {
		actions = append(actions, e.Action)
		assert.EqualValues(t, 1, e.RepoID)
		assert.EqualValues(t, env.ID, entryData(t, e)["environment_id"])
		assert.NotContains(t, e.Data, "secret-value")
		assert.NotContains(t, e.Data, "variable-value")
	}
	assert.Equal(t, []string{
		"repo.actions_env_secret.created", "repo.actions_env_secret.updated", "repo.actions_env_secret.deleted",
		"repo.actions_env_variable.created", "repo.actions_env_variable.updated", "repo.actions_env_variable.deleted",
	}, actions)
}

// Values of secrets and variables are at most 64 KiB at every level, an environment holds at most 100 of each, and
// only the doer's own act writes an environment's secrets, variables and rules, whoever calls the model.
func TestEnvironmentSecretVariableLimits(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	env, err := GetOrCreateRepoEnvironment(ctx, 1, "limits")
	require.NoError(t, err)

	big := strings.Repeat("x", secret_model.MaxValueSize+1)
	fits := strings.Repeat("x", secret_model.MaxValueSize)
	_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 1, env.ID, "BIG", big)
	require.ErrorIs(t, err, util.ErrInvalidArgument)
	_, err = secret_model.InsertEncryptedSecret(ctx, 0, 0, 1, "BIG", big)
	require.ErrorIs(t, err, util.ErrInvalidArgument, "a repository secret too")
	_, err = InsertEnvironmentVariable(ctx, 0, 1, env.ID, "BIG", big)
	require.ErrorIs(t, err, util.ErrInvalidArgument)
	_, err = InsertVariable(ctx, 2, 0, 0, "BIG", big)
	require.ErrorIs(t, err, util.ErrInvalidArgument, "an owner variable too")
	v, err := InsertEnvironmentVariable(ctx, 0, 1, env.ID, "FITS", fits)
	require.NoError(t, err)
	v.Data = big
	_, err = UpdateVariable(ctx, v)
	require.ErrorIs(t, err, util.ErrInvalidArgument, "an update too")

	for i := 1; i < secret_model.MaxPerEnvironment; i++ {
		_, err := InsertEnvironmentVariable(ctx, 0, 1, env.ID, fmt.Sprintf("V%d", i), "x")
		require.NoError(t, err)
	}
	for i := range secret_model.MaxPerEnvironment {
		_, err := secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 1, env.ID, fmt.Sprintf("S%d", i), "x")
		require.NoError(t, err)
	}
	_, err = InsertEnvironmentVariable(ctx, 0, 1, env.ID, "ONE_MORE", "x")
	require.ErrorIs(t, err, util.ErrInvalidArgument)
	_, err = secret_model.InsertEncryptedEnvironmentSecret(ctx, 0, 1, env.ID, "ONE_MORE", "x")
	require.ErrorIs(t, err, util.ErrInvalidArgument)
	_, err = InsertVariable(ctx, 0, 0, 1, "ONE_MORE", "x")
	require.NoError(t, err, "the repository level has no count cap")

	t.Run("own act", func(t *testing.T) {
		bare := t.Context() // no actor: can't be told from a delegated credential
		_, err := InsertEnvironmentVariable(bare, 0, 1, env.ID, "NOT_OWN", "x")
		require.ErrorIs(t, err, audit_model.ErrNotOwnAct)
		_, err = secret_model.InsertEncryptedEnvironmentSecret(bare, 0, 1, env.ID, "NOT_OWN", "x")
		require.ErrorIs(t, err, audit_model.ErrNotOwnAct)
		v.Data = "y"
		_, err = UpdateVariable(bare, v)
		require.ErrorIs(t, err, audit_model.ErrNotOwnAct)
		_, err = DeleteEnvironmentVariable(bare, v.ID, 0, 1, env.ID)
		require.ErrorIs(t, err, audit_model.ErrNotOwnAct)
		require.ErrorIs(t, UpdateEnvironment(bare, env, nil), audit_model.ErrNotOwnAct)
		require.ErrorIs(t, CreateEnvironment(bare, &ActionEnvironment{RepoID: 1, Name: "other"}, nil), audit_model.ErrNotOwnAct)
		require.ErrorIs(t, DeleteEnvironment(bare, env, func(context.Context) error { return nil }), audit_model.ErrNotOwnAct)
		_, err = InsertVariable(bare, 0, 0, 1, "REPO_LEVEL", "x")
		require.NoError(t, err, "the repository level keeps its own rules")
	})
}

// A look-alike or non-ASCII name finds no environment (the Kelvin sign lower-cases to an ASCII k) and creates none.
func TestEnvironmentNamesAreASCII(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := auditCtx()
	require.NoError(t, CreateEnvironment(ctx, &ActionEnvironment{RepoID: 1, Name: "Kprod"}, nil))
	got, err := GetEnvironmentByName(ctx, 0, 1, "  kPROD ")
	require.NoError(t, err)
	assert.Equal(t, "Kprod", got.Name)
	for _, name := range []string{"\u212aprod", "pr\u043ed", "Kprod\u00a0", ""} {
		_, err := GetEnvironmentByName(ctx, 0, 1, name)
		require.ErrorIs(t, err, ErrEnvironmentNotFound, name)
		_, err = GetOrCreateRepoEnvironment(ctx, 1, name)
		require.ErrorIs(t, err, util.ErrInvalidArgument, name)
	}
	n, err := db.GetEngine(ctx).Where("repo_id = 1").Count(new(ActionEnvironment))
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
}

func TestEnvironmentAllowsWorkflow(t *testing.T) {
	e := &ActionEnvironment{}
	assert.True(t, e.AllowsWorkflow("anything.yml"), "empty: any workflow")
	e.AllowedWorkflows = []string{"deploy.yml", "deploy-*.yml", "ci/**"}
	for workflow, want := range map[string]bool{
		"deploy.yml": true, "deploy-prod.yml": true, "deploy-.yml": true, "deploy-a/b.yml": false,
		"deploy.yaml": false, "xdeploy.yml": false, "Deploy.yml": false, "": false, "ci/a/b.yml": true,
	} {
		assert.Equal(t, want, e.AllowsWorkflow(workflow), workflow)
	}
}
