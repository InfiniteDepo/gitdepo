// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit_test

import (
	"sync"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The canonical form and the hash are an external contract (auditors recompute them): never change these values.
func TestCanonicalGolden(t *testing.T) {
	e := &audit_model.Entry{
		ID: 7, CreatedUnix: 1700000000, Action: "auth.signin", Category: "auth", Result: "success",
		ActorType: "user", ActorID: 2, ActorName: "user2", SudoByID: 3,
		CredentialType: "access_token", CredentialID: 4, CredentialName: "t<&>", CredentialOwnerID: 2,
		IP: "192.0.2.1", UserAgent: "ua\"é", RequestID: "rid", OwnerID: 5, GroupID: 6, RepoID: 8, SubjectUserID: 2,
		TargetType: "access_token", TargetID: 9, TargetName: "tn", Data: `{"a":1}`,
	}
	canonical, err := audit_model.Canonical(e)
	require.NoError(t, err)
	assert.Equal(t, `[7,1700000000,"auth.signin","auth","success","user",2,"user2",3,"access_token",4,"t\u003c\u0026\u003e",2,"192.0.2.1","ua\"é","rid",5,6,8,2,"access_token",9,"tn","{\"a\":1}"]`, string(canonical))

	hash, err := audit_model.HashEntry(audit_model.ZeroHash, e)
	require.NoError(t, err)
	assert.Equal(t, "0901d96df6dc5433400b425bdd1bbf3140449fe85ec2fbd7405a7e45bf215dbd", hash)
	assert.Len(t, hash, 64)
}

// A fresh install has no head row (migrations are recorded, not run): reading works and writes nothing.
func TestGetHeadEmpty(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	_, err := db.GetEngine(t.Context()).Exec("DELETE FROM audit_chain_head")
	require.NoError(t, err)

	head, err := audit_model.GetHead(t.Context())
	require.NoError(t, err)
	assert.EqualValues(t, 0, head.Seq)
	assert.Equal(t, audit_model.ZeroHash, head.Hash)
	assert.Equal(t, audit_model.ZeroHash, head.AnchorPrevHash)
	n, err := db.GetEngine(t.Context()).Count(new(audit_model.ChainHead))
	require.NoError(t, err)
	assert.Zero(t, n)
}

func TestEnsureHeadConcurrent(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	_, err := db.GetEngine(t.Context()).Exec("DELETE FROM audit_chain_head")
	require.NoError(t, err)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- audit_model.EnsureHead(t.Context()) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	n, err := db.GetEngine(t.Context()).Count(new(audit_model.ChainHead))
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	require.NoError(t, audit_model.EnsureHead(t.Context())) // and again when it exists
}
