// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package storage

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"forgejo.org/modules/setting"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Azurite's well-known development account
const azuriteAccountKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

func azuriteStorageConfig(t *testing.T, container, basePath string) *setting.Storage {
	t.Helper()
	endpoint := os.Getenv("TEST_AZURITE_URL")
	if endpoint == "" {
		t.Skip("TEST_AZURITE_URL not set")
	}
	return &setting.Storage{
		AzureBlobConfig: setting.AzureBlobStorageConfig{
			Endpoint:    "http://" + endpoint + "/devstoreaccount1/",
			AccountName: "devstoreaccount1",
			AccountKey:  azuriteAccountKey,
			Container:   container,
			BasePath:    basePath,
		},
	}
}

func TestAzureBlobStorageIterator(t *testing.T) {
	testStorageIterator(t, setting.AzureBlobStorageType, azuriteStorageConfig(t, "test-iterator", ""))
	testStorageIterator(t, setting.AzureBlobStorageType, azuriteStorageConfig(t, "test-iterator-base", "base/"))
}

func TestAzureBlobStorageObject(t *testing.T) {
	// a new container per run checks that a missing container is created
	s, err := NewStorage(setting.AzureBlobStorageType, azuriteStorageConfig(t, fmt.Sprintf("test-object-%d", time.Now().UnixNano()), "base/"))
	require.NoError(t, err)

	n, err := s.Save("x/test.txt", strings.NewReader("0123456789"), -1)
	require.NoError(t, err)
	assert.EqualValues(t, 10, n)

	fi, err := s.Stat("x/test.txt")
	require.NoError(t, err)
	assert.Equal(t, "test.txt", fi.Name())
	assert.EqualValues(t, 10, fi.Size())

	obj, err := s.Open("x/test.txt")
	require.NoError(t, err)
	defer obj.Close()
	buf := make([]byte, 2)
	_, err = obj.Seek(3, io.SeekStart)
	require.NoError(t, err)
	_, err = io.ReadFull(obj, buf)
	require.NoError(t, err)
	assert.Equal(t, "34", string(buf))
	_, err = obj.Seek(-2, io.SeekEnd)
	require.NoError(t, err)
	rest, err := io.ReadAll(obj)
	require.NoError(t, err)
	assert.Equal(t, "89", string(rest))
	_, err = obj.Seek(0, io.SeekStart)
	require.NoError(t, err)
	all, err := io.ReadAll(obj)
	require.NoError(t, err)
	assert.Equal(t, "0123456789", string(all))

	require.NoError(t, s.Delete("x/test.txt"))
	_, err = s.Stat("x/test.txt")
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = s.Open("x/test.txt")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestAzureBlobStorageURL(t *testing.T) {
	s, err := NewStorage(setting.AzureBlobStorageType, azuriteStorageConfig(t, "test-url", "base/"))
	require.NoError(t, err)
	_, err = s.Save("x/test.txt", strings.NewReader("content"), 7)
	require.NoError(t, err)

	u, err := s.URL("x/test.txt", "a\r\nb\".txt", map[string][]string{
		"response-content-type":  {"text/plain"},
		"response-cache-control": {"public"},
	})
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "b", q.Get("sr"))
	assert.Equal(t, "r", q.Get("sp"))
	assert.Equal(t, `attachment; filename="ab\".txt"`, q.Get("rscd"))
	assert.Equal(t, "text/plain", q.Get("rsct"))
	assert.Empty(t, q.Get("rscc"))
	assert.Equal(t, "/devstoreaccount1/test-url/base/x/test.txt", u.Path)

	resp, err := http.Get(u.String())
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "content", string(body))
	assert.Equal(t, `attachment; filename="ab\".txt"`, resp.Header.Get("Content-Disposition"))
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))

	root, err := NewStorage(setting.AzureBlobStorageType, azuriteStorageConfig(t, "test-url", ""))
	require.NoError(t, err)
	_, err = root.URL("", "name", nil)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestAzureBlobCredential(t *testing.T) {
	tokenCred, sharedKey, err := newAzureBlobCredential(setting.AzureBlobStorageConfig{AccountName: "account"})
	require.NoError(t, err)
	assert.Nil(t, sharedKey)
	assert.IsType(t, &azidentity.DefaultAzureCredential{}, tokenCred)

	tokenCred, sharedKey, err = newAzureBlobCredential(setting.AzureBlobStorageConfig{AccountName: "account", AccountKey: azuriteAccountKey})
	require.NoError(t, err)
	assert.Nil(t, tokenCred)
	require.NotNil(t, sharedKey)
	assert.Equal(t, "account", sharedKey.AccountName())
}
