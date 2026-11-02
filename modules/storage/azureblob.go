// Copyright 2024 The Gitea Authors. All rights reserved.
// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package storage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
	"unicode"

	"forgejo.org/modules/log"
	"forgejo.org/modules/proxy"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

var _ ObjectStorage = &AzureBlobStorage{}

// azureBlobObject reads a blob with one ranged download, restarted after a Seek
type azureBlobObject struct {
	ctx     context.Context
	client  *blob.Client
	name    string
	size    int64
	modTime time.Time
	offset  int64
	body    io.ReadCloser
}

func (a *azureBlobObject) Read(p []byte) (int, error) {
	if a.offset >= a.size {
		return 0, io.EOF
	}
	if a.body == nil {
		res, err := a.client.DownloadStream(a.ctx, &blob.DownloadStreamOptions{
			Range: blob.HTTPRange{Offset: a.offset},
		})
		if err != nil {
			return 0, convertAzureBlobErr(err)
		}
		a.body = res.Body
	}
	n, err := a.body.Read(p)
	a.offset += int64(n)
	return n, err
}

func (a *azureBlobObject) Close() error {
	if a.body == nil {
		return nil
	}
	err := a.body.Close()
	a.body = nil
	return err
}

func (a *azureBlobObject) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += a.offset
	case io.SeekEnd:
		offset += a.size
	default:
		return 0, errors.New("Seek: invalid whence")
	}
	if offset < 0 || offset > a.size {
		return 0, errors.New("Seek: invalid offset")
	}
	if offset != a.offset {
		_ = a.Close()
		a.offset = offset
	}
	return a.offset, nil
}

func (a *azureBlobObject) Stat() (os.FileInfo, error) {
	return &azureBlobFileInfo{name: path.Base(a.name), size: a.size, modTime: a.modTime}, nil
}

// AzureBlobStorage returns an azure blob storage
type AzureBlobStorage struct {
	cfg       *setting.AzureBlobStorageConfig
	ctx       context.Context
	client    *azblob.Client
	sharedKey *azblob.SharedKeyCredential // nil when using the default azure credential

	udcMu     sync.Mutex
	udc       *service.UserDelegationCredential
	udcExpiry time.Time
}

func convertAzureBlobErr(err error) error {
	if err == nil {
		return nil
	}
	if bloberror.HasCode(err, bloberror.BlobNotFound, bloberror.ContainerNotFound, bloberror.ResourceNotFound) {
		return os.ErrNotExist
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
		return os.ErrNotExist
	}
	return err
}

// newAzureBlobCredential returns a shared key credential if an account key is set, otherwise the default azure credential (managed identity, workload identity, ...)
func newAzureBlobCredential(cfg setting.AzureBlobStorageConfig) (azcore.TokenCredential, *azblob.SharedKeyCredential, error) {
	if cfg.AccountKey != "" {
		cred, err := azblob.NewSharedKeyCredential(cfg.AccountName, cfg.AccountKey)
		return nil, cred, err
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	return cred, nil, err
}

// NewAzureBlobStorage returns an azure blob storage
func NewAzureBlobStorage(ctx context.Context, cfg *setting.Storage) (ObjectStorage, error) {
	initCtx, cancel := context.WithTimeout(ctx, initializationTimeout)
	defer cancel()

	config := cfg.AzureBlobConfig

	log.Info("Creating Azure Blob storage at %s:%s with base path %s", config.Endpoint, config.Container, config.BasePath)

	tokenCred, sharedKey, err := newAzureBlobCredential(config)
	if err != nil {
		return nil, err
	}
	opts := &azblob.ClientOptions{ClientOptions: azcore.ClientOptions{
		Transport: &http.Client{Transport: &http.Transport{Proxy: proxy.Proxy()}},
	}}
	var client *azblob.Client
	if sharedKey != nil {
		log.Info("Azure Blob storage uses a shared key credential")
		client, err = azblob.NewClientWithSharedKeyCredential(config.Endpoint, sharedKey, opts)
	} else {
		log.Info("Azure Blob storage uses the default Azure credential")
		client, err = azblob.NewClient(config.Endpoint, tokenCred, opts)
	}
	if err != nil {
		return nil, err
	}

	// check before creating, so an identity that may only use an existing container works
	containerClient := client.ServiceClient().NewContainerClient(config.Container)
	if _, err := containerClient.GetProperties(initCtx, nil); bloberror.HasCode(err, bloberror.ContainerNotFound) {
		// no Access option: the container stays private
		_, err = containerClient.Create(initCtx, nil)
		if err != nil && !bloberror.HasCode(err, bloberror.ContainerAlreadyExists) {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return &AzureBlobStorage{
		cfg:       &config,
		ctx:       ctx,
		client:    client,
		sharedKey: sharedKey,
	}, nil
}

func (a *AzureBlobStorage) buildAzureBlobPath(p string) string {
	p = strings.TrimPrefix(util.PathJoinRelX(a.cfg.BasePath, p), "/") // object store doesn't use slash for root path
	if p == "." {
		p = "" // object store doesn't use dot as relative path
	}
	return p
}

func (a *AzureBlobStorage) buildAzureBlobDirPrefix(p string) string {
	// ending slash is required for avoiding matching like "foo/" and "foobar/" with prefix "foo"
	p = a.buildAzureBlobPath(p) + "/"
	if p == "/" {
		p = "" // object store doesn't use slash for root path
	}
	return p
}

func (a *AzureBlobStorage) getBlobClient(name string) *blob.Client {
	return a.client.ServiceClient().NewContainerClient(a.cfg.Container).NewBlobClient(name)
}

// Open opens a file
func (a *AzureBlobStorage) Open(path string) (Object, error) {
	name := a.buildAzureBlobPath(path)
	blobClient := a.getBlobClient(name)
	res, err := blobClient.GetProperties(a.ctx, nil)
	if err != nil {
		return nil, convertAzureBlobErr(err)
	}
	return &azureBlobObject{
		ctx:     a.ctx,
		client:  blobClient,
		name:    name,
		size:    *res.ContentLength,
		modTime: *res.LastModified,
	}, nil
}

// Save saves a file to azure blob storage
func (a *AzureBlobStorage) Save(path string, r io.Reader, size int64) (int64, error) {
	rd := &countingReader{Reader: r}
	_, err := a.client.UploadStream(a.ctx, a.cfg.Container, a.buildAzureBlobPath(path), rd, nil)
	if err != nil {
		return 0, convertAzureBlobErr(err)
	}
	return rd.n, nil
}

type countingReader struct {
	io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	c.n += int64(n)
	return n, err
}

type azureBlobFileInfo struct {
	name    string
	size    int64
	modTime time.Time
}

func (a azureBlobFileInfo) Name() string {
	return a.name
}

func (a azureBlobFileInfo) Size() int64 {
	return a.size
}

func (a azureBlobFileInfo) ModTime() time.Time {
	return a.modTime
}

func (a azureBlobFileInfo) IsDir() bool {
	return strings.HasSuffix(a.name, "/")
}

func (a azureBlobFileInfo) Mode() os.FileMode {
	return os.ModePerm
}

func (a azureBlobFileInfo) Sys() any {
	return nil
}

// Stat returns the stat information of the object
func (a *AzureBlobStorage) Stat(p string) (os.FileInfo, error) {
	name := a.buildAzureBlobPath(p)
	res, err := a.getBlobClient(name).GetProperties(a.ctx, nil)
	if err != nil {
		return nil, convertAzureBlobErr(err)
	}
	return &azureBlobFileInfo{name: path.Base(name), size: *res.ContentLength, modTime: *res.LastModified}, nil
}

// Delete delete a file
func (a *AzureBlobStorage) Delete(path string) error {
	_, err := a.getBlobClient(a.buildAzureBlobPath(path)).Delete(a.ctx, nil)
	return convertAzureBlobErr(err)
}

// userDelegationCredential returns a cached user delegation key, valid for at least 10 more minutes
func (a *AzureBlobStorage) userDelegationCredential(now time.Time) (*service.UserDelegationCredential, error) {
	a.udcMu.Lock()
	defer a.udcMu.Unlock()
	if a.udc == nil || a.udcExpiry.Sub(now) < 10*time.Minute {
		expiry := now.Add(time.Hour)
		udc, err := a.client.ServiceClient().GetUserDelegationCredential(a.ctx, service.KeyInfo{
			Start:  new(now.Add(-time.Minute).Format(sas.TimeFormat)),
			Expiry: new(expiry.Format(sas.TimeFormat)),
		}, nil)
		if err != nil {
			return nil, convertAzureBlobErr(err)
		}
		a.udc, a.udcExpiry = udc, expiry
	}
	return a.udc, nil
}

// URL gets a read-only SAS URL for a single blob. The link is valid for 5 minutes.
func (a *AzureBlobStorage) URL(path, name string, reqParams url.Values) (*url.URL, error) {
	blobName := a.buildAzureBlobPath(path)
	if blobName == "" {
		return nil, os.ErrNotExist // an empty blob name would sign a container SAS (sr=c)
	}
	now := time.Now().UTC()
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	values := sas.BlobSignatureValues{
		Protocol:           sas.ProtocolHTTPS,
		StartTime:          now.Add(-time.Minute),
		ExpiryTime:         now.Add(5 * time.Minute),
		Permissions:        (&sas.BlobPermissions{Read: true}).String(),
		ContainerName:      a.cfg.Container,
		BlobName:           blobName,
		ContentDisposition: "attachment; filename=\"" + quoteEscaper.Replace(name) + "\"",
		ContentType:        reqParams.Get("response-content-type"),
	}
	if strings.HasPrefix(a.cfg.Endpoint, "http://") {
		values.Protocol = sas.ProtocolHTTPSandHTTP
	}

	var params sas.QueryParameters
	var err error
	if a.sharedKey != nil {
		params, err = values.SignWithSharedKey(a.sharedKey)
	} else {
		var udc *service.UserDelegationCredential
		if udc, err = a.userDelegationCredential(now); err == nil {
			params, err = values.SignWithUserDelegation(udc)
		}
	}
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(a.getBlobClient(blobName).URL())
	if err != nil {
		return nil, err
	}
	u.RawQuery = params.Encode()
	return u, nil
}

// IterateObjects iterates across the objects in the azure blob storage
func (a *AzureBlobStorage) IterateObjects(dirName string, fn func(path string, obj Object) error) error {
	prefix := a.buildAzureBlobDirPrefix(dirName)
	basePrefix := a.buildAzureBlobDirPrefix("")
	pager := a.client.NewListBlobsFlatPager(a.cfg.Container, &container.ListBlobsFlatOptions{
		Prefix: &prefix,
	})
	for pager.More() {
		resp, err := pager.NextPage(a.ctx)
		if err != nil {
			return convertAzureBlobErr(err)
		}
		for _, item := range resp.Segment.BlobItems {
			object := &azureBlobObject{
				ctx:     a.ctx,
				client:  a.getBlobClient(*item.Name),
				name:    *item.Name,
				size:    *item.Properties.ContentLength,
				modTime: *item.Properties.LastModified,
			}
			if err := func() error {
				defer object.Close()
				return fn(strings.TrimPrefix(object.name, basePrefix), object)
			}(); err != nil {
				return convertAzureBlobErr(err)
			}
		}
	}
	return nil
}

func init() {
	RegisterStorageType(setting.AzureBlobStorageType, NewAzureBlobStorage)
}
