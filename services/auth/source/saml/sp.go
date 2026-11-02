// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"forgejo.org/modules/graceful"
	"forgejo.org/modules/log"
	"forgejo.org/modules/process"
	"forgejo.org/modules/proxy"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"

	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"golang.org/x/sync/singleflight"
)

const (
	metadataRefresh = time.Hour
	maxMetadataSize = 10 << 20
)

// The name ID formats offered in the admin form.
var NameIDFormats = []string{
	string(saml.PersistentNameIDFormat),
	string(saml.EmailAddressNameIDFormat),
	string(saml.UnspecifiedNameIDFormat),
	string(saml.TransientNameIDFormat),
}

// sourcePath is the path of the SAML endpoints of the named source below the AppURL.
func sourcePath(name, endpoint string) string {
	return "user/saml/" + url.PathEscape(name) + "/" + endpoint
}

// MetadataURL is the URL of the SP metadata, and the default SP entity ID.
func MetadataURL(name string) string {
	return setting.AppURL + sourcePath(name, "metadata")
}

// ACSURL is the URL where the IdP posts its responses.
func ACSURL(name string) string {
	return setting.AppURL + sourcePath(name, "acs")
}

// SLOURL is the URL of single logout.
func SLOURL(name string) string {
	return setting.AppURL + sourcePath(name, "slo")
}

// EntityID is the SP entity ID: the configured one or the metadata URL.
func (source *Source) EntityID() string {
	if source.SPEntityID != "" {
		return source.SPEntityID
	}
	return MetadataURL(source.authSource.Name)
}

// ParseCertificate reads a certificate in PEM or bare base64 DER form.
func ParseCertificate(s string) (*x509.Certificate, error) {
	s = strings.TrimSpace(s)
	var der []byte
	if block, _ := pem.Decode([]byte(s)); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("expected a CERTIFICATE PEM block, got %q", block.Type)
		}
		der = block.Bytes
	} else {
		var err error
		if der, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), "")); err != nil {
			return nil, errors.New("the certificate is neither PEM nor base64")
		}
	}
	return x509.ParseCertificate(der)
}

// ParsePrivateKey reads an RSA private key in PEM form (PKCS #1 or PKCS #8) of at least 2048 bits.
func ParsePrivateKey(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(s)))
	if block == nil {
		return nil, errors.New("the private key is not PEM")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		var err error
		if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		if key, ok = k.(*rsa.PrivateKey); !ok {
			return nil, errors.New("the private key is not an RSA key")
		}
	default:
		return nil, fmt.Errorf("unsupported private key PEM block %q", block.Type)
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("the private key is shorter than 2048 bits")
	}
	return key, nil
}

// ValidationError says which field of the admin form Validate refused (Field is the form name without the "saml_"
// prefix, e.g. "sp_private_key") and why (Reason, a short code the form turns into its own text). Detail is the
// underlying error, if any; Error is the English text for logs.
type ValidationError struct {
	Field  string
	Reason string
	Detail error
	text   string
}

func (e *ValidationError) Error() string { return e.text }
func (e *ValidationError) Unwrap() error { return e.Detail }

func invalidField(field, reason, text string, detail error) error {
	if detail != nil {
		text = fmt.Sprintf("%s: %v", text, detail)
	}
	return &ValidationError{Field: field, Reason: reason, Detail: detail, text: text}
}

// spKeyPair returns the SP key and certificate, nil if none is configured.
func (source *Source) spKeyPair() (*rsa.PrivateKey, *x509.Certificate, error) {
	if source.SPCertificate == "" && source.SPPrivateKey == "" {
		return nil, nil, nil //nolint:nilnil // no key pair configured
	}
	if source.SPCertificate == "" {
		return nil, nil, invalidField("sp_certificate", "pair_certificate", "the SP certificate and private key must be set together", nil)
	}
	if source.SPPrivateKey == "" {
		return nil, nil, invalidField("sp_private_key", "pair_key", "the SP certificate and private key must be set together", nil)
	}
	cert, err := ParseCertificate(source.SPCertificate)
	if err != nil {
		return nil, nil, invalidField("sp_certificate", "certificate", "SP certificate", err)
	}
	key, err := ParsePrivateKey(source.SPPrivateKey)
	if err != nil {
		return nil, nil, invalidField("sp_private_key", "private_key", "SP private key", err)
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, invalidField("sp_private_key", "mismatch", "the SP certificate does not belong to the private key", nil)
	}
	return key, cert, nil
}

// ParseIDPMetadata reads IdP metadata: an EntityDescriptor, or an EntitiesDescriptor holding the IdP with entityID
// (or a single IdP when entityID is empty).
func ParseIDPMetadata(data []byte, entityID string) (*saml.EntityDescriptor, error) {
	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("invalid metadata XML: %w", err)
	}
	var root struct{ XMLName xml.Name }
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("invalid metadata XML: %w", err)
	}
	var candidates []saml.EntityDescriptor
	switch root.XMLName.Local {
	case "EntityDescriptor":
		var ed saml.EntityDescriptor
		if err := xml.Unmarshal(data, &ed); err != nil {
			return nil, fmt.Errorf("invalid metadata: %w", err)
		}
		candidates = append(candidates, ed)
	case "EntitiesDescriptor":
		var eds saml.EntitiesDescriptor
		if err := xml.Unmarshal(data, &eds); err != nil {
			return nil, fmt.Errorf("invalid metadata: %w", err)
		}
		candidates = flattenEntities(&eds)
	default:
		return nil, errors.New("the metadata has no EntityDescriptor")
	}

	var found *saml.EntityDescriptor
	for i := range candidates {
		ed := &candidates[i]
		if len(ed.IDPSSODescriptors) == 0 || (entityID != "" && ed.EntityID != entityID) {
			continue
		}
		if found != nil {
			return nil, errors.New("the metadata lists several identity providers: set the IdP entity ID")
		}
		found = ed
	}
	if found == nil {
		if entityID != "" {
			return nil, fmt.Errorf("the metadata has no identity provider %q", entityID)
		}
		return nil, errors.New("the metadata has no identity provider")
	}
	return found, checkIDP(found)
}

func flattenEntities(eds *saml.EntitiesDescriptor) []saml.EntityDescriptor {
	list := eds.EntityDescriptors
	for i := range eds.EntitiesDescriptors {
		list = append(list, flattenEntities(&eds.EntitiesDescriptors[i])...)
	}
	return list
}

// checkIDP checks that the IdP has an entity ID, a sign-in URL and a signing certificate.
func checkIDP(ed *saml.EntityDescriptor) error {
	if ed.EntityID == "" {
		return errors.New("the identity provider has no entity ID")
	}
	sp := saml.ServiceProvider{IDPMetadata: ed}
	if sp.GetSSOBindingLocation(saml.HTTPRedirectBinding) == "" && sp.GetSSOBindingLocation(saml.HTTPPostBinding) == "" {
		return errors.New("the identity provider has no single sign-on URL with the HTTP-Redirect or HTTP-POST binding")
	}
	hasCert := false
	for _, d := range ed.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if kd.Use != "" && kd.Use != "signing" {
				continue
			}
			for _, c := range kd.KeyInfo.X509Data.X509Certificates {
				if _, err := ParseCertificate(c.Data); err != nil {
					return fmt.Errorf("invalid IdP signing certificate: %w", err)
				}
				hasCert = true
			}
		}
	}
	if !hasCert {
		return errors.New("the identity provider has no signing certificate")
	}
	return nil
}

// manualIDP builds the IdP metadata from the entity ID, URLs and certificate set by hand.
func (source *Source) manualIDP() (*saml.EntityDescriptor, error) {
	cert, err := ParseCertificate(source.IDPCertificate)
	if err != nil {
		return nil, fmt.Errorf("IdP certificate: %w", err)
	}
	for _, u := range []string{source.IDPSSOURL, source.IDPSLOURL} {
		if u != "" && !isHTTPURL(u) {
			return nil, fmt.Errorf("%q is not an http(s) URL", u)
		}
	}
	d := saml.IDPSSODescriptor{
		SSODescriptor: saml.SSODescriptor{
			RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				KeyDescriptors: []saml.KeyDescriptor{{
					Use:     "signing",
					KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(cert.Raw)}}}},
				}},
			},
		},
		SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: source.IDPSSOURL}},
	}
	if source.IDPSLOURL != "" {
		d.SingleLogoutServices = []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: source.IDPSLOURL}}
	}
	ed := &saml.EntityDescriptor{EntityID: source.IDPEntityID, IDPSSODescriptors: []saml.IDPSSODescriptor{d}}
	return ed, checkIDP(ed)
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

type cachedMetadata struct {
	key        string
	fetched    time.Time
	entity     *saml.EntityDescriptor // nil: the last fetch failed with err
	err        error
	refreshing bool
}

// metadataRetry is how long a failed fetch is remembered before the next one, so a down IdP isn't asked on every
// request.
const metadataRetry = time.Minute

var (
	metadataMu      sync.Mutex
	metadataCache   = map[int64]*cachedMetadata{}
	metadataFetches singleflight.Group

	// MetadataHTTPClient fetches IdP metadata; tests replace it.
	MetadataHTTPClient = &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{Proxy: proxy.Proxy()},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return errors.New("metadata redirects must stay on https")
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
)

func forgetMetadata(sourceID int64) {
	metadataMu.Lock()
	defer metadataMu.Unlock()
	delete(metadataCache, sourceID)
}

// FetchMetadata downloads IdP metadata over https.
func FetchMetadata(ctx context.Context, metadataURL, entityID string) (*saml.EntityDescriptor, error) {
	u, err := url.Parse(metadataURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("the metadata URL must be an https URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := MetadataHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch metadata: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}
	if len(data) > maxMetadataSize {
		return nil, errors.New("the metadata is larger than 10 MiB")
	}
	return ParseIDPMetadata(data, entityID)
}

// LoadIDPMetadata returns the IdP metadata: fetched from the metadata URL (cached, refreshed hourly in the background,
// the last good copy is kept when a refresh fails), parsed from the stored XML, or built from the manual settings.
func (source *Source) LoadIDPMetadata(ctx context.Context, updated timeutil.TimeStamp) (*saml.EntityDescriptor, error) {
	switch {
	case source.IDPMetadataURL != "":
	case source.IDPMetadata != "":
		return ParseIDPMetadata([]byte(source.IDPMetadata), source.IDPEntityID)
	default:
		return source.manualIDP()
	}

	id := source.authSource.ID
	key := fmt.Sprintf("%d|%s|%s", updated, source.IDPMetadataURL, source.IDPEntityID)
	metadataMu.Lock()
	c := metadataCache[id]
	if c != nil && c.key == key && c.entity == nil && time.Since(c.fetched) < metadataRetry {
		metadataMu.Unlock()
		return nil, c.err
	}
	if c != nil && c.key == key && c.entity != nil {
		if time.Since(c.fetched) >= metadataRefresh && !c.refreshing {
			c.refreshing = true
			go source.refreshMetadata(c)
		}
		metadataMu.Unlock()
		return c.entity, nil
	}
	metadataMu.Unlock()

	// concurrent requests on a cold cache share one fetch
	v, err, _ := metadataFetches.Do(fmt.Sprintf("%d|%s", id, key), func() (any, error) {
		entity, err := FetchMetadata(ctx, source.IDPMetadataURL, source.IDPEntityID)
		metadataMu.Lock()
		metadataCache[id] = &cachedMetadata{key: key, fetched: time.Now(), entity: entity, err: err}
		metadataMu.Unlock()
		return entity, err
	})
	entity, _ := v.(*saml.EntityDescriptor)
	return entity, err
}

func (source *Source) refreshMetadata(c *cachedMetadata) {
	ctx, _, finished := process.GetManager().AddTypedContextTimeout(graceful.GetManager().ShutdownContext(), 30*time.Second,
		"SAML metadata refresh: "+source.authSource.Name, process.SystemProcessType, true)
	defer finished()
	entity, err := FetchMetadata(ctx, source.IDPMetadataURL, source.IDPEntityID)

	metadataMu.Lock()
	defer metadataMu.Unlock()
	c.refreshing = false
	if err != nil {
		log.Warn("SAML source %q: refreshing the IdP metadata failed, keeping the last copy: %v", source.authSource.Name, err)
		c.fetched = time.Now().Add(metadataRetry - metadataRefresh)
		return
	}
	c.entity, c.fetched = entity, time.Now()
}

// ServiceProvider builds the SAML service provider of the source.
func (source *Source) ServiceProvider(ctx context.Context) (*saml.ServiceProvider, error) {
	idp, err := source.LoadIDPMetadata(ctx, source.authSource.UpdatedUnix)
	if err != nil {
		return nil, err
	}
	return source.newServiceProvider(idp)
}

func (source *Source) newServiceProvider(idp *saml.EntityDescriptor) (*saml.ServiceProvider, error) {
	name := source.authSource.Name
	key, cert, err := source.spKeyPair()
	if err != nil {
		return nil, err
	}
	metadataURL, _ := url.Parse(MetadataURL(name))
	acsURL, _ := url.Parse(ACSURL(name))
	sloURL, _ := url.Parse(SLOURL(name))
	sp := &saml.ServiceProvider{
		EntityID:          source.EntityID(),
		MetadataURL:       *metadataURL,
		AcsURL:            *acsURL,
		SloURL:            *sloURL,
		IDPMetadata:       idp,
		AuthnNameIDFormat: saml.NameIDFormat(source.NameIDFormat),
		LogoutBindings:    []string{saml.HTTPRedirectBinding},
	}
	// the library also accepts an assertion that names no audience
	sp.ValidateAudienceRestriction = func(a *saml.Assertion) error {
		for _, r := range a.Conditions.AudienceRestrictions {
			if r.Audience.Value == sp.EntityID {
				return nil
			}
		}
		return errors.New("the assertion is not addressed to this service provider")
	}
	if source.ForceAuthn {
		sp.ForceAuthn = &source.ForceAuthn
	}
	if key != nil {
		sp.Key, sp.Certificate = key, cert
		if source.SignRequests {
			sp.SignatureMethod = dsig.RSASHA256SignatureMethod
		}
	}
	return sp, nil
}

// SPMetadata returns the SP metadata for the IdP: the ACS takes the HTTP-POST binding only.
func (source *Source) SPMetadata() (*saml.EntityDescriptor, error) {
	sp, err := source.newServiceProvider(nil)
	if err != nil {
		return nil, err
	}
	md := sp.Metadata()
	for i := range md.SPSSODescriptors {
		d := &md.SPSSODescriptors[i]
		d.AssertionConsumerServices = slices.DeleteFunc(d.AssertionConsumerServices, func(e saml.IndexedEndpoint) bool {
			return e.Binding != saml.HTTPPostBinding
		})
	}
	return md, nil
}

// Validate checks a configuration before it is stored: the IdP metadata loads, the SP key pair matches and the
// options fit together.
func (source *Source) Validate(ctx context.Context) error {
	manual := source.IDPMetadataURL == "" && source.IDPMetadata == ""
	if manual {
		if source.IDPEntityID == "" && source.IDPSSOURL == "" && source.IDPCertificate == "" {
			return invalidField("idp_metadata_url", "idp_missing", "set an IdP metadata URL, the IdP metadata XML, or the IdP entity ID, SSO URL and certificate", nil)
		}
		for _, f := range []struct{ field, value string }{{"idp_entity_id", source.IDPEntityID}, {"idp_sso_url", source.IDPSSOURL}, {"idp_certificate", source.IDPCertificate}} {
			if f.value == "" {
				return invalidField(f.field, "required", "set the IdP entity ID, SSO URL and certificate", nil)
			}
		}
		if _, err := ParseCertificate(source.IDPCertificate); err != nil {
			return invalidField("idp_certificate", "certificate", "IdP certificate", err)
		}
		for _, f := range []struct{ field, value string }{{"idp_sso_url", source.IDPSSOURL}, {"idp_slo_url", source.IDPSLOURL}} {
			if f.value != "" && !isHTTPURL(f.value) {
				return invalidField(f.field, "not_http", fmt.Sprintf("%q is not an http(s) URL", f.value), nil)
			}
		}
	}
	var err error
	field := "idp_metadata"
	switch {
	case source.IDPMetadataURL != "":
		field = "idp_metadata_url"
		_, err = FetchMetadata(ctx, source.IDPMetadataURL, source.IDPEntityID)
	case manual:
		field = "idp_entity_id"
		_, err = source.LoadIDPMetadata(ctx, 0)
	default:
		_, err = source.LoadIDPMetadata(ctx, 0)
	}
	if err != nil {
		return invalidField(field, "metadata", "IdP metadata", err)
	}
	key, _, err := source.spKeyPair()
	if err != nil {
		return err
	}
	if key == nil && (source.SignRequests || source.RequireEncryptedAssertions) {
		field := "require_encrypted_assertions"
		if source.SignRequests {
			field = "sign_requests"
		}
		return invalidField(field, "needs_key", "signing requests and encrypted assertions need the SP certificate and private key", nil)
	}
	if source.NameIDFormat == string(saml.TransientNameIDFormat) && source.UserIDAttribute == "" {
		return invalidField("user_id_attribute", "transient", "a transient NameID changes at every sign-in: set the attribute that holds the stable user ID", nil)
	}
	if source.SPEntityID != "" && !isHTTPURL(source.SPEntityID) && !strings.HasPrefix(source.SPEntityID, "urn:") {
		return invalidField("sp_entity_id", "entity_id", "the SP entity ID must be a URL or a URN", nil)
	}
	return nil
}
