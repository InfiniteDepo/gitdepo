// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"forgejo.org/models/auth"
	"forgejo.org/modules/cache"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	idpEntityID = "https://idp.example.com/metadata"
	acsURL      = "https://forge.example.com/user/saml/corp/acs"
	spEntityID  = "https://forge.example.com/user/saml/corp/metadata"
)

type keyPair struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return keyPair{key: key, cert: cert}
}

func (kp keyPair) certPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kp.cert.Raw}))
}

func (kp keyPair) keyPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(kp.key)}))
}

func (kp keyPair) signingContext() *dsig.SigningContext {
	sc := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{kp.cert.Raw}, PrivateKey: kp.key}))
	sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	_ = sc.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	return sc
}

type fixture struct {
	idp, sp keyPair
	source  *Source
}

func setup(t *testing.T) *fixture {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.AppURL, "https://forge.example.com/"))
	require.NoError(t, cache.Init())

	f := &fixture{idp: newKeyPair(t), sp: newKeyPair(t)}
	f.source = &Source{
		IDPEntityID:    idpEntityID,
		IDPSSOURL:      "https://idp.example.com/sso",
		IDPSLOURL:      "https://idp.example.com/slo",
		IDPCertificate: f.idp.certPEM(),
		NameIDFormat:   string(saml.PersistentNameIDFormat),

		UsernameAttribute: "uid",
		FullNameAttribute: "displayName",
		EmailAttribute:    "mail",
		GroupClaimName:    "groups",
	}
	f.source.SetAuthSource(&auth.Source{ID: 1, Name: "corp", Type: auth.SAML})
	return f
}

func (f *fixture) serviceProvider(t *testing.T) *saml.ServiceProvider {
	t.Helper()
	sp, err := f.source.ServiceProvider(t.Context())
	require.NoError(t, err)
	return sp
}

type responseOptions struct {
	inResponseTo   string
	audience       string
	issuer         string
	destination    string
	recipient      string
	nameID         string
	notOnOrAfter   time.Time
	attrs          map[string][]string
	signAssertion  bool
	signResponse   bool
	signer         *keyPair
	encryptFor     *x509.Certificate
	mutateResponse func(*etree.Element)

	nameIDFormat   string            // persistent when empty
	noConfirmation bool              // leave out the bearer SubjectConfirmation
	noAudience     bool              // leave out the AudienceRestriction
	friendlyNames  map[string]string // attribute name → FriendlyName
}

func (f *fixture) defaults() responseOptions {
	return responseOptions{
		inResponseTo:  "id-request",
		audience:      spEntityID,
		issuer:        idpEntityID,
		destination:   acsURL,
		recipient:     acsURL,
		nameID:        "alice-guid",
		notOnOrAfter:  time.Now().Add(5 * time.Minute),
		attrs:         map[string][]string{"uid": {"alice"}, "displayName": {"Alice A."}, "mail": {"alice@example.com"}, "groups": {"dev", "ops"}},
		signAssertion: true,
		signer:        &f.idp,
	}
}

func elementBytes(t *testing.T, el *etree.Element) []byte {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	b, err := doc.WriteToBytes()
	require.NoError(t, err)
	return b
}

func (f *fixture) response(t *testing.T, o responseOptions) string {
	t.Helper()
	now := time.Now()
	var attrs []saml.Attribute
	for name, values := range o.attrs {
		attr := saml.Attribute{Name: name, FriendlyName: o.friendlyNames[name], NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"}
		for _, v := range values {
			attr.Values = append(attr.Values, saml.AttributeValue{Type: "xs:string", Value: v})
		}
		attrs = append(attrs, attr)
	}
	format := o.nameIDFormat
	if format == "" {
		format = string(saml.PersistentNameIDFormat)
	}
	a := &saml.Assertion{
		ID:           newID(),
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: o.issuer},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Format: format, Value: o.nameID},
			SubjectConfirmations: []saml.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					InResponseTo: o.inResponseTo,
					NotOnOrAfter: o.notOnOrAfter,
					Recipient:    o.recipient,
				},
			}},
		},
		Conditions: &saml.Conditions{
			NotBefore:            now.Add(-time.Minute),
			NotOnOrAfter:         o.notOnOrAfter,
			AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: o.audience}}},
		},
		AuthnStatements: []saml.AuthnStatement{{AuthnInstant: now, SessionIndex: "session-1"}},
	}
	if o.noConfirmation {
		a.Subject.SubjectConfirmations = nil
	}
	if o.noAudience {
		a.Conditions.AudienceRestrictions = nil
	}
	a.AttributeStatements = []saml.AttributeStatement{{Attributes: attrs}}
	assertionEl := a.Element()
	if o.signAssertion {
		signed, err := o.signer.signingContext().SignEnveloped(assertionEl)
		require.NoError(t, err)
		a.Signature = signed.ChildElements()[len(signed.ChildElements())-1]
		assertionEl = a.Element()
	}
	if o.encryptFor != nil {
		enc := xmlenc.OAEP()
		enc.BlockCipher = xmlenc.AES128CBC
		enc.DigestMethod = &xmlenc.SHA1
		data, err := enc.Encrypt(o.encryptFor, elementBytes(t, assertionEl), nil)
		require.NoError(t, err)
		data.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
		assertionEl = etree.NewElement("saml:EncryptedAssertion")
		assertionEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
		assertionEl.AddChild(data)
	}

	resp := &saml.Response{
		ID:           newID(),
		InResponseTo: o.inResponseTo,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  o.destination,
		Issuer:       &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: o.issuer},
		Status:       saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	}
	respEl := resp.Element()
	respEl.AddChild(assertionEl)
	if o.signResponse {
		signed, err := o.signer.signingContext().SignEnveloped(respEl)
		require.NoError(t, err)
		resp.Signature = signed.ChildElements()[len(signed.ChildElements())-1]
		respEl = resp.Element()
		respEl.AddChild(assertionEl)
	}
	if o.mutateResponse != nil {
		o.mutateResponse(respEl)
	}
	return base64.StdEncoding.EncodeToString(elementBytes(t, respEl))
}

func TestParseResponse(t *testing.T) {
	f := setup(t)
	sp := f.serviceProvider(t)

	t.Run("signed assertion", func(t *testing.T) {
		a, err := f.source.ParseResponse(sp, f.response(t, f.defaults()), "id-request")
		require.NoError(t, err)
		assert.Equal(t, "alice-guid", a.User.UserID)
		assert.Equal(t, "alice", a.User.NickName)
		assert.Equal(t, "Alice A.", a.User.Name)
		assert.Equal(t, "alice@example.com", a.User.Email)
		assert.Equal(t, "corp", a.User.Provider)
		assert.Equal(t, []string{"dev", "ops"}, a.User.RawData["groups"])
		assert.Equal(t, "alice", a.User.RawData["preferred_username"])
		assert.Equal(t, "alice-guid", a.NameID)
		assert.Equal(t, "session-1", a.SessionIndex)
	})

	t.Run("signed response only", func(t *testing.T) {
		o := f.defaults()
		o.signAssertion, o.signResponse = false, true
		_, err := f.source.ParseResponse(sp, f.response(t, o), "id-request")
		require.NoError(t, err)
	})

	refused := map[string]func(o *responseOptions){
		"unsigned":              func(o *responseOptions) { o.signAssertion = false },
		"signed by another key": func(o *responseOptions) { other := newKeyPair(t); o.signer = &other },
		"expired":               func(o *responseOptions) { o.notOnOrAfter = time.Now().Add(-10 * time.Minute) },
		"wrong audience":        func(o *responseOptions) { o.audience = "https://other.example.com/metadata" },
		"wrong issuer":          func(o *responseOptions) { o.issuer = "https://evil.example.com/metadata" },
		"wrong destination":     func(o *responseOptions) { o.destination = "https://evil.example.com/acs" },
		"wrong recipient":       func(o *responseOptions) { o.recipient = "https://evil.example.com/acs" },
		"other request":         func(o *responseOptions) { o.inResponseTo = "id-other" },
		"unsolicited":           func(o *responseOptions) { o.inResponseTo = "" },
		"no audience":           func(o *responseOptions) { o.noAudience = true },
		"no subject confirmation": func(o *responseOptions) {
			o.noConfirmation = true
		},
		"transient NameID": func(o *responseOptions) { o.nameIDFormat = string(saml.TransientNameIDFormat) },
		"NameID of another format": func(o *responseOptions) {
			o.nameIDFormat = string(saml.EmailAddressNameIDFormat)
		},
		"tampered after signing": func(o *responseOptions) {
			o.mutateResponse = func(el *etree.Element) {
				el.FindElement("./Assertion/Subject/NameID").SetText("admin")
			}
		},
	}
	for name, mutate := range refused {
		t.Run(name, func(t *testing.T) {
			o := f.defaults()
			mutate(&o)
			_, err := f.source.ParseResponse(sp, f.response(t, o), "id-request")
			require.ErrorAs(t, err, &ErrInvalidResponse{})
		})
	}

	t.Run("not base64 or too large", func(t *testing.T) {
		_, err := f.source.ParseResponse(sp, "%%%", "id-request")
		require.Error(t, err)
		_, err = f.source.ParseResponse(sp, strings.Repeat("A", 2*MaxResponseSize), "id-request")
		require.Error(t, err)
	})

	t.Run("replayed", func(t *testing.T) {
		resp := f.response(t, f.defaults())
		_, err := f.source.ParseResponse(sp, resp, "id-request")
		require.NoError(t, err)
		_, err = f.source.ParseResponse(sp, resp, "id-request")
		require.ErrorContains(t, err, "used before")
	})

	t.Run("IdP-initiated", func(t *testing.T) {
		o := f.defaults()
		o.inResponseTo = ""
		resp := f.response(t, o)
		// never accepted: with IdP-initiated sign-in on, the ACS starts a sign-in of its own instead
		_, err := f.source.ParseResponse(sp, resp, "")
		require.ErrorContains(t, err, "no sign-in was started")

		// a browser that started a sign-in takes only the answer to its own request
		for _, inResponseTo := range []string{"", "id-other"} {
			o.inResponseTo = inResponseTo
			_, err = f.source.ParseResponse(f.serviceProvider(t), f.response(t, o), "id-request")
			require.ErrorAs(t, err, &ErrInvalidResponse{}, inResponseTo)
		}
	})

	t.Run("username and email", func(t *testing.T) {
		o := f.defaults()
		delete(o.attrs, "uid")
		a, err := f.source.ParseResponse(sp, f.response(t, o), "id-request")
		require.NoError(t, err)
		assert.Equal(t, "alice", a.User.NickName, "taken from the email address")

		for _, name := range []string{"uid", "mail"} {
			o := f.defaults()
			o.attrs[name] = append(o.attrs[name], "other@example.com")
			_, err := f.source.ParseResponse(sp, f.response(t, o), "id-request")
			require.ErrorContains(t, err, "values", name)
		}
	})

	t.Run("attribute with the same name and friendly name", func(t *testing.T) {
		f.source.UserIDAttribute = "objectGUID"
		defer func() { f.source.UserIDAttribute = "" }()
		o := f.defaults()
		o.attrs["objectGUID"] = []string{"guid-1"}
		o.attrs["urn:oid:2.5.4.42"] = []string{"Alice"}
		o.friendlyNames = map[string]string{"objectGUID": "objectGUID", "urn:oid:2.5.4.42": "uid"}
		a, err := f.source.ParseResponse(sp, f.response(t, o), "id-request")
		require.NoError(t, err)
		assert.Equal(t, "guid-1", a.User.UserID)
		// a friendly name never adds to an attribute of that name
		assert.Equal(t, []string{"alice"}, a.User.RawData["uid"])
		assert.Equal(t, []string{"Alice"}, a.User.RawData["urn:oid:2.5.4.42"])
	})

	t.Run("transient NameID with a user ID attribute", func(t *testing.T) {
		f.source.UserIDAttribute = "objectGUID"
		defer func() { f.source.UserIDAttribute = "" }()
		o := f.defaults()
		o.nameIDFormat = string(saml.TransientNameIDFormat)
		o.attrs["objectGUID"] = []string{"guid-1"}
		a, err := f.source.ParseResponse(sp, f.response(t, o), "id-request")
		require.NoError(t, err)
		assert.Equal(t, "guid-1", a.User.UserID)
	})

	t.Run("user ID attribute", func(t *testing.T) {
		f.source.UserIDAttribute = "objectGUID"
		defer func() { f.source.UserIDAttribute = "" }()

		o := f.defaults()
		o.attrs["objectGUID"] = []string{"guid-1"}
		a, err := f.source.ParseResponse(sp, f.response(t, o), "id-request")
		require.NoError(t, err)
		assert.Equal(t, "guid-1", a.User.UserID)

		o.attrs["objectGUID"] = []string{"guid-1", "guid-2"}
		_, err = f.source.ParseResponse(sp, f.response(t, o), "id-request")
		require.ErrorContains(t, err, "exactly one user ID")

		delete(o.attrs, "objectGUID")
		_, err = f.source.ParseResponse(sp, f.response(t, o), "id-request")
		require.ErrorContains(t, err, "exactly one user ID")
	})
}

// TestSignatureWrapping moves the signed assertion out of the way and puts a forged one where it is read.
func TestSignatureWrapping(t *testing.T) {
	f := setup(t)
	sp := f.serviceProvider(t)

	forge := func(t *testing.T, keepSignature bool) string {
		o := f.defaults()
		o.mutateResponse = func(resp *etree.Element) {
			signed := resp.FindElement("./Assertion")
			forged := signed.Copy()
			forged.FindElement("./Subject/NameID").SetText("admin")
			if !keepSignature {
				forged.RemoveChild(forged.FindElement("./Signature"))
			}
			resp.RemoveChild(signed)
			ext := resp.CreateElement("samlp:Extensions")
			ext.AddChild(signed)
			resp.InsertChildAt(0, forged)
		}
		return f.response(t, o)
	}
	for _, keep := range []bool{false, true} {
		a, err := f.source.ParseResponse(sp, forge(t, keep), "id-request")
		if err == nil {
			assert.NotEqual(t, "admin", a.User.UserID)
		}
		require.Error(t, err)
	}

	t.Run("forged assertion next to the signed one", func(t *testing.T) {
		o := f.defaults()
		o.mutateResponse = func(resp *etree.Element) {
			forged := resp.FindElement("./Assertion").Copy()
			forged.FindElement("./Subject/NameID").SetText("admin")
			forged.RemoveChild(forged.FindElement("./Signature"))
			resp.InsertChildAt(0, forged)
		}
		a, err := f.source.ParseResponse(sp, f.response(t, o), "id-request")
		if err == nil {
			assert.Equal(t, "alice-guid", a.User.UserID)
		}
	})

	t.Run("comment in the NameID", func(t *testing.T) {
		o := f.defaults()
		o.nameID = "admin.evil"
		o.mutateResponse = func(resp *etree.Element) {
			nameID := resp.FindElement("./Assertion/Subject/NameID")
			nameID.SetText("admin")
			nameID.CreateComment("x")
			nameID.CreateText(".evil")
		}
		a, err := f.source.ParseResponse(sp, f.response(t, o), "id-request")
		require.NoError(t, err)
		assert.Equal(t, "admin.evil", a.User.UserID)
	})
}

func TestEncryptedAssertions(t *testing.T) {
	f := setup(t)
	f.source.SPCertificate, f.source.SPPrivateKey = f.sp.certPEM(), f.sp.keyPEM()
	f.source.RequireEncryptedAssertions = true
	sp := f.serviceProvider(t)

	_, err := f.source.ParseResponse(sp, f.response(t, f.defaults()), "id-request")
	require.ErrorContains(t, err, "unencrypted assertion")

	o := f.defaults()
	o.encryptFor = f.sp.cert
	a, err := f.source.ParseResponse(sp, f.response(t, o), "id-request")
	require.NoError(t, err)
	assert.Equal(t, "alice-guid", a.User.UserID)

	// a plain assertion is refused at any depth
	for _, xml := range []string{
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion/></samlp:Response>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><samlp:Extensions><x><saml:Assertion/></x></samlp:Extensions><saml:EncryptedAssertion/></samlp:Response>`,
	} {
		require.ErrorContains(t, checkNoPlainAssertion([]byte(xml)), "unencrypted assertion")
	}
	require.NoError(t, checkNoPlainAssertion([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><EncryptedAssertion/></samlp:Response>`)))

	// RSA PKCS#1 v1.5 key transport is refused, OAEP is accepted
	keyTransport := func(alg string) []byte {
		return []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><saml:EncryptedAssertion><xenc:EncryptedData><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="` + alg + `"/></xenc:EncryptedKey></xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>`)
	}
	require.ErrorContains(t, checkKeyTransport(keyTransport("http://www.w3.org/2001/04/xmlenc#rsa-1_5")), "PKCS#1 v1.5")
	require.NoError(t, checkKeyTransport(keyTransport("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")))
}

func TestLogout(t *testing.T) {
	f := setup(t)
	f.source.SPCertificate, f.source.SPPrivateKey, f.source.SignRequests = f.sp.certPEM(), f.sp.keyPEM(), true
	sp := f.serviceProvider(t)

	t.Run("logout request to the IdP is signed", func(t *testing.T) {
		u, err := LogoutRequestURL(sp, "alice-guid", string(saml.PersistentNameIDFormat), "session-1")
		require.NoError(t, err)
		parsed, err := url.Parse(u)
		require.NoError(t, err)
		assert.Equal(t, "idp.example.com", parsed.Host)
		// the IdP checks the signature with the SP certificate
		idpSide := &saml.ServiceProvider{IDPMetadata: &saml.EntityDescriptor{IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{KeyDescriptors: []saml.KeyDescriptor{{
				Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(f.sp.cert.Raw)}}}},
			}}}},
		}}}}
		_, _, err = verifyRedirectSignature(idpSide, parsed.RawQuery, "SAMLRequest")
		require.NoError(t, err)
		_, _, err = verifyRedirectSignature(idpSide, strings.Replace(parsed.RawQuery, "SAMLRequest=", "SAMLRequest=A", 1), "SAMLRequest")
		require.Error(t, err)
	})

	// idpLogoutRequest builds a logout request signed by the IdP for the redirect binding.
	idpLogoutRequest := func(t *testing.T, signer keyPair, destination string, sign bool) string {
		req := saml.LogoutRequest{
			ID:           newID(),
			Version:      "2.0",
			IssueInstant: time.Now(),
			Destination:  destination,
			Issuer:       &saml.Issuer{Value: idpEntityID},
			NameID:       &saml.NameID{Value: "alice-guid"},
		}
		idpSP := &saml.ServiceProvider{Key: signer.key, Certificate: signer.cert}
		if sign {
			idpSP.SignatureMethod = dsig.RSASHA256SignatureMethod
		}
		u, err := redirectURL(idpSP, destination, "SAMLRequest", req.Element(), "relay")
		require.NoError(t, err)
		parsed, err := url.Parse(u)
		require.NoError(t, err)
		return parsed.RawQuery
	}
	sloURL := "https://forge.example.com/user/saml/corp/slo"

	signed := idpLogoutRequest(t, f.idp, sloURL, true)
	req, relay, err := f.source.ParseLogoutRequest(sp, signed)
	require.NoError(t, err)
	assert.Equal(t, "alice-guid", req.NameID.Value)
	assert.Equal(t, "relay", relay)
	_, _, err = f.source.ParseLogoutRequest(sp, signed)
	require.ErrorContains(t, err, "used before")

	_, _, err = f.source.ParseLogoutRequest(sp, idpLogoutRequest(t, f.idp, sloURL, false))
	require.ErrorContains(t, err, "not signed")
	_, _, err = f.source.ParseLogoutRequest(sp, idpLogoutRequest(t, newKeyPair(t), sloURL, true))
	require.ErrorContains(t, err, "does not match")
	_, _, err = f.source.ParseLogoutRequest(sp, idpLogoutRequest(t, f.idp, "https://evil.example.com/slo", true))
	require.ErrorContains(t, err, "is for")
	_, _, err = f.source.ParseLogoutRequest(sp, idpLogoutRequest(t, f.idp, sloURL, true)+"&SigAlg=x")
	require.ErrorContains(t, err, "duplicate")

	// a parameter name spelled with escapes is not covered by the signature, so it is refused
	forged := saml.LogoutRequest{
		ID: newID(), Version: "2.0", IssueInstant: time.Now(), Destination: sloURL,
		Issuer: &saml.Issuer{Value: idpEntityID}, NameID: &saml.NameID{Value: "victim"},
	}
	forgedURL, err := redirectURL(&saml.ServiceProvider{}, sloURL, "SAMLRequest", forged.Element(), "")
	require.NoError(t, err)
	parsedForged, err := url.Parse(forgedURL)
	require.NoError(t, err)
	forgedMessage := url.QueryEscape(parsedForged.Query().Get("SAMLRequest"))
	for _, prefix := range []string{"SAML%52equest=" + forgedMessage, "Relay%53tate=https%3A%2F%2Fevil.example.com%2F"} {
		_, _, err = f.source.ParseLogoutRequest(sp, prefix+"&"+idpLogoutRequest(t, f.idp, sloURL, true))
		require.ErrorContains(t, err, "encoded", prefix)
	}

	u, err := LogoutResponseURL(sp, req.ID, relay)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(u, "https://idp.example.com/slo?SAMLResponse="))
	assert.Contains(t, u, "&Signature=")
}

func TestParseIDPMetadata(t *testing.T) {
	kp := newKeyPair(t)
	entity := func(id string) string {
		return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + id + `">
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` +
			base64.StdEncoding.EncodeToString(kp.cert.Raw) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
</IDPSSODescriptor></EntityDescriptor>`
	}

	ed, err := ParseIDPMetadata([]byte(entity("https://a")), "")
	require.NoError(t, err)
	assert.Equal(t, "https://a", ed.EntityID)

	both := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + entity("https://a") + entity("https://b") + `</EntitiesDescriptor>`
	_, err = ParseIDPMetadata([]byte(both), "")
	require.ErrorContains(t, err, "several identity providers")
	ed, err = ParseIDPMetadata([]byte(both), "https://b")
	require.NoError(t, err)
	assert.Equal(t, "https://b", ed.EntityID)
	_, err = ParseIDPMetadata([]byte(both), "https://c")
	require.Error(t, err)

	_, err = ParseIDPMetadata([]byte(strings.Replace(entity("https://a"), `use="signing"`, `use="encryption"`, 1)), "")
	require.ErrorContains(t, err, "no signing certificate")
	_, err = ParseIDPMetadata([]byte("<foo/>"), "")
	require.Error(t, err)

	_, err = FetchMetadata(t.Context(), "http://idp.example.com/metadata", "")
	require.ErrorContains(t, err, "https")
}

func TestSourceConfig(t *testing.T) {
	f := setup(t)
	f.source.SPCertificate, f.source.SPPrivateKey = f.sp.certPEM(), f.sp.keyPEM()

	bs, err := f.source.ToDB()
	require.NoError(t, err)
	assert.NotContains(t, string(bs), "PRIVATE KEY")
	loaded := &Source{}
	require.NoError(t, loaded.FromDB(bs))
	assert.Equal(t, f.sp.keyPEM(), loaded.SPPrivateKey)
	assert.Empty(t, loaded.SPPrivateKeyEncrypt)

	valid := func() *Source {
		s := *loaded
		return &s
	}
	require.NoError(t, valid().Validate(t.Context()))

	s := valid()
	s.NameIDFormat = string(saml.TransientNameIDFormat)
	require.ErrorContains(t, s.Validate(t.Context()), "transient")

	s = valid()
	s.SPPrivateKey = ""
	require.ErrorContains(t, s.Validate(t.Context()), "set together")

	s = valid()
	s.SPCertificate, s.SPPrivateKey, s.RequireEncryptedAssertions = "", "", true
	require.ErrorContains(t, s.Validate(t.Context()), "need the SP certificate")

	s = valid()
	s.SPCertificate = newKeyPair(t).certPEM()
	require.ErrorContains(t, s.Validate(t.Context()), "does not belong")

	s = valid()
	s.IDPCertificate = ""
	require.Error(t, s.Validate(t.Context()))

	s = valid()
	s.IDPSSOURL = "javascript:alert(1)"
	require.Error(t, s.Validate(t.Context()))
}

func TestSPMetadata(t *testing.T) {
	f := setup(t)
	md, err := f.source.SPMetadata()
	require.NoError(t, err)
	assert.Equal(t, spEntityID, md.EntityID)
	require.Len(t, md.SPSSODescriptors, 1)
	acs := md.SPSSODescriptors[0].AssertionConsumerServices
	require.Len(t, acs, 1)
	assert.Equal(t, saml.HTTPPostBinding, acs[0].Binding)
	assert.Equal(t, acsURL, acs[0].Location)
}
