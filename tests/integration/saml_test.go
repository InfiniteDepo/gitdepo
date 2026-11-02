// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	saml_source "forgejo.org/services/auth/source/saml"
	"forgejo.org/tests"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// samlTestIDP is an identity provider that answers the requests the test passes to it.
type samlTestIDP struct {
	t   *testing.T
	idp *saml.IdentityProvider
	sp  *saml.EntityDescriptor
}

func (p *samlTestIDP) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if p.sp == nil || p.sp.EntityID != id {
		return nil, fmt.Errorf("unknown service provider %q", id)
	}
	return p.sp, nil
}

func newSAMLTestIDP(t *testing.T) *samlTestIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	base, _ := url.Parse("https://idp.example.com/")
	p := &samlTestIDP{t: t}
	p.idp = &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             *base.JoinPath("metadata"),
		SSOURL:                  *base.JoinPath("sso"),
		LogoutURL:               *base.JoinPath("slo"),
		ServiceProviderProvider: p,
	}
	return p
}

func (p *samlTestIDP) metadataXML() string {
	data, err := xml.Marshal(p.idp.Metadata())
	require.NoError(p.t, err)
	return string(data)
}

// loadSP reads the SP metadata gitdepo serves for the source, as an admin would import it into the IdP.
func (p *samlTestIDP) loadSP(name string) {
	resp := MakeRequest(p.t, NewRequest(p.t, "GET", "/user/saml/"+name+"/metadata"), http.StatusOK)
	assert.Equal(p.t, "application/samlmetadata+xml", resp.Header().Get("Content-Type"))
	p.sp = &saml.EntityDescriptor{}
	require.NoError(p.t, xml.Unmarshal(resp.Body.Bytes(), p.sp))
}

func samlSession(nameID, username string, groups ...string) *saml.Session {
	return &saml.Session{
		CreateTime:     time.Now(),
		Index:          "session-" + nameID,
		NameID:         nameID,
		NameIDFormat:   string(saml.PersistentNameIDFormat),
		UserName:       username,
		UserEmail:      username + "@idp.example.com",
		UserCommonName: strings.ToUpper(username),
		Groups:         groups,
	}
}

// answer runs the IdP's SSO endpoint for the authentication request in location and returns its SAMLResponse.
func (p *samlTestIDP) answer(location string, session *saml.Session) string {
	p.t.Helper()
	require.True(p.t, strings.HasPrefix(location, p.idp.SSOURL.String()+"?"), location)
	req, err := saml.NewIdpAuthnRequest(p.idp, httptest.NewRequest("GET", location, nil))
	require.NoError(p.t, err)
	require.NoError(p.t, req.Validate())
	require.NoError(p.t, saml.DefaultAssertionMaker{}.MakeAssertion(req, session))
	form, err := req.PostBinding()
	require.NoError(p.t, err)
	return form.SAMLResponse
}

type samlSessionProvider struct{ session *saml.Session }

func (s samlSessionProvider) GetSession(http.ResponseWriter, *http.Request, *saml.IdpAuthnRequest) *saml.Session {
	return s.session
}

// unsolicited returns an IdP-initiated SAMLResponse.
func (p *samlTestIDP) unsolicited(session *saml.Session) string {
	p.t.Helper()
	p.idp.SessionProvider = samlSessionProvider{session}
	rec := httptest.NewRecorder()
	p.idp.ServeIDPInitiated(rec, httptest.NewRequest("GET", "https://idp.example.com/start", nil), p.sp.EntityID, "")
	require.Equal(p.t, http.StatusOK, rec.Code, rec.Body.String())
	value, ok := NewHTMLParser(p.t, rec.Body).Find(`input[name="SAMLResponse"]`).Attr("value")
	require.True(p.t, ok)
	return value
}

func addSAMLSource(t *testing.T, name string, p *samlTestIDP, extra map[string]string) *auth.Source {
	t.Helper()
	payload := map[string]string{
		"type":                     fmt.Sprintf("%d", auth.SAML),
		"name":                     name,
		"is_active":                "on",
		"saml_idp_metadata":        p.metadataXML(),
		"saml_name_id_format":      string(saml.PersistentNameIDFormat),
		"saml_username_attribute":  "uid",
		"saml_full_name_attribute": "cn",
		"saml_email_attribute":     "mail",
		"saml_group_claim_name":    "eduPersonAffiliation",
	}
	maps.Copy(payload, extra)
	source := addAuthSource(t, payload)
	p.loadSP(name)
	return source
}

// samlStart starts a sign-in on session and returns the IdP URL it sends the browser to.
func samlStart(t *testing.T, session *TestSession, name string) string {
	t.Helper()
	resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/saml/"+name+"/login"), http.StatusSeeOther)
	return test.RedirectURL(resp)
}

// samlSignIn starts a sign-in on session and returns the IdP's answer to it.
func samlSignIn(t *testing.T, session *TestSession, name string, p *samlTestIDP, s *saml.Session) string {
	t.Helper()
	return p.answer(samlStart(t, session, name), s)
}

// postACS posts a SAMLResponse as the IdP's page does: cross-site first, then again from gitdepo's own page.
func postACS(t *testing.T, session *TestSession, name, samlResponse string) *httptest.ResponseRecorder {
	t.Helper()
	req := NewRequestWithValues(t, "POST", "/user/saml/"+name+"/acs", map[string]string{"SAMLResponse": samlResponse})
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp := session.MakeRequest(t, req, http.StatusOK)
	form := NewHTMLParser(t, resp.Body).Find("form#saml-post")
	action, _ := form.Attr("action")
	assert.Equal(t, "/user/saml/"+name+"/acs", action)
	value, _ := form.Find(`input[name="SAMLResponse"]`).Attr("value")
	assert.Equal(t, samlResponse, value)

	req = NewRequestWithValues(t, "POST", action, map[string]string{"SAMLResponse": value})
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	return session.MakeRequest(t, req, http.StatusSeeOther)
}

func signedInAs(t *testing.T, session *TestSession) string {
	t.Helper()
	resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), NoExpectedStatus)
	if resp.Code != http.StatusOK {
		return ""
	}
	return NewHTMLParser(t, resp.Body).Find(`input[name="name"]`).AttrOr("value", "")
}

func TestSAMLSignIn(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.OAuth2Client.EnableAutoRegistration, true)()

	p := newSAMLTestIDP(t)
	source := addSAMLSource(t, "corp", p, map[string]string{
		"saml_group_team_map": `{"dev": {"org3": ["team1"]}}`,
		"saml_admin_group":    "admins",
	})
	require.True(t, source.IsSAML())

	t.Run("login page shows the button", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/user/login"), http.StatusOK)
		NewHTMLParser(t, resp.Body).AssertElement(t, `a[href="/user/saml/corp/login"]`, true)
	})

	var samlResponse string
	t.Run("new user is registered and signed in", func(t *testing.T) {
		session := emptyTestSession(t)
		samlResponse = samlSignIn(t, session, "corp", p, samlSession("guid-alice", "alice", "dev"))
		resp := postACS(t, session, "corp", samlResponse)
		assert.Equal(t, "/", test.RedirectURL(resp))
		assert.Equal(t, "alice", signedInAs(t, session))

		u := unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "alice"})
		assert.Equal(t, auth.SAML, u.LoginType)
		assert.Equal(t, source.ID, u.LoginSource)
		assert.Equal(t, "guid-alice", u.LoginName)
		assert.Equal(t, "alice@idp.example.com", u.Email)
		assert.Equal(t, "ALICE", u.FullName)
		isMember, err := organization.IsTeamMember(t.Context(), 3, 2, u.ID)
		require.NoError(t, err)
		assert.True(t, isMember, "group dev maps to org3/team1")
	})

	t.Run("admin group makes a site admin", func(t *testing.T) {
		session := emptyTestSession(t)
		postACS(t, session, "corp", samlSignIn(t, session, "corp", p, samlSession("guid-erin", "erin", "admins")))
		assert.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "erin"}).IsAdmin)
		assert.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "alice"}).IsAdmin)
	})

	t.Run("a response to an older request is refused", func(t *testing.T) {
		session := emptyTestSession(t)
		samlStart(t, session, "corp")
		resp := postACS(t, session, "corp", samlResponse)
		assert.Equal(t, "/user/login", test.RedirectURL(resp))
		assert.Empty(t, signedInAs(t, session))
	})

	t.Run("a response for another browser's request is refused", func(t *testing.T) {
		victim := emptyTestSession(t)
		attacker := emptyTestSession(t)
		planted := samlSignIn(t, attacker, "corp", p, samlSession("guid-mallory", "mallory"))
		samlStart(t, victim, "corp")
		resp := postACS(t, victim, "corp", planted)
		assert.Equal(t, "/user/login", test.RedirectURL(resp))
		assert.Empty(t, signedInAs(t, victim))
		unittest.AssertNotExistsBean(t, &user_model.User{LowerName: "mallory"})
	})

	t.Run("existing user signs in again and out through the IdP", func(t *testing.T) {
		session := emptyTestSession(t)
		resp := postACS(t, session, "corp", samlSignIn(t, session, "corp", p, samlSession("guid-alice", "alice", "dev")))
		assert.Equal(t, "/", test.RedirectURL(resp))
		assert.Equal(t, "alice", signedInAs(t, session))

		resp = session.MakeRequest(t, NewRequest(t, "POST", "/user/logout"), http.StatusSeeOther)
		loc := test.RedirectURL(resp)
		require.True(t, strings.HasPrefix(loc, "https://idp.example.com/slo?SAMLRequest="), loc)
		assert.Empty(t, signedInAs(t, session))
	})

	t.Run("without auto registration the user links an account", func(t *testing.T) {
		defer test.MockVariableValue(&setting.OAuth2Client.EnableAutoRegistration, false)()
		session := emptyTestSession(t)
		resp := postACS(t, session, "corp", samlSignIn(t, session, "corp", p, samlSession("guid-bob", "bob")))
		assert.Equal(t, "/user/link_account", test.RedirectURL(resp))
		unittest.AssertNotExistsBean(t, &user_model.User{LowerName: "bob"})

		session.MakeRequest(t, NewRequest(t, "GET", "/user/link_account"), http.StatusOK)
		req := NewRequestWithValues(t, "POST", "/user/link_account_signin", map[string]string{"user_name": "user2", "password": userPassword})
		session.MakeRequest(t, req, http.StatusSeeOther)
		assert.Equal(t, "user2", signedInAs(t, session))
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "user2"})
		linked, err := db.GetEngine(t.Context()).Exist(&user_model.ExternalLoginUser{ExternalID: "guid-bob", LoginSourceID: source.ID, UserID: user2.ID})
		require.NoError(t, err)
		assert.True(t, linked)

		// the linked account signs in through the IdP from now on
		other := emptyTestSession(t)
		resp = postACS(t, other, "corp", samlSignIn(t, other, "corp", p, samlSession("guid-bob", "bob")))
		assert.Equal(t, "/", test.RedirectURL(resp))
		assert.Equal(t, "user2", signedInAs(t, other))
	})

	t.Run("single sign-in option", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Service.EnableInternalSignIn, false)()
		session := emptyTestSession(t)
		resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/login"), http.StatusSeeOther)
		assert.Equal(t, "/user/saml/corp/login", test.RedirectURL(resp))

		// after a failed sign-in the page shows the error instead of sending the browser around again
		samlStart(t, session, "corp")
		resp = postACS(t, session, "corp", samlResponse)
		assert.Equal(t, "/user/login", test.RedirectURL(resp))
		resp = session.MakeRequest(t, NewRequest(t, "GET", "/user/login"), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "corp")
	})

	t.Run("unknown source is not found", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "GET", "/user/saml/nope/login"), http.StatusNotFound)
		MakeRequest(t, NewRequest(t, "GET", "/user/saml/nope/metadata"), http.StatusNotFound)
	})
}

func TestSAMLIDPInitiated(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.OAuth2Client.EnableAutoRegistration, true)()

	p := newSAMLTestIDP(t)
	addSAMLSource(t, "corp", p, nil)
	session := emptyTestSession(t)
	postACS(t, session, "corp", samlSignIn(t, session, "corp", p, samlSession("guid-alice", "alice")))
	require.Equal(t, "alice", signedInAs(t, session))

	t.Run("refused unless allowed", func(t *testing.T) {
		session := emptyTestSession(t)
		resp := postACS(t, session, "corp", p.unsolicited(samlSession("guid-alice", "alice")))
		assert.Equal(t, "/user/login", test.RedirectURL(resp))
		assert.Empty(t, signedInAs(t, session))
	})

	addSAMLSource(t, "open", p, map[string]string{"saml_allow_idp_initiated": "on"})
	session = emptyTestSession(t)
	postACS(t, session, "open", samlSignIn(t, session, "open", p, samlSession("guid-carol", "carol")))
	require.Equal(t, "carol", signedInAs(t, session))

	t.Run("starts a sign-in of its own", func(t *testing.T) {
		// a response the attacker got for their own account, planted in the victim's browser
		session := emptyTestSession(t)
		planted := p.unsolicited(samlSession("guid-mallory", "mallory"))
		resp := postACS(t, session, "open", planted)
		assert.Equal(t, "/user/saml/open/login", test.RedirectURL(resp))
		assert.Empty(t, signedInAs(t, session))
		unittest.AssertNotExistsBean(t, &user_model.User{LowerName: "mallory"})

		// the IdP answers that sign-in for the browser's own user
		postACS(t, session, "open", samlSignIn(t, session, "open", p, samlSession("guid-carol", "carol")))
		assert.Equal(t, "carol", signedInAs(t, session))
	})

	t.Run("a planted response never links to a signed-in user", func(t *testing.T) {
		attacker := emptyTestSession(t)
		ownAnswer := samlSignIn(t, attacker, "open", p, samlSession("guid-mallory", "mallory"))
		for _, planted := range []string{ownAnswer, p.unsolicited(samlSession("guid-mallory", "mallory"))} {
			victim := loginUser(t, "user2")
			samlStart(t, victim, "open") // the attacker opens the sign-in in the victim's browser first
			resp := postACS(t, victim, "open", planted)
			assert.Equal(t, "/user/login", test.RedirectURL(resp))
			assert.Equal(t, "user2", signedInAs(t, victim))
		}
		linked, err := db.GetEngine(t.Context()).Exist(&user_model.ExternalLoginUser{ExternalID: "guid-mallory"})
		require.NoError(t, err)
		assert.False(t, linked)
		unittest.AssertNotExistsBean(t, &user_model.User{LowerName: "mallory"})
	})

	t.Run("never switches a signed-in user to another account", func(t *testing.T) {
		victim := loginUser(t, "user2")
		resp := postACS(t, victim, "open", p.unsolicited(samlSession("guid-carol", "carol")))
		assert.Equal(t, "/user/saml/open/login", test.RedirectURL(resp))
		assert.Equal(t, "user2", signedInAs(t, victim))
	})
}

// logoutRequest returns the query of a logout request the IdP sends with the HTTP-Redirect binding.
func (p *samlTestIDP) logoutRequest(name, nameID string, sign bool) string {
	p.t.Helper()
	req := saml.LogoutRequest{
		ID:           fmt.Sprintf("id-logout-%s-%d", nameID, time.Now().UnixNano()),
		Version:      "2.0",
		IssueInstant: time.Now(),
		Destination:  setting.AppURL + "user/saml/" + name + "/slo",
		Issuer:       &saml.Issuer{Value: p.idp.MetadataURL.String()},
		NameID:       &saml.NameID{Value: nameID},
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	data, err := doc.WriteToBytes()
	require.NoError(p.t, err)
	var deflated bytes.Buffer
	w, _ := flate.NewWriter(&deflated, flate.BestCompression)
	_, _ = w.Write(data)
	require.NoError(p.t, w.Close())
	query := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(deflated.Bytes())) +
		"&SigAlg=" + url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	if sign {
		digest := sha256.Sum256([]byte(query))
		sig, err := rsa.SignPKCS1v15(rand.Reader, p.idp.Key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
		require.NoError(p.t, err)
		query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return query
}

func TestSAMLSingleLogout(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.OAuth2Client.EnableAutoRegistration, true)()

	p := newSAMLTestIDP(t)
	addSAMLSource(t, "corp", p, nil)
	session := emptyTestSession(t)
	postACS(t, session, "corp", samlSignIn(t, session, "corp", p, samlSession("guid-alice", "alice")))
	require.Equal(t, "alice", signedInAs(t, session))

	t.Run("unsigned request is refused", func(t *testing.T) {
		session.MakeRequest(t, NewRequest(t, "GET", "/user/saml/corp/slo?"+p.logoutRequest("corp", "guid-alice", false)), http.StatusBadRequest)
		assert.Equal(t, "alice", signedInAs(t, session))
	})

	t.Run("another user's logout keeps the session", func(t *testing.T) {
		resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/saml/corp/slo?"+p.logoutRequest("corp", "guid-bob", true)), http.StatusSeeOther)
		assert.True(t, strings.HasPrefix(test.RedirectURL(resp), "https://idp.example.com/slo?SAMLResponse="))
		assert.Equal(t, "alice", signedInAs(t, session))
	})

	logout := p.logoutRequest("corp", "guid-alice", true)
	t.Run("the user's logout signs out", func(t *testing.T) {
		resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/saml/corp/slo?"+logout), http.StatusSeeOther)
		assert.True(t, strings.HasPrefix(test.RedirectURL(resp), "https://idp.example.com/slo?SAMLResponse="))
		assert.Empty(t, signedInAs(t, session))
	})

	t.Run("a logout request is used once", func(t *testing.T) {
		session := emptyTestSession(t)
		postACS(t, session, "corp", samlSignIn(t, session, "corp", p, samlSession("guid-alice", "alice")))
		session.MakeRequest(t, NewRequest(t, "GET", "/user/saml/corp/slo?"+logout), http.StatusBadRequest)
		assert.Equal(t, "alice", signedInAs(t, session))
	})

	t.Run("switching to another account follows the new user", func(t *testing.T) {
		carol := emptyTestSession(t)
		postACS(t, carol, "corp", samlSignIn(t, carol, "corp", p, samlSession("guid-carol", "carol")))
		session := emptyTestSession(t)
		postACS(t, session, "corp", samlSignIn(t, session, "corp", p, samlSession("guid-alice", "alice")))
		postACS(t, session, "corp", samlSignIn(t, session, "corp", p, samlSession("guid-carol", "carol")))
		require.Equal(t, "carol", signedInAs(t, session))

		session.MakeRequest(t, NewRequest(t, "GET", "/user/saml/corp/slo?"+p.logoutRequest("corp", "guid-alice", true)), http.StatusSeeOther)
		assert.Equal(t, "carol", signedInAs(t, session))
		session.MakeRequest(t, NewRequest(t, "GET", "/user/saml/corp/slo?"+p.logoutRequest("corp", "guid-carol", true)), http.StatusSeeOther)
		assert.Empty(t, signedInAs(t, session))
	})

	t.Run("an unfinished sign-in doesn't follow a password sign-in", func(t *testing.T) {
		defer test.MockVariableValue(&setting.OAuth2Client.EnableAutoRegistration, false)()
		session := emptyTestSession(t)
		resp := postACS(t, session, "corp", samlSignIn(t, session, "corp", p, samlSession("guid-mallory", "mallory")))
		require.Equal(t, "/user/link_account", test.RedirectURL(resp))
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/login", map[string]string{
			"user_name": "user2",
			"password":  userPassword,
		}), http.StatusSeeOther)
		require.Equal(t, "user2", signedInAs(t, session))
		session.MakeRequest(t, NewRequest(t, "GET", "/user/saml/corp/slo?"+p.logoutRequest("corp", "guid-mallory", true)), http.StatusSeeOther)
		assert.Equal(t, "user2", signedInAs(t, session))
	})
}

func TestSAMLAdminForm(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	p := newSAMLTestIDP(t)
	source := addSAMLSource(t, "corp", p, nil)
	session := loginUser(t, "user1")

	resp := session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/admin/auths/%d", source.ID)), http.StatusOK)
	doc := NewHTMLParser(t, resp.Body)
	acs, _ := doc.Find("#saml-acs-url").Attr("value")
	assert.Equal(t, setting.AppURL+"user/saml/corp/acs", acs)
	metadata, _ := doc.Find("#saml-metadata-url").Attr("value")
	assert.Equal(t, setting.AppURL+"user/saml/corp/metadata", metadata)

	t.Run("invalid metadata is refused", func(t *testing.T) {
		req := NewRequestWithValues(t, "POST", "/admin/auths/new", map[string]string{
			"type":              fmt.Sprintf("%d", auth.SAML),
			"name":              "broken",
			"is_active":         "on",
			"saml_idp_metadata": "<not-metadata/>",
		})
		resp := session.MakeRequest(t, req, http.StatusOK)
		unittest.AssertNotExistsBean(t, &auth.Source{Name: "broken"})
		// only the refused field is marked
		doc := NewHTMLParser(t, resp.Body)
		assert.Equal(t, 1, doc.Find(".saml-sp-urls ~ .field.error").Length())
		assert.Equal(t, 1, doc.Find(".field.error #saml_idp_metadata").Length())
		assert.Equal(t, 1, doc.Find(".field.error .help.tw-text-red").Length(), "the message is shown under the field")
	})

	t.Run("a private key is stored encrypted and never shown", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

		signed := addSAMLSource(t, "signed", p, map[string]string{
			"saml_sp_certificate": certPEM,
			"saml_sp_private_key": keyPEM,
			"saml_sign_requests":  "on",
		})
		raw, err := signed.Cfg.ToDB()
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "PRIVATE KEY")

		resp := session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/admin/auths/%d", signed.ID)), http.StatusOK)
		assert.NotContains(t, resp.Body.String(), "PRIVATE KEY")

		// the SP metadata names the key, and requests are signed
		assert.NotNil(t, p.sp.SPSSODescriptors[0].KeyDescriptors)
		assert.Contains(t, samlStart(t, emptyTestSession(t), "signed"), "&Signature=")

		edit := func(t *testing.T, values map[string]string) *saml_source.Source {
			payload := map[string]string{
				"type":                fmt.Sprintf("%d", auth.SAML),
				"name":                "signed",
				"is_active":           "on",
				"saml_idp_metadata":   p.metadataXML(),
				"saml_name_id_format": string(saml.PersistentNameIDFormat),
			}
			maps.Copy(payload, values)
			session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/admin/auths/%d", signed.ID), payload), http.StatusSeeOther)
			return unittest.AssertExistsAndLoadBean(t, &auth.Source{ID: signed.ID}).Cfg.(*saml_source.Source)
		}
		t.Run("an edit without the key keeps it", func(t *testing.T) {
			cfg := edit(t, map[string]string{"saml_sp_certificate": certPEM, "saml_sign_requests": "on"})
			assert.Contains(t, cfg.SPPrivateKey, "PRIVATE KEY")
			assert.Contains(t, samlStart(t, emptyTestSession(t), "signed"), "&Signature=")
		})
		t.Run("an edit without certificate and key removes both", func(t *testing.T) {
			cfg := edit(t, nil)
			assert.Empty(t, cfg.SPCertificate)
			assert.Empty(t, cfg.SPPrivateKey)
			assert.NotContains(t, samlStart(t, emptyTestSession(t), "signed"), "&Signature=")
		})
	})

	t.Run("only the SAML checkbox skips local 2FA", func(t *testing.T) {
		// the hidden OAuth2 section of the add page has a checkbox of its own
		source := addSAMLSource(t, "twofa", p, map[string]string{"skip_local_two_fa": "on"})
		assert.False(t, source.Cfg.(*saml_source.Source).SkipLocalTwoFA)
		source = addSAMLSource(t, "twofa2", p, map[string]string{"saml_skip_local_two_fa": "on"})
		assert.True(t, source.Cfg.(*saml_source.Source).SkipLocalTwoFA)
	})
}
