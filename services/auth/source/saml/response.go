// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package saml

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"forgejo.org/modules/cache"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/markbates/goth"
)

// MaxResponseSize bounds the decoded SAMLResponse.
const MaxResponseSize = 1 << 20

// ErrInvalidResponse is returned for any response that is refused; the cause is only logged.
type ErrInvalidResponse struct {
	Cause error
}

func (err ErrInvalidResponse) Error() string {
	return "invalid SAML response: " + err.Cause.Error()
}

func (err ErrInvalidResponse) Unwrap() error {
	return err.Cause
}

func invalid(format string, args ...any) error {
	return ErrInvalidResponse{Cause: fmt.Errorf(format, args...)}
}

// Assertion is what a verified response says about the user.
type Assertion struct {
	User         goth.User
	NameID       string
	NameIDFormat string
	SessionIndex string
}

// ParseResponse verifies a base64 SAMLResponse posted to the ACS and returns the user it asserts. requestID is the ID
// of the AuthnRequest this browser sent: a response must answer it, so an unsolicited one is always refused.
func (source *Source) ParseResponse(sp *saml.ServiceProvider, samlResponse, requestID string) (*Assertion, error) {
	if base64.StdEncoding.DecodedLen(len(samlResponse)) > MaxResponseSize {
		return nil, invalid("the response is larger than %d bytes", MaxResponseSize)
	}
	raw, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, invalid("the response is not base64")
	}
	if requestID == "" {
		return nil, invalid("no sign-in was started in this browser")
	}
	if source.RequireEncryptedAssertions {
		if err := checkNoPlainAssertion(raw); err != nil {
			return nil, err
		}
	}

	if err := checkKeyTransport(raw); err != nil {
		return nil, err
	}

	// sp.AllowIDPInitiated stays false: the library skips InResponseTo when it is set
	a, err := sp.ParseXMLResponse(raw, []string{requestID}, sp.AcsURL)
	if err != nil {
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			err = ire.PrivateErr
		}
		return nil, ErrInvalidResponse{Cause: err}
	}
	if err := checkReplay(source.authSource.ID, a); err != nil {
		return nil, err
	}
	return source.toAssertion(a)
}

// checkNoPlainAssertion refuses a response that carries an unencrypted Assertion anywhere: the library would accept
// it alongside, or instead of, an EncryptedAssertion.
func checkNoPlainAssertion(raw []byte) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return invalid("the response is not XML")
	}
	elements := []*etree.Element{doc.Root()}
	for len(elements) > 0 {
		el := elements[len(elements)-1]
		elements = elements[:len(elements)-1]
		if el.Tag == "Assertion" {
			return invalid("the response holds an unencrypted assertion and this source requires encryption")
		}
		elements = append(elements, el.ChildElements()...)
	}
	return nil
}

// checkKeyTransport refuses RSA PKCS#1 v1.5 key transport in an encrypted assertion: its padding errors are an
// oracle for the SP key (Bleichenbacher).
func checkKeyTransport(raw []byte) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return invalid("the response is not XML")
	}
	for _, m := range doc.Root().FindElements("//EncryptionMethod") {
		if m.SelectAttrValue("Algorithm", "") == "http://www.w3.org/2001/04/xmlenc#rsa-1_5" {
			return invalid("the assertion key is encrypted with RSA PKCS#1 v1.5")
		}
	}
	return nil
}

var replayMu sync.Mutex

// checkReplay refuses an assertion ID seen before, until the assertion expires. The cache is per process unless the
// instance uses a shared cache (redis); requests started in the browser are also bound to its session.
func checkReplay(sourceID int64, a *saml.Assertion) error {
	if a.ID == "" {
		return invalid("the assertion has no ID")
	}
	// at least as long as the library accepts the assertion after it was issued
	ttl := time.Until(a.Conditions.NotOnOrAfter.Add(saml.MaxClockSkew))
	ttl = min(max(ttl, time.Until(a.IssueInstant.Add(saml.MaxIssueDelay+2*saml.MaxClockSkew))), 24*time.Hour)
	return useOnce("assertion", sourceID, a.ID, ttl)
}

// useOnce records a message ID for ttl and refuses one that was recorded before.
func useOnce(kind string, sourceID int64, id string, ttl time.Duration) error {
	c := cache.GetCache()
	if c == nil {
		return invalid("no cache to record the %s ID", kind)
	}
	sum := sha256.Sum256([]byte(id))
	key := fmt.Sprintf("saml_%s_%d_%s", kind, sourceID, hex.EncodeToString(sum[:]))

	replayMu.Lock()
	defer replayMu.Unlock()
	if c.IsExist(key) {
		return invalid("the %s was used before", kind)
	}
	if err := c.Put(key, 1, int64(ttl/time.Second)+1); err != nil {
		return invalid("record the %s ID: %v", kind, err)
	}
	return nil
}

// attributes returns the values of each attribute by name, and by friendly name where no attribute has that name.
func attributes(a *saml.Assertion) map[string][]string {
	attrs := map[string][]string{}
	friendly := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			var values []string
			for _, v := range attr.Values {
				if v.NameID != nil {
					values = append(values, v.NameID.Value)
				} else {
					values = append(values, v.Value)
				}
			}
			if attr.Name != "" {
				attrs[attr.Name] = append(attrs[attr.Name], values...)
			}
			if attr.FriendlyName != "" {
				friendly[attr.FriendlyName] = append(friendly[attr.FriendlyName], values...)
			}
		}
	}
	for name, values := range friendly {
		if _, ok := attrs[name]; !ok {
			attrs[name] = values
		}
	}
	return attrs
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// maxExternalIDLength is the length of external_login_user.external_id and user.login_name.
const maxExternalIDLength = 255

func (source *Source) toAssertion(a *saml.Assertion) (*Assertion, error) {
	if a.Subject == nil || a.Subject.NameID == nil || a.Subject.NameID.Value == "" {
		return nil, invalid("the assertion has no NameID")
	}
	if !slices.ContainsFunc(a.Subject.SubjectConfirmations, func(c saml.SubjectConfirmation) bool {
		return c.Method == "urn:oasis:names:tc:SAML:2.0:cm:bearer" && c.SubjectConfirmationData != nil
	}) {
		// without one the library checks neither the recipient nor the request the assertion answers
		return nil, invalid("the assertion has no bearer subject confirmation")
	}
	attrs := attributes(a)
	nameID := a.Subject.NameID
	if source.UserIDAttribute == "" {
		// the NameID is the account: a transient one, or one of another kind than configured, isn't a stable ID
		if nameID.Format == string(saml.TransientNameIDFormat) ||
			nameID.Format != "" && source.NameIDFormat != string(saml.UnspecifiedNameIDFormat) && nameID.Format != source.NameIDFormat {
			return nil, invalid("the NameID format %q can't identify the account (configured: %q)", nameID.Format, source.NameIDFormat)
		}
	}

	userID := nameID.Value
	if source.UserIDAttribute != "" {
		values := attrs[source.UserIDAttribute]
		if len(values) != 1 || values[0] == "" {
			return nil, invalid("the attribute %q must hold exactly one user ID, it has %d values", source.UserIDAttribute, len(values))
		}
		userID = values[0]
	}
	if len(userID) > maxExternalIDLength {
		return nil, invalid("the user ID is longer than %d bytes", maxExternalIDLength)
	}

	rawData := make(map[string]any, len(attrs)+1)
	for name, values := range attrs {
		rawData[name] = values
	}
	// one value each: with several, which one would decide the account is up to the IdP's order
	for _, name := range []string{source.UsernameAttribute, source.EmailAttribute} {
		if len(attrs[name]) > 1 {
			return nil, invalid("the attribute %q has %d values", name, len(attrs[name]))
		}
	}
	email := first(attrs[source.EmailAttribute])
	if email == "" && nameID.Format == string(saml.EmailAddressNameIDFormat) {
		email = nameID.Value
	}
	username := first(attrs[source.UsernameAttribute])
	if username == "" {
		username, _, _ = strings.Cut(email, "@")
	}
	rawData["preferred_username"] = username

	result := &Assertion{
		User: goth.User{
			Provider: source.authSource.Name,
			UserID:   userID,
			NickName: username,
			Name:     first(attrs[source.FullNameAttribute]),
			Email:    email,
			RawData:  rawData,
		},
		NameID:       nameID.Value,
		NameIDFormat: nameID.Format,
	}
	if len(a.AuthnStatements) > 0 {
		result.SessionIndex = a.AuthnStatements[0].SessionIndex
	}
	return result, nil
}
