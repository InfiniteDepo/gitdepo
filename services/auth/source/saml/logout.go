// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strings"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

func newID() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return "id-" + hex.EncodeToString(b)
}

// redirectURL encodes el for the HTTP-Redirect binding as the query parameter param (SAMLRequest or SAMLResponse) of
// destination, and signs the query when the SP signs requests.
func redirectURL(sp *saml.ServiceProvider, destination, param string, el *etree.Element, relayState string) (string, error) {
	u, err := url.Parse(destination)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("invalid IdP URL %q", destination)
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	var buf bytes.Buffer
	b64 := base64.NewEncoder(base64.StdEncoding, &buf)
	fw, _ := flate.NewWriter(b64, flate.BestCompression)
	if _, err := doc.WriteTo(fw); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	if err := b64.Close(); err != nil {
		return "", err
	}

	q := param + "=" + url.QueryEscape(buf.String())
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	if sp.SignatureMethod != "" {
		q += "&SigAlg=" + url.QueryEscape(sp.SignatureMethod)
		sc, err := saml.GetSigningContext(sp)
		if err != nil {
			return "", err
		}
		sig, err := sc.SignString(q)
		if err != nil {
			return "", err
		}
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	if u.RawQuery != "" {
		q = u.RawQuery + "&" + q
	}
	u.RawQuery = q
	return u.String(), nil
}

func sloEndpoint(sp *saml.ServiceProvider) *saml.Endpoint {
	for _, d := range sp.IDPMetadata.IDPSSODescriptors {
		for i, e := range d.SingleLogoutServices {
			if e.Binding == saml.HTTPRedirectBinding {
				return &d.SingleLogoutServices[i]
			}
		}
	}
	return nil
}

// LogoutRequestURL returns the URL that sends the user's logout request to the IdP, "" when the IdP has no single
// logout URL with the HTTP-Redirect binding.
func LogoutRequestURL(sp *saml.ServiceProvider, nameID, nameIDFormat, sessionIndex string) (string, error) {
	e := sloEndpoint(sp)
	if e == nil {
		return "", nil
	}
	req := saml.LogoutRequest{
		ID:           newID(),
		Version:      "2.0",
		IssueInstant: saml.TimeNow(),
		Destination:  e.Location,
		Issuer:       &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: sp.EntityID},
		NameID:       &saml.NameID{Format: nameIDFormat, Value: nameID},
	}
	if sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
	}
	return redirectURL(sp, e.Location, "SAMLRequest", req.Element(), "")
}

// LogoutResponseURL returns the URL that answers the IdP's logout request with success.
func LogoutResponseURL(sp *saml.ServiceProvider, requestID, relayState string) (string, error) {
	e := sloEndpoint(sp)
	if e == nil {
		return "", errors.New("the IdP has no single logout URL with the HTTP-Redirect binding")
	}
	location := e.Location
	if e.ResponseLocation != "" {
		location = e.ResponseLocation
	}
	resp := saml.LogoutResponse{
		ID:           newID(),
		InResponseTo: requestID,
		Version:      "2.0",
		IssueInstant: saml.TimeNow(),
		Destination:  location,
		Issuer:       &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: sp.EntityID},
		Status:       saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	}
	return redirectURL(sp, location, "SAMLResponse", resp.Element(), relayState)
}

// rawQueryParam returns the raw (still URL-encoded) value of a parameter that must appear at most once, with its
// name written plainly: the signed octets are the raw parameters, so no other spelling may name it.
func rawQueryParam(rawQuery, name string) (string, bool, error) {
	var value string
	found := false
	for part := range strings.SplitSeq(rawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		if key, err := url.QueryUnescape(k); err != nil || key != name {
			continue
		}
		if found || k != name {
			return "", false, fmt.Errorf("duplicate or encoded query parameter %s", name)
		}
		value, found = v, true
	}
	return value, found, nil
}

var sigAlgs = map[string]crypto.Hash{
	dsig.RSASHA256SignatureMethod:   crypto.SHA256,
	dsig.RSASHA512SignatureMethod:   crypto.SHA512,
	dsig.ECDSASHA256SignatureMethod: crypto.SHA256,
	dsig.ECDSASHA512SignatureMethod: crypto.SHA512,
}

// idpSigningCerts returns the IdP certificates for signing ("signing" or no use).
func idpSigningCerts(sp *saml.ServiceProvider) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, d := range sp.IDPMetadata.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if kd.Use != "" && kd.Use != "signing" {
				continue
			}
			for _, c := range kd.KeyInfo.X509Data.X509Certificates {
				if cert, err := ParseCertificate(c.Data); err == nil {
					certs = append(certs, cert)
				}
			}
		}
	}
	return certs
}

// verifyRedirectSignature checks the HTTP-Redirect binding signature of a message (SAML bindings §3.4.4.1): the
// signed octets are the parameters exactly as received, in the order SAMLRequest, RelayState, SigAlg. It returns the
// decoded message and RelayState taken from those same signed parameters.
func verifyRedirectSignature(sp *saml.ServiceProvider, rawQuery, param string) (message, relayState string, err error) {
	rawMessage, _, err := rawQueryParam(rawQuery, param)
	if err != nil {
		return "", "", err
	}
	rawRelay, hasRelay, err := rawQueryParam(rawQuery, "RelayState")
	if err != nil {
		return "", "", err
	}
	rawSigAlg, hasSigAlg, err := rawQueryParam(rawQuery, "SigAlg")
	if err != nil {
		return "", "", err
	}
	rawSig, hasSig, err := rawQueryParam(rawQuery, "Signature")
	if err != nil {
		return "", "", err
	}
	if !hasSigAlg || !hasSig {
		return "", "", errors.New("the message is not signed")
	}
	if message, err = url.QueryUnescape(rawMessage); err != nil {
		return "", "", err
	}
	if relayState, err = url.QueryUnescape(rawRelay); err != nil {
		return "", "", err
	}
	sigAlg, err := url.QueryUnescape(rawSigAlg)
	if err != nil {
		return "", "", err
	}
	hash, ok := sigAlgs[sigAlg]
	if !ok {
		return "", "", fmt.Errorf("unsupported signature algorithm %q", sigAlg)
	}
	sigB64, err := url.QueryUnescape(rawSig)
	if err != nil {
		return "", "", err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", "", errors.New("the signature is not base64")
	}

	signed := param + "=" + rawMessage
	if hasRelay {
		signed += "&RelayState=" + rawRelay
	}
	signed += "&SigAlg=" + rawSigAlg
	h := hash.New()
	h.Write([]byte(signed))
	digest := h.Sum(nil)

	for _, cert := range idpSigningCerts(sp) {
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if strings.Contains(sigAlg, "rsa-") && rsa.VerifyPKCS1v15(pub, hash, digest, sig) == nil {
				return message, relayState, nil
			}
		case *ecdsa.PublicKey:
			if strings.Contains(sigAlg, "ecdsa-") && verifyECDSA(pub, digest, sig) {
				return message, relayState, nil
			}
		}
	}
	return "", "", errors.New("the signature does not match an IdP signing certificate")
}

// verifyECDSA accepts an ASN.1 signature or the r||s concatenation of XML signatures.
func verifyECDSA(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	if ecdsa.VerifyASN1(pub, digest, sig) {
		return true
	}
	n := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*n {
		return false
	}
	return ecdsa.Verify(pub, digest, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:]))
}

// ParseLogoutRequest verifies a logout request the IdP sent with the HTTP-Redirect binding. It must be signed by the
// IdP, addressed to this SP's logout URL, current and used once.
func (source *Source) ParseLogoutRequest(sp *saml.ServiceProvider, rawQuery string) (*saml.LogoutRequest, string, error) {
	message, relayState, err := verifyRedirectSignature(sp, rawQuery, "SAMLRequest")
	if err != nil {
		return nil, "", err
	}
	deflated, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return nil, "", errors.New("the request is not base64")
	}
	data, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(deflated)), MaxResponseSize+1))
	if err != nil {
		return nil, "", fmt.Errorf("inflate the request: %w", err)
	}
	if len(data) > MaxResponseSize {
		return nil, "", errors.New("the request is too large")
	}
	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		return nil, "", fmt.Errorf("invalid XML: %w", err)
	}
	var req saml.LogoutRequest
	if err := xml.Unmarshal(data, &req); err != nil {
		return nil, "", fmt.Errorf("invalid logout request: %w", err)
	}

	now := saml.TimeNow()
	switch {
	case req.ID == "":
		return nil, "", errors.New("the logout request has no ID")
	case req.Issuer == nil || req.Issuer.Value != sp.IDPMetadata.EntityID:
		return nil, "", errors.New("the logout request is not from the IdP")
	case req.Destination != sp.SloURL.String():
		return nil, "", fmt.Errorf("the logout request is for %q", req.Destination)
	case req.IssueInstant.Add(saml.MaxIssueDelay + saml.MaxClockSkew).Before(now), req.IssueInstant.Add(-saml.MaxClockSkew).After(now):
		return nil, "", errors.New("the logout request is not current")
	case req.NotOnOrAfter != nil && req.NotOnOrAfter.Add(saml.MaxClockSkew).Before(now):
		return nil, "", errors.New("the logout request expired")
	case req.NameID == nil || req.NameID.Value == "":
		return nil, "", errors.New("the logout request has no NameID")
	}
	if err := useOnce("logout", source.authSource.ID, req.ID, saml.MaxIssueDelay+2*saml.MaxClockSkew); err != nil {
		return nil, "", err
	}
	return &req, relayState, nil
}
