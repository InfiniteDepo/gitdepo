// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package saml

import (
	"forgejo.org/models/auth"
	"forgejo.org/modules/json"
	"forgejo.org/modules/secret"
	"forgejo.org/modules/setting"
	source_service "forgejo.org/services/auth/source"
	"forgejo.org/services/auth/source/oauth2"
)

// Source holds the configuration of a SAML 2.0 login source: forgejo is the service provider (SP), the configured
// identity provider (IdP) signs the assertions.
type Source struct {
	// The IdP: a metadata URL (refreshed hourly), metadata XML, or the entity ID, SSO URL and signing certificate.
	IDPMetadataURL string
	IDPMetadata    string
	IDPEntityID    string
	IDPSSOURL      string
	IDPSLOURL      string
	IDPCertificate string

	// The SP: the entity ID defaults to the metadata URL. The key signs requests and decrypts assertions.
	SPEntityID          string
	SPCertificate       string
	SPPrivateKey        string
	SPPrivateKeyEncrypt string
	SignRequests        bool

	// NameIDFormat is the format requested from the IdP. UserIDAttribute names the attribute that holds the stable
	// identifier; empty means the NameID.
	NameIDFormat      string
	UserIDAttribute   string
	UsernameAttribute string
	FullNameAttribute string
	EmailAttribute    string

	RequireEncryptedAssertions bool
	ForceAuthn                 bool
	AllowIDPInitiated          bool
	IconURL                    string
	SkipLocalTwoFA             bool

	// The claim settings, as in OAuth2 sources: an attribute is a claim.
	RequiredClaimName        string
	RequiredClaimValue       string
	GroupClaimName           string
	AdminGroup               string
	RestrictedGroup          string
	GroupTeamMap             string
	GroupTeamMapRemoval      bool
	DynGroupMaps             string
	DynGroupMapsRemoval      bool
	QuotaGroupClaimName      string
	QuotaGroupMap            string
	QuotaGroupMapRemoval     bool
	GroupUserGroupMap        string
	GroupUserGroupMapRemoval bool

	// reference to the authSource
	authSource *auth.Source
}

// FromDB fills up a SAML source from its serialized format.
func (source *Source) FromDB(bs []byte) error {
	err := json.UnmarshalHandleDoubleEncode(bs, &source)
	if err != nil {
		return err
	}
	if source.SPPrivateKeyEncrypt != "" {
		source.SPPrivateKey, err = secret.DecryptSecret(setting.SecretKey, source.SPPrivateKeyEncrypt)
		source.SPPrivateKeyEncrypt = ""
	}
	return err
}

// ToDB exports a SAML source to its serialized format; the SP private key is stored encrypted.
func (source *Source) ToDB() ([]byte, error) {
	if source.SPPrivateKey != "" {
		var err error
		source.SPPrivateKeyEncrypt, err = secret.EncryptSecret(setting.SecretKey, source.SPPrivateKey)
		if err != nil {
			return nil, err
		}
	}
	source.SPPrivateKey = ""
	return json.Marshal(source)
}

// SetAuthSource sets the related AuthSource
func (source *Source) SetAuthSource(authSource *auth.Source) {
	source.authSource = authSource
}

// RegisterSource drops the cached IdP metadata, so a changed source loads it again.
func (source *Source) RegisterSource() error {
	source_service.RemoveDynGroupMaps(source.authSource.ID)
	forgetMetadata(source.authSource.ID)
	return nil
}

// UnregisterSource drops the cached IdP metadata.
func (source *Source) UnregisterSource() error {
	source_service.RemoveDynGroupMaps(source.authSource.ID)
	forgetMetadata(source.authSource.ID)
	return nil
}

// DisplayName is the type shown next to linked accounts.
func (source *Source) DisplayName() string {
	return "SAML"
}

// ClaimSettings returns the claim and group settings in the shape of an OAuth2 source, so that the sign-in code
// that syncs groups, admin and restricted flags serves both.
func (source *Source) ClaimSettings() *oauth2.Source {
	return &oauth2.Source{
		RequiredClaimName:        source.RequiredClaimName,
		RequiredClaimValue:       source.RequiredClaimValue,
		GroupClaimName:           source.GroupClaimName,
		AdminGroup:               source.AdminGroup,
		RestrictedGroup:          source.RestrictedGroup,
		GroupTeamMap:             source.GroupTeamMap,
		GroupTeamMapRemoval:      source.GroupTeamMapRemoval,
		DynGroupMaps:             source.DynGroupMaps,
		DynGroupMapsRemoval:      source.DynGroupMapsRemoval,
		QuotaGroupClaimName:      source.QuotaGroupClaimName,
		QuotaGroupMap:            source.QuotaGroupMap,
		QuotaGroupMapRemoval:     source.QuotaGroupMapRemoval,
		GroupUserGroupMap:        source.GroupUserGroupMap,
		GroupUserGroupMapRemoval: source.GroupUserGroupMapRemoval,
		SkipLocalTwoFA:           source.SkipLocalTwoFA,
	}
}

func init() {
	auth.RegisterTypeConfig(auth.SAML, &Source{})
}
