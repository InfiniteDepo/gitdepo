// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"forgejo.org/modules/keying"
)

// Fingerprint returns the hex HMAC-SHA256 of a secret, keyed by a key derived
// from the instance key (keying.SecretScanning). The same secret has the same
// fingerprint in every rule and repository (for private keys, whatever the
// line endings or wrapping, see Rule.Normalize), and the fingerprint can't be
// checked against a dictionary without the instance key, unlike a plain hash.
// keying must be initialized.
func Fingerprint(secret []byte) string {
	return fingerprint(keying.MACKey(keying.SecretScanning), secret)
}

func fingerprint(key, secret []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(secret)
	return hex.EncodeToString(m.Sum(nil))
}
