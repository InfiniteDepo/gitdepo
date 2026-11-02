// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"forgejo.org/modules/log"
	"forgejo.org/modules/setting/config"
)

// SecretScanningOptions are the secret scanning settings. SecretScanning holds the [secret_scanning] section of
// app.ini; SecretScanningSettings is what is in force (the values saved in Site administration win).
type SecretScanningOptions struct {
	Enabled      bool
	GenericRules bool // also run the rules that are noisy by default (secretdetection.Rule.DefaultOff)
	ScanText     bool // also scan the text of issues, pull requests and comments (on by default)

	MaxConcurrentScans   int64         // scans running at once in this process
	ScanTimeout          time.Duration // the time of one slice of a scan
	MaxBlobSize          int64         // bytes of one file; a larger one is skipped without being read
	MaxScanBytes         int64         // bytes read by one slice of a scan (a slice is one queue item; a larger repository takes several)
	MaxScanBlobs         int64         // files read by one slice of a scan
	MaxAlertsPerRepo     int64
	MaxLocationsPerAlert int64
	MaxTextBytes         int64 // bytes of one issue, pull request or comment text that are scanned; the rest is cut
}

// SecretScanning is the [secret_scanning] section of app.ini, the defaults of SecretScanningSettings.
var SecretScanning SecretScanningOptions

// SecretScanningLimit is one numeric setting: its name (in the saved configuration, the admin form and the audit
// log), its app.ini key, its default and its bounds. Durations are counted in seconds.
type SecretScanningLimit struct {
	Name, Key         string
	Default, Min, Max int64
	Duration          bool
	field             func(o *SecretScanningOptions) any // *int64 or *time.Duration
}

// SecretScanningLimits are the numeric settings, checked by the same bounds in app.ini and in Site administration.
// The lower bounds of the scan time, the file size and the alert cap keep an admin from making scanning ineffective
// by accident (a one-second scan, a one-byte file limit, a handful of alerts).
var SecretScanningLimits = []SecretScanningLimit{
	{"max_concurrent_scans", "MAX_CONCURRENT_SCANS", 1, 1, 16, false, func(o *SecretScanningOptions) any { return &o.MaxConcurrentScans }},
	{"scan_timeout", "SCAN_TIMEOUT", 300, 30, 24 * 3600, true, func(o *SecretScanningOptions) any { return &o.ScanTimeout }},
	{"max_blob_size", "MAX_BLOB_SIZE", 1 << 20, 64 << 10, 100 << 20, false, func(o *SecretScanningOptions) any { return &o.MaxBlobSize }},
	{"max_scan_bytes", "MAX_SCAN_BYTES", 2 << 30, 1 << 20, 1 << 40, false, func(o *SecretScanningOptions) any { return &o.MaxScanBytes }},
	{"max_scan_blobs", "MAX_SCAN_BLOBS", 2_000_000, 1000, 100_000_000, false, func(o *SecretScanningOptions) any { return &o.MaxScanBlobs }},
	{"max_alerts_per_repo", "MAX_ALERTS_PER_REPO", 10_000, 100, 1_000_000, false, func(o *SecretScanningOptions) any { return &o.MaxAlertsPerRepo }},
	{"max_locations_per_alert", "MAX_LOCATIONS_PER_ALERT", 100, 1, 10_000, false, func(o *SecretScanningOptions) any { return &o.MaxLocationsPerAlert }},
	{"max_text_bytes", "MAX_TEXT_BYTES", 1 << 20, 1 << 10, 16 << 20, false, func(o *SecretScanningOptions) any { return &o.MaxTextBytes }},
}

// SecretScanningLimitByName finds a limit by its name.
func SecretScanningLimitByName(name string) (SecretScanningLimit, bool) {
	for _, l := range SecretScanningLimits {
		if l.Name == name {
			return l, true
		}
	}
	return SecretScanningLimit{}, false
}

// Check refuses a value outside the bounds; the message names the setting.
func (l SecretScanningLimit) Check(v int64) error {
	if v < l.Min || v > l.Max {
		return fmt.Errorf("%s must be %d to %d", l.Name, l.Min, l.Max)
	}
	return nil
}

// Get reads the limit from the options (seconds for a duration).
func (l SecretScanningLimit) Get(o *SecretScanningOptions) int64 {
	switch p := l.field(o).(type) {
	case *int64:
		return *p
	case *time.Duration:
		return int64(*p / time.Second)
	}
	return 0
}

func (l SecretScanningLimit) set(o *SecretScanningOptions, v int64) {
	switch p := l.field(o).(type) {
	case *int64:
		*p = v
	case *time.Duration:
		*p = time.Duration(v) * time.Second
	}
}

var secretScanningDigits = regexp.MustCompile(`^[0-9]+$`)

// loadSecretScanningFrom reads [secret_scanning]. One rule for every key: a value that can't be read is logged and the
// default is used, and the server never stops for it. Integers are plain decimal digits (no sign, hex or separators),
// SCAN_TIMEOUT is a duration (5m) or a bare number of seconds, and a number outside its bounds is clamped with a warning.
func loadSecretScanningFrom(rootCfg ConfigProvider) error {
	sec := rootCfg.Section("secret_scanning")
	SecretScanning.Enabled = secretScanningBool(sec, "ENABLED", false)
	SecretScanning.GenericRules = secretScanningBool(sec, "GENERIC_RULES", false)
	SecretScanning.ScanText = secretScanningBool(sec, "SCAN_TEXT", true)
	for _, l := range SecretScanningLimits {
		v := l.Default
		if raw := strings.TrimSpace(sec.Key(l.Key).String()); raw != "" {
			parsed, ok := parseSecretScanningValue(raw, l.Duration)
			if ok {
				v = parsed
			} else {
				log.Warn("[secret_scanning] %s %q can't be read as %s, using the default %d", l.Key, raw, map[bool]string{true: "a duration or a number of seconds", false: "a whole number"}[l.Duration], l.Default)
			}
		}
		if err := l.Check(v); err != nil {
			clamped := min(max(v, l.Min), l.Max)
			log.Warn("[secret_scanning] %s %d is out of bounds (%d to %d), using %d", l.Key, v, l.Min, l.Max, clamped)
			v = clamped
		}
		l.set(&SecretScanning, v)
	}
	return nil
}

// secretScanningBool reads a boolean key: a word that is none (the ones MapTo reads) is logged and the default is used.
func secretScanningBool(sec ConfigSection, key string, def bool) bool {
	raw := strings.TrimSpace(sec.Key(key).String())
	if raw == "" {
		return def
	}
	v, err := sec.Key(key).Bool()
	if err != nil {
		log.Warn("[secret_scanning] %s %q is not a boolean, using the default %t", key, raw, def)
		return def
	}
	return v
}

// parseSecretScanningValue reads plain decimal digits (any number of them: one too long for 64 bits reads as the
// largest number, so it is clamped to the key's maximum) and, for a duration, also a Go duration (seconds as the unit
// of the result).
func parseSecretScanningValue(raw string, duration bool) (int64, bool) {
	if secretScanningDigits.MatchString(raw) {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return math.MaxInt64, true
		}
		return v, true
	}
	if duration {
		d, err := time.ParseDuration(raw)
		if err == nil && d >= 0 {
			return int64(d / time.Second), true
		}
	}
	return 0, false
}

// SecretScanningState is stored as JSON in the "secret_scanning.enabled" system setting. An empty Mode means the
// app.ini default ([secret_scanning] ENABLED); once the switch is saved in Site administration, the stored value wins.
type SecretScanningState struct {
	Mode        string `json:"mode"` // "on", "off" or "" (app.ini)
	UpdatedBy   int64  `json:"updated_by,omitempty"`
	UpdatedUnix int64  `json:"updated_unix,omitempty"`
}

// Enabled is the site switch in force. A stored value that can't be parsed or isn't known reads as off.
func (s SecretScanningState) Enabled() bool {
	switch s.Mode {
	case "":
		return SecretScanning.Enabled
	case "on":
		return true
	}
	return false
}

// SecretScanningConfig is stored as JSON in the "secret_scanning.config" system setting: the settings saved in Site
// administration (the site switch is SecretScanningState). Every field is optional: what isn't stored is the app.ini
// value. Invalid marks a stored value that can't be parsed.
type SecretScanningConfig struct {
	Invalid bool `json:"-"`

	GenericRules *bool            `json:"generic_rules,omitempty"`
	ScanText     *bool            `json:"scan_text,omitempty"`
	Limits       map[string]int64 `json:"limits,omitempty"` // by SecretScanningLimit.Name; seconds for a duration
	UpdatedBy    int64            `json:"updated_by,omitempty"`
	UpdatedUnix  int64            `json:"updated_unix,omitempty"`
}

// mergedSecretScanning caches SecretScanningSettings: Merge (and its logs) runs once per settings revision and
// app.ini values.
var mergedSecretScanning struct {
	sync.Mutex
	revision int
	base     SecretScanningOptions
	merged   SecretScanningOptions
	ok       bool
}

// SecretScanningSettings is the secret scanning configuration in force: the values saved in Site administration over
// app.ini. Read it before building a query, never while one is being built.
func SecretScanningSettings(ctx context.Context) SecretScanningOptions {
	// the revision first: a value read after it is never older than its key (a newer one is merged again next time)
	revision := config.GetDynGetter().GetRevision(ctx)
	stored := Config().SecretScanningConfig.Value(ctx) // outside the lock: it may query the database
	m := &mergedSecretScanning
	m.Lock()
	defer m.Unlock()
	if m.ok && m.revision == revision && m.base == SecretScanning {
		return m.merged
	}
	m.revision, m.base, m.merged, m.ok = revision, SecretScanning, stored.Merge(), true
	return m.merged
}

// Merge applies the stored values over app.ini. A stored value that can't be used is logged and its app.ini value is
// used.
func (c SecretScanningConfig) Merge() SecretScanningOptions {
	o := SecretScanning
	if c.Invalid {
		return o
	}
	if c.GenericRules != nil {
		o.GenericRules = *c.GenericRules
	}
	if c.ScanText != nil {
		o.ScanText = *c.ScanText
	}
	for name, v := range c.Limits {
		l, ok := SecretScanningLimitByName(name)
		if !ok {
			log.Error("secret_scanning.config: unknown setting %q is ignored", name)
			continue
		}
		if err := l.Check(v); err != nil {
			log.Error("secret_scanning.config: %v, using the app.ini value", err)
			continue
		}
		l.set(&o, v)
	}
	return o
}
