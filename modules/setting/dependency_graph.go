// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"forgejo.org/modules/log"
	"forgejo.org/modules/secret"
	"forgejo.org/modules/setting/config"
)

// DefaultOSVMirrorURL is the public OSV bucket.
const DefaultOSVMirrorURL = "https://osv-vulnerabilities.storage.googleapis.com"

// DependencyGraphOptions are the dependency graph settings: the manifests of the default branch are read into a list
// of dependencies per repository, and an SBOM can be exported from it. DependencyGraph holds the [dependency_graph]
// section of app.ini; DependencyGraphSettings is what is in force (the values saved in Site administration win).
type DependencyGraphOptions struct {
	Enabled            bool
	MaxManifestSize    int64 // bytes of one lock file; the small formats (go.mod, requirements.txt, ...) stop at 1 MiB
	MaxManifests       int   // manifests read per repository
	MaxDependencies    int   // dependencies stored per repository
	MaxTreeEntries     int   // entries of the tree a scan walks
	ScanTimeout        time.Duration
	MaxConcurrentScans int // scans running at once in this process

	// The OSV mirror (services/vulnerability). An empty OSVMirrorURL means no download (offline).
	OSVMirrorURL        string
	OSVMirrorToken      string // sent to the mirror's own scheme and host only; never shown, registered with log.RegisterSecret
	OSVMirrorUser       string // with it, the token is the password of Basic auth instead of a Bearer token
	OSVMirrorHosts      string // hostmatcher list that replaces [webhook] ALLOWED_HOST_LIST for the mirror, when set
	UpdateInterval      time.Duration
	OSVMaxDownload      int64 // bytes of one ecosystem's all.zip
	OSVMaxEntries       int   // entries of one zip
	OSVMaxEntrySize     int64 // uncompressed bytes of one entry
	OSVMaxUncompressed  int64 // uncompressed bytes of one zip
	OSVEcosystemTimeout time.Duration

	// MirrorConfigInvalid is set by DependencyGraphSettings when the saved mirror settings can't be used (the
	// configuration, its URL, host list, sign-in or token can't be read): the mirror downloads nothing then.
	MirrorConfigInvalid bool
	// OSVMirrorHostsFromPage marks a host list saved in Site administration: it is narrower by rule
	// (CheckPageHostList), and the mirror's dial check also blocks the internal addresses (MirrorBlockedHosts).
	OSVMirrorHostsFromPage bool
	// OSVMirrorURLFromPage marks a mirror URL saved in Site administration (other than app.ini's): the mirror's dial
	// check blocks the internal addresses then too, so a DNS name of this machine is refused when it is dialled.
	OSVMirrorURLFromPage bool
}

// DependencyGraph is the [dependency_graph] section of app.ini, the defaults of DependencyGraphSettings.
var DependencyGraph DependencyGraphOptions

// DependencyGraphLimit is one numeric setting of the dependency graph: its name (in the saved configuration, the
// admin form and the audit log), its app.ini key and its bounds. Durations are counted in seconds.
type DependencyGraphLimit struct {
	Name, Key string
	Min, Max  int64
	Duration  bool
	field     func(o *DependencyGraphOptions) any // *int, *int64 or *time.Duration
}

// DependencyGraphLimits are the numeric settings, checked by the same bounds in app.ini and in Site administration.
var DependencyGraphLimits = []DependencyGraphLimit{
	{"max_concurrent_scans", "MAX_CONCURRENT_SCANS", 1, 16, false, func(o *DependencyGraphOptions) any { return &o.MaxConcurrentScans }},
	{"scan_timeout", "SCAN_TIMEOUT", 1, 24 * 3600, true, func(o *DependencyGraphOptions) any { return &o.ScanTimeout }},
	{"max_manifest_size", "MAX_MANIFEST_SIZE", 1, 100 << 20, false, func(o *DependencyGraphOptions) any { return &o.MaxManifestSize }},
	{"max_manifests", "MAX_MANIFESTS", 1, 100000, false, func(o *DependencyGraphOptions) any { return &o.MaxManifests }},
	{"max_dependencies", "MAX_DEPENDENCIES", 1, 1000000, false, func(o *DependencyGraphOptions) any { return &o.MaxDependencies }},
	{"max_tree_entries", "MAX_TREE_ENTRIES", 1, 10000000, false, func(o *DependencyGraphOptions) any { return &o.MaxTreeEntries }},
	{"update_interval", "UPDATE_INTERVAL", int64(MinUpdateInterval / time.Second), int64(MaxUpdateInterval / time.Second), true, func(o *DependencyGraphOptions) any { return &o.UpdateInterval }},
	{"osv_max_download", "OSV_MAX_DOWNLOAD", 1, 16 << 30, false, func(o *DependencyGraphOptions) any { return &o.OSVMaxDownload }},
	{"osv_max_entries", "OSV_MAX_ENTRIES", 1, 10000000, false, func(o *DependencyGraphOptions) any { return &o.OSVMaxEntries }},
	{"osv_max_entry_size", "OSV_MAX_ENTRY_SIZE", 1, 1 << 30, false, func(o *DependencyGraphOptions) any { return &o.OSVMaxEntrySize }},
	{"osv_max_uncompressed", "OSV_MAX_UNCOMPRESSED", 1, 256 << 30, false, func(o *DependencyGraphOptions) any { return &o.OSVMaxUncompressed }},
	{"osv_ecosystem_timeout", "OSV_ECOSYSTEM_TIMEOUT", 1, 24 * 3600, true, func(o *DependencyGraphOptions) any { return &o.OSVEcosystemTimeout }},
}

// DependencyGraphLimitByName finds a limit by its name.
func DependencyGraphLimitByName(name string) (DependencyGraphLimit, bool) {
	for _, l := range DependencyGraphLimits {
		if l.Name == name {
			return l, true
		}
	}
	return DependencyGraphLimit{}, false
}

// Check refuses a value outside the bounds; the message names the setting.
func (l DependencyGraphLimit) Check(v int64) error {
	if v < l.Min || v > l.Max {
		return fmt.Errorf("%s must be %d to %d", l.Name, l.Min, l.Max)
	}
	return nil
}

// Get is the value of the limit in o (seconds for a duration).
func (l DependencyGraphLimit) Get(o *DependencyGraphOptions) int64 {
	switch p := l.field(o).(type) {
	case *int:
		return int64(*p)
	case *int64:
		return *p
	case *time.Duration:
		return int64(*p / time.Second)
	}
	return 0
}

func (l DependencyGraphLimit) set(o *DependencyGraphOptions, v int64) {
	switch p := l.field(o).(type) {
	case *int:
		*p = int(v)
	case *int64:
		*p = v
	case *time.Duration:
		*p = time.Duration(v) * time.Second
	}
}

// dependencyGraphLimitDefaults are the app.ini defaults of the limits, by name
var dependencyGraphLimitDefaults = map[string]any{
	"max_concurrent_scans": 1, "scan_timeout": 60 * time.Second, "max_manifest_size": int64(20 << 20), "max_manifests": 500,
	"max_dependencies": 50000, "max_tree_entries": 200000, "update_interval": 24 * time.Hour, "osv_max_download": int64(512 << 20),
	"osv_max_entries": 500000, "osv_max_entry_size": int64(4 << 20), "osv_max_uncompressed": int64(4 << 30),
	"osv_ecosystem_timeout": 15 * time.Minute,
}

func loadDependencyGraphFrom(rootCfg ConfigProvider) error {
	sec := rootCfg.Section("dependency_graph")
	DependencyGraph.Enabled = sec.Key("ENABLED").MustBool(false)
	for _, l := range DependencyGraphLimits {
		var v int64
		switch def := dependencyGraphLimitDefaults[l.Name].(type) {
		case int:
			v = sec.Key(l.Key).MustInt64(int64(def))
		case int64:
			v = sec.Key(l.Key).MustInt64(def)
		case time.Duration:
			d, err := sec.Key(l.Key).MustDuration(def)
			if err != nil {
				return err
			}
			v = int64(d / time.Second)
		}
		if err := l.Check(v); err != nil {
			clamped := min(max(v, l.Min), l.Max)
			log.Warn("[dependency_graph] %s %d is out of bounds (%d to %d), using %d", l.Key, v, l.Min, l.Max, clamped)
			v = clamped
		}
		l.set(&DependencyGraph, v)
	}
	return loadOSVMirrorFrom(sec)
}

// MinUpdateInterval and MaxUpdateInterval bound [dependency_graph] UPDATE_INTERVAL.
const (
	MinUpdateInterval = time.Hour
	MaxUpdateInterval = 30 * 24 * time.Hour
)

// ErrOSVMirrorURLUserInfo is a mirror URL with user info, a query or a fragment.
var ErrOSVMirrorURLUserInfo = errors.New("must have no user info, query or fragment")

// CheckOSVMirrorURL checks a mirror URL and returns it without a trailing slash. The message never holds the URL.
func CheckOSVMirrorURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	switch {
	case err != nil:
		return "", errors.New("is not a valid URL")
	case u.Scheme != "https" && u.Scheme != "http", u.Hostname() == "":
		return "", errors.New("must be an http(s) URL with a host")
	case u.User != nil, u.RawQuery != "", u.Fragment != "", u.ForceQuery:
		return "", ErrOSVMirrorURLUserInfo
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// OSVMirrorOrigin is the scheme and host (with port) of a mirror URL, lower case: the credential goes only there.
func OSVMirrorOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func loadOSVMirrorFrom(sec ConfigSection) (err error) {
	g := &DependencyGraph
	g.OSVMirrorURL = DefaultOSVMirrorURL
	if sec.HasKey("OSV_MIRROR_URL") {
		g.OSVMirrorURL = strings.TrimSpace(sec.Key("OSV_MIRROR_URL").String())
	}
	if g.OSVMirrorURL != "" {
		if g.OSVMirrorURL, err = CheckOSVMirrorURL(g.OSVMirrorURL); errors.Is(err, ErrOSVMirrorURLUserInfo) {
			return fmt.Errorf("[dependency_graph] OSV_MIRROR_URL %w (put a credential in OSV_MIRROR_TOKEN or OSV_MIRROR_TOKEN_URI)", err)
		} else if err != nil {
			return fmt.Errorf("[dependency_graph] OSV_MIRROR_URL %w", err)
		}
		if strings.HasPrefix(g.OSVMirrorURL, "http://") {
			log.Warn("[dependency_graph] OSV_MIRROR_URL uses http: the advisory data is not protected in transit")
		}
	}
	g.OSVMirrorUser = strings.TrimSpace(sec.Key("OSV_MIRROR_USER").String())
	if err := CheckOSVMirrorUser(g.OSVMirrorUser); err != nil {
		return fmt.Errorf("[dependency_graph] OSV_MIRROR_USER %w", err)
	}
	g.OSVMirrorHosts = strings.TrimSpace(sec.Key("OSV_MIRROR_ALLOWED_HOSTS").String())
	if err := CheckHostList(g.OSVMirrorHosts); err != nil {
		return fmt.Errorf("[dependency_graph] OSV_MIRROR_ALLOWED_HOSTS: %w", err)
	}
	if g.OSVMirrorToken, err = loadOSVMirrorToken(sec); err != nil {
		return err
	}
	if g.OSVMirrorUser != "" && g.OSVMirrorToken == "" {
		return errors.New("[dependency_graph] OSV_MIRROR_USER is set without OSV_MIRROR_TOKEN or OSV_MIRROR_TOKEN_URI")
	}
	if g.OSVMirrorToken != "" {
		log.RegisterSecret(g.OSVMirrorToken)
		if strings.HasPrefix(g.OSVMirrorURL, "http://") {
			log.Warn("[dependency_graph] OSV_MIRROR_TOKEN is sent over http: it is not protected in transit")
		}
	}
	return nil
}

// DependencyGraphState is stored as JSON in the "dependency_graph.enabled" system setting. An empty Mode means the
// app.ini default ([dependency_graph] ENABLED); once the switch is saved in Site administration, the stored value wins.
type DependencyGraphState struct {
	Mode        string `json:"mode"` // "on", "off" or "" (app.ini)
	UpdatedBy   int64  `json:"updated_by"`
	UpdatedUnix int64  `json:"updated_unix"`
}

// Enabled is the site switch in force. A stored value that can't be parsed or isn't known reads as off.
func (s DependencyGraphState) Enabled() bool {
	switch s.Mode {
	case "":
		return DependencyGraph.Enabled
	case "on":
		return true
	}
	return false
}

// loadOSVMirrorToken reads OSV_MIRROR_TOKEN or OSV_MIRROR_TOKEN_URI (a file: URI). It does not use loadSecret, which
// exits the process and whose errors could echo a token pasted into the URI by mistake.
func loadOSVMirrorToken(sec ConfigSection) (string, error) {
	token, uri := sec.Key("OSV_MIRROR_TOKEN").String(), sec.Key("OSV_MIRROR_TOKEN_URI").String()
	switch {
	case token != "" && uri != "":
		return "", errors.New("[dependency_graph] OSV_MIRROR_TOKEN and OSV_MIRROR_TOKEN_URI are both set, use only one")
	case uri == "":
		token = strings.TrimSpace(token)
	case !strings.HasPrefix(uri, "file:"):
		return "", errors.New("[dependency_graph] OSV_MIRROR_TOKEN_URI must be a file: URI")
	default:
		var err error
		if token, err = loadSecretFromURI(uri); err != nil {
			return "", fmt.Errorf("[dependency_graph] OSV_MIRROR_TOKEN_URI: %w", err)
		}
	}
	if token != "" {
		if err := CheckOSVMirrorToken(token); err != nil {
			return "", fmt.Errorf("[dependency_graph] the OSV mirror token %w", err)
		}
	}
	return token, nil
}

// CheckOSVMirrorToken accepts 8 to 1024 characters without CR, LF or NUL (every registered secret is redacted from
// the logs wherever it occurs, so a short one would blank out ordinary text). The message never holds the token.
func CheckOSVMirrorToken(token string) error {
	if len(token) < 8 || len(token) > 1024 || strings.ContainsAny(token, "\r\n\x00") {
		return errors.New("must be 8 to 1024 characters")
	}
	return nil
}

// CheckOSVMirrorUser accepts a Basic auth user name: at most 256 bytes, no colon, no control character.
func CheckOSVMirrorUser(user string) error {
	if len(user) > 256 || strings.ContainsRune(user, ':') || strings.ContainsFunc(user, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return errors.New("must be at most 256 characters without a colon")
	}
	return nil
}

// CheckHostList refuses an entry that is no builtin (external, private, loopback), CIDR, address or host name pattern.
func CheckHostList(list string) error {
	for entry := range strings.SplitSeq(list, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return fmt.Errorf("%q is not a CIDR network", entry)
			}
			continue
		}
		for _, r := range entry {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("*?.-_:[]", r)) {
				return fmt.Errorf("%q is not a host name, address, CIDR network or one of external, private, loopback", entry)
			}
		}
	}
	return nil
}

// The sources of the advisory database in Site administration.
const (
	OSVSourcePublic = "public" // DefaultOSVMirrorURL
	OSVSourceMirror = "mirror" // a mirror or proxy (MirrorURL)
	OSVSourceNone   = "none"   // offline: nothing is downloaded
)

// The sign-in to the mirror in Site administration.
const (
	OSVSignInNone  = "none"
	OSVSignInToken = "token" // Authorization: Bearer
	OSVSignInBasic = "basic" // the token as the password of User
)

// DependencyGraphAppSource is the source app.ini's OSV_MIRROR_URL stands for.
func DependencyGraphAppSource() string {
	switch DependencyGraph.OSVMirrorURL {
	case "":
		return OSVSourceNone
	case DefaultOSVMirrorURL:
		return OSVSourcePublic
	}
	return OSVSourceMirror
}

// DependencyGraphAppSignIn is the sign-in app.ini's OSV_MIRROR_TOKEN and OSV_MIRROR_USER stand for.
func DependencyGraphAppSignIn() string {
	switch {
	case DependencyGraph.OSVMirrorToken == "":
		return OSVSignInNone
	case DependencyGraph.OSVMirrorUser != "":
		return OSVSignInBasic
	}
	return OSVSignInToken
}

// DependencyGraphConfig is stored as JSON in the "dependency_graph.config" system setting: the dependency graph
// settings saved in Site administration (the site switch is DependencyGraphState). Every field is optional: what isn't
// stored is the app.ini value. Invalid marks a stored value that can't be parsed.
type DependencyGraphConfig struct {
	Invalid bool `json:"-"`

	Limits    map[string]int64 `json:"limits,omitempty"`     // by DependencyGraphLimit.Name; seconds for a duration
	Source    string           `json:"source,omitempty"`     // OSVSource*
	MirrorURL string           `json:"mirror_url,omitempty"` // with OSVSourceMirror
	SignIn    string           `json:"sign_in,omitempty"`    // OSVSignIn*
	User      string           `json:"user,omitempty"`       // with OSVSignInBasic
	// TokenEnc is the token encrypted with SecretKey: nil = the app.ini token, "" = none. It is sent only to
	// TokenOrigin, the scheme and host it was entered for, so a changed URL never receives it.
	TokenEnc    *string `json:"token_enc,omitempty"`
	TokenOrigin string  `json:"token_origin,omitempty"`
	Hosts       *string `json:"allowed_hosts,omitempty"`

	UpdatedBy   int64 `json:"updated_by,omitempty"`
	UpdatedUnix int64 `json:"updated_unix,omitempty"`
}

// mergedDependencyGraph caches DependencyGraphSettings: Merge (its logs, the token's decryption) runs once per
// settings revision, app.ini values and secret key.
var mergedDependencyGraph struct {
	sync.Mutex
	revision  int
	base      DependencyGraphOptions
	secretKey string
	merged    DependencyGraphOptions
	ok        bool
}

// DependencyGraphSettings is the dependency graph configuration in force: the values saved in Site administration
// over app.ini. Read it before building a query, never while one is being built.
func DependencyGraphSettings(ctx context.Context) DependencyGraphOptions {
	// the revision first: a value read after it is never older than its key (a newer one is merged again next time)
	revision := config.GetDynGetter().GetRevision(ctx)
	stored := Config().DependencyGraphConfig.Value(ctx) // outside the lock: it may query the database
	m := &mergedDependencyGraph
	m.Lock()
	defer m.Unlock()
	if m.ok && m.revision == revision && m.base == DependencyGraph && m.secretKey == SecretKey {
		return m.merged
	}
	m.revision, m.base, m.secretKey, m.merged, m.ok = revision, DependencyGraph, SecretKey, stored.Merge(), true
	return m.merged
}

// Merge applies the stored values over app.ini. A stored value that can't be used is logged and its app.ini value is
// used, except for the mirror's host list and token: then the mirror is off (MirrorConfigInvalid), never more open.
func (c DependencyGraphConfig) Merge() DependencyGraphOptions {
	o := DependencyGraph
	if c.Invalid {
		o.MirrorConfigInvalid = true
		return o
	}
	for name, v := range c.Limits {
		l, ok := DependencyGraphLimitByName(name)
		if !ok {
			log.Error("dependency_graph.config: unknown setting %q is ignored", name)
			continue
		}
		if err := l.Check(v); err != nil {
			log.Error("dependency_graph.config: %v, using the app.ini value", err)
			continue
		}
		l.set(&o, v)
	}

	token, user, tokenOrigin := o.OSVMirrorToken, o.OSVMirrorUser, OSVMirrorOrigin(o.OSVMirrorURL)
	switch c.Source {
	case "":
	case OSVSourcePublic:
		o.OSVMirrorURL = DefaultOSVMirrorURL
	case OSVSourceNone:
		o.OSVMirrorURL = ""
	case OSVSourceMirror:
		if u, err := CheckOSVMirrorURL(c.MirrorURL); err != nil {
			// never another source than the one chosen: the mirror may be there to keep the server off the internet
			log.Error("dependency_graph.config: the mirror URL %v, the mirror is off", err)
			o.MirrorConfigInvalid = true
		} else {
			o.OSVMirrorURLFromPage = u != o.OSVMirrorURL
			o.OSVMirrorURL = u
		}
	default:
		log.Error("dependency_graph.config: unknown source %q, using the app.ini value", c.Source)
	}
	if c.TokenEnc != nil {
		token, tokenOrigin = "", c.TokenOrigin
		if *c.TokenEnc != "" {
			t, err := secret.DecryptSecret(SecretKey, *c.TokenEnc)
			if err == nil {
				err = CheckOSVMirrorToken(t)
			}
			if err != nil {
				log.Error("dependency_graph.config: the mirror token can't be read, the mirror is off")
				o.MirrorConfigInvalid = true
			} else {
				log.RegisterSecret(t)
				token = t
			}
		}
	}
	switch c.SignIn {
	case "":
	case OSVSignInNone:
		token, user = "", ""
	case OSVSignInToken:
		user = ""
	case OSVSignInBasic:
		user = c.User
		if user == "" || CheckOSVMirrorUser(user) != nil {
			log.Error("dependency_graph.config: the mirror user can't be used, the mirror is off")
			o.MirrorConfigInvalid = true
		}
	default:
		log.Error("dependency_graph.config: unknown sign-in %q, the mirror is off", c.SignIn)
		o.MirrorConfigInvalid = true
	}
	if c.Source == OSVSourcePublic || c.Source == OSVSourceNone || tokenOrigin != OSVMirrorOrigin(o.OSVMirrorURL) {
		token = "" // a token goes only to the scheme and host it was given for
	}
	if token == "" {
		user = ""
	}
	o.OSVMirrorToken, o.OSVMirrorUser = token, user
	if c.Hosts != nil && strings.TrimSpace(*c.Hosts) != "" { // a stored empty list is the app.ini value
		if err := CheckPageHostList(*c.Hosts); err != nil {
			log.Error("dependency_graph.config: the allowed hosts can't be used, the mirror is off")
			o.MirrorConfigInvalid = true
		} else {
			o.OSVMirrorHosts, o.OSVMirrorHostsFromPage = strings.TrimSpace(*c.Hosts), true
		}
	}
	return o
}

// CheckPageHostList checks a host list saved in Site administration, which may only name what to download from:
// exact host names (no wildcard, not localhost), single IP addresses (not loopback, link-local or unspecified),
// networks no wider than /16 (IPv4) or /48 (IPv6), and "external". An IPv4-mapped network (::ffff:a.b.c.d/n) counts
// as IPv4, and nothing may touch the internal addresses (mirrorInternalNets) or the IPv6 forms of IPv4 (NAT64, 6to4,
// Teredo). The wider app.ini syntax (private, loopback, patterns) stays in OSV_MIRROR_ALLOWED_HOSTS. A network may
// still contain loopback or this machine's addresses: the mirror's dial check blocks those (MirrorBlockedHosts).
func CheckPageHostList(list string) error {
	for entry := range strings.SplitSeq(list, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		var n *net.IPNet
		switch {
		case entry == "", entry == "external":
			continue
		case strings.Contains(entry, "/"):
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return fmt.Errorf("%q is not a network", entry)
			}
			n = ipv4Form(ipNet)
			ones, bits := n.Mask.Size()
			if bits == 32 && ones < 16 || bits == 128 && ones < 48 {
				return fmt.Errorf("%q is wider than /16 (IPv4) or /48 (IPv6)", entry)
			}
		case net.ParseIP(strings.Trim(entry, "[]")) != nil:
			ip := net.ParseIP(strings.Trim(entry, "[]"))
			if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				return fmt.Errorf("%q is a loopback, link-local or unspecified address", entry)
			}
			n = ipv4Form(&net.IPNet{IP: ip, Mask: net.CIDRMask(8*len(ip), 8*len(ip))})
		default:
			if entry == "private" || entry == "loopback" || !isHostName(entry) || IsLoopbackHost(entry) {
				return fmt.Errorf("%q is not a host name, address, network or external", entry)
			}
			continue
		}
		for _, internal := range mirrorInternalNets {
			if _, in, _ := net.ParseCIDR(internal); netsOverlap(n, ipv4Form(in)) {
				return fmt.Errorf("%q is or contains an internal address (link-local, cloud metadata or unspecified)", entry)
			}
		}
		if len(n.IP) == net.IPv6len {
			for _, embedded := range ipv6FormsOfIPv4 {
				if _, in, _ := net.ParseCIDR(embedded); netsOverlap(n, in) {
					return fmt.Errorf("%q is an IPv6 form of IPv4 addresses (NAT64, 6to4, Teredo or IPv4-mapped), name the IPv4 address or network", entry)
				}
			}
		}
	}
	return nil
}

// mirrorInternalNets are the internal addresses a host list saved in Site administration never names or reaches:
// link-local (169.254.169.254 is the metadata service of most clouds), the unspecified addresses, and the cloud
// metadata services outside link-local: AWS over IPv6 (fd00:ec2::254), Alibaba Cloud (100.100.100.200) and the
// Azure WireServer (168.63.129.16).
var mirrorInternalNets = []string{
	"169.254.0.0/16", "fe80::/10", "0.0.0.0/8", "::/128",
	"fd00:ec2::254/128", "100.100.100.200/32", "168.63.129.16/32",
}

// ipv6FormsOfIPv4 are the IPv6 networks that stand for IPv4 addresses: IPv4-mapped (an entry inside it is read as
// IPv4 by ipv4Form, so only a wider one meets it), NAT64 (RFC 6052, RFC 8215), 6to4 and Teredo.
var ipv6FormsOfIPv4 = []string{"::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32"}

// ipv4Form returns an IPv4-mapped network (::ffff:a.b.c.d/n, n >= 96) as the IPv4 network it stands for, which is
// also how net.IPNet.Contains (and so the dial check) reads it; any other network is returned as it is.
func ipv4Form(n *net.IPNet) *net.IPNet {
	ones, bits := n.Mask.Size()
	if ip4 := n.IP.To4(); ip4 != nil && bits == 128 && ones >= 96 {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(ones-96, 32)}
	}
	return n
}

// netsOverlap reports whether two networks share an address (networks of one family either nest or are apart).
func netsOverlap(a, b *net.IPNet) bool {
	return len(a.IP) == len(b.IP) && (a.Contains(b.IP) || b.Contains(a.IP))
}

// isHostName accepts an exact DNS name: labels of letters, digits and hyphens.
func isHostName(s string) bool {
	if len(s) > 253 {
		return false
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(s, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// MirrorBlockedHosts is what the mirror never reaches when its URL or host list was saved in Site administration,
// whatever the list names: loopback, the internal addresses (mirrorInternalNets) and the addresses this instance's
// HTTP and built-in SSH servers listen on (every address of this machine when one listens on all of them).
func MirrorBlockedHosts() string {
	blocked := append([]string{"loopback"}, mirrorInternalNets...)
	allAddrs := false
	listen := []string{HTTPAddr}
	if SSH.StartBuiltinServer {
		listen = append(listen, SSH.ListenHost)
	}
	for _, addr := range listen {
		if ip := net.ParseIP(addr); ip != nil && !ip.IsUnspecified() {
			blocked = append(blocked, ip.String())
		} else {
			allAddrs = true // a name or an unspecified address: assume every address
		}
	}
	if addrs, err := net.InterfaceAddrs(); allAddrs && err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				blocked = append(blocked, n.IP.String())
			}
		}
	}
	return strings.Join(blocked, ",")
}

// IsInstanceHost reports whether host (and port: "" means any port) names this instance: the public names (the
// host of AppURL, the domain and the SSH domain) on any port, since a proxy may serve them on other ports too, the
// host and port of LocalURL, the HTTP address or a loopback or unspecified address on the HTTP port, and the SSH
// listen address on the SSH port (any case, a trailing dot and an IPv6 zone ignored, ports compared as numbers).
// Log shipping (with the endpoint's port) and the advisory mirror (any port) refuse it.
func IsInstanceHost(host, port string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return false
	}
	type hostPort struct{ host, port string }
	self := []hostPort{{HTTPAddr, HTTPPort}, {SSH.Domain, ""}, {Domain, ""}}
	if SSH.StartBuiltinServer {
		self = append(self, hostPort{SSH.ListenHost, strconv.Itoa(SSH.ListenPort)})
	}
	if u, err := url.Parse(AppURL); err == nil {
		self = append(self, hostPort{u.Hostname(), ""})
	}
	if u, err := url.Parse(LocalURL); err == nil {
		self = append(self, hostPort{u.Hostname(), URLPort(u)})
	}
	if IsLoopbackHost(host) {
		self = append(self, hostPort{host, HTTPPort})
		if SSH.StartBuiltinServer {
			self = append(self, hostPort{host, strconv.Itoa(SSH.ListenPort)})
		}
	}
	for _, s := range self {
		if h := strings.TrimSuffix(strings.Trim(s.host, "[]"), "."); h != "" && strings.EqualFold(h, host) && (port == "" || s.port == "" || samePort(port, s.port)) {
			return true
		}
	}
	return false
}

// samePort compares two ports as numbers, so "03000" is 3000.
func samePort(a, b string) bool {
	x, errA := strconv.Atoi(a)
	y, errB := strconv.Atoi(b)
	return errA == nil && errB == nil && x == y
}

// URLPort is the port of u, or the default port of its scheme (http, https).
func URLPort(u *url.URL) string {
	if p := u.Port(); p != "" || u.Scheme != "http" && u.Scheme != "https" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

// IsLoopbackHost reports whether host is "localhost" (or a name under it), a loopback or unspecified address, or a
// numeric form the C resolver reads as an address (127.1, 2130706433, 0177.0.0.1, 0x7f000001): no real name looks
// like one, so it is refused as if it were loopback.
func IsLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return isNumericHost(host)
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}

// isNumericHost reports whether every label of host is decimal or 0x hexadecimal: the inet_aton forms.
func isNumericHost(host string) bool {
	for label := range strings.SplitSeq(host, ".") {
		if hex, ok := strings.CutPrefix(label, "0x"); ok {
			if strings.TrimLeft(hex, "0123456789abcdef") != "" {
				return false
			}
		} else if label == "" || strings.TrimLeft(label, "0123456789") != "" {
			return false
		}
	}
	return true
}
