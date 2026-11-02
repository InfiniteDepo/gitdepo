// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package dependency reads the dependencies a repository declares in its manifests and lock files. The parsers are
// pure Go: nothing is executed, downloaded or read from outside the manifest's own bytes (the callers hand over the
// few sibling files a format needs).
package dependency

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Ecosystems, named as OSV names them. This is a closed list: nothing else is stored.
const (
	Go        = "Go"
	NPM       = "npm"
	PyPI      = "PyPI"
	Maven     = "Maven"
	NuGet     = "NuGet"
	Cargo     = "crates.io"
	RubyGems  = "RubyGems"
	Packagist = "Packagist"
)

// Ecosystems lists every ecosystem.
var Ecosystems = []string{Go, NPM, PyPI, Maven, NuGet, Cargo, RubyGems, Packagist}

// IsEcosystem reports whether e is one of Ecosystems.
func IsEcosystem(e string) bool {
	return slices.Contains(Ecosystems, e)
}

// Limits of one stored row, in bytes.
const (
	MaxNameLen    = 512
	MaxVersionLen = 256
	MaxLicenseLen = 256
	MaxPathLen    = 1024

	// MaxSmallManifestSize is the size limit of the formats that are small by nature (go.mod, requirements.txt,
	// pom.xml, project files, Gemfile.lock); lock files may be as large as the configured limit.
	MaxSmallManifestSize = 1 << 20

	maxLineLen = 64 << 10
	maxXMLDeep = 256
)

// ErrParse is the error of a manifest that can't be read. The text of the wrapped error may hold bytes of the
// manifest, so callers store and show only the fixed code.
var ErrParse = errors.New("dependency: cannot parse manifest")

// Dependency is one package a manifest declares or locks.
type Dependency struct {
	Ecosystem   string
	Name        string
	Version     string // "" if the manifest doesn't fix it
	Requirement string // the range the manifest declares when it doesn't fix the version ("^4.18.0"), else ""
	License     string // as the manifest states it, "" if unknown
	Direct      bool   // declared by the project itself, not only needed by another dependency
}

// Finder returns the content of the file name next to the manifest, or with up, in the nearest directory above it
// (the manifest's own directory first). It returns nil if there is none. The caller limits the size.
type Finder func(name string, up bool) []byte

// Format is a manifest format.
type Format struct {
	Ecosystem string
	// Small formats are limited to MaxSmallManifestSize.
	Small bool
	// Unpinned formats are manifests read only when no lock file read by the scan covers them (see Covered): they
	// list the direct dependencies with the ranges they declare, no versions.
	Unpinned bool
	Locks    []string
	cover    coverRule
	match    func(base string) bool
	parse    func(s *sink, data []byte, find Finder) error
}

var formats []*Format

func register(f *Format) { formats = append(formats, f) }

// FormatFor returns the format of a file with the given base name, or nil. Names are matched exactly (the project
// files by their suffix), as git stores them.
func FormatFor(base string) *Format {
	for _, f := range formats {
		if f.match(base) {
			return f
		}
	}
	return nil
}

// FormatForPath is FormatFor for a path in the repository: it also knows the Django layout, where any *.txt file
// directly inside a directory named requirements is a requirements file.
func FormatForPath(p string) *Format {
	base := path.Base(p)
	if f := FormatFor(base); f != nil {
		return f
	}
	if strings.HasSuffix(base, ".txt") && path.Base(path.Dir(p)) == "requirements" {
		return FormatFor("requirements.txt")
	}
	return nil
}

// ErrTooManyDependencies is returned when a manifest holds more rows than the caller allows. It stops the parser at
// once: the work and the memory of a parse are bounded by the limit, not by the shape of the input.
var ErrTooManyDependencies = errors.New("dependency: too many dependencies")

// ErrTooManyEntries is returned when a manifest holds so many intermediate entries that reading it would cost more
// than the allowed rows do, though it may keep few rows. Only that manifest is given up.
var ErrTooManyEntries = errors.New("dependency: too many entries")

// isLimit reports an error that stops a parse because a limit was reached.
func isLimit(err error) bool {
	return errors.Is(err, ErrTooManyDependencies) || errors.Is(err, ErrTooManyEntries)
}

// DefaultMaxDependencies is the row limit of Parse.
const DefaultMaxDependencies = 50000

// entryFactor is how many intermediate entries (map keys, lockfile entries, lines with a key) a parse may keep per
// allowed row.
const entryFactor = 4

// sink receives the rows of a parse. emit counts the rows, entry counts everything else a parser keeps in memory;
// emit fails with ErrTooManyDependencies and entry with ErrTooManyEntries past their limit, and both look at the context now and then.
type sink struct {
	ctx        context.Context
	maxRows    int
	maxEntries int
	rows       []Dependency
	index      map[[2]string]int // name, version -> position in rows
	entries    int
	ticks      int
	info       Info // what a lock file covers, what a manifest is, what was not read
}

func newSink(ctx context.Context, maxRows int) *sink {
	return &sink{ctx: ctx, maxRows: maxRows, maxEntries: maxRows * entryFactor, index: map[[2]string]int{}}
}

func (s *sink) tick() error {
	if s.ticks++; s.ticks&255 == 0 {
		return s.ctx.Err()
	}
	return nil
}

// emit adds a row; a package listed again (same name and version) is merged into the first row.
func (s *sink) emit(d Dependency) error {
	k := [2]string{d.Name, d.Version}
	if i, ok := s.index[k]; ok {
		s.rows[i].Direct = s.rows[i].Direct || d.Direct
		if s.rows[i].License == "" {
			s.rows[i].License = d.License
		}
		return s.tick()
	}
	if len(s.rows) >= s.maxRows {
		return ErrTooManyDependencies
	}
	s.index[k] = len(s.rows)
	s.rows = append(s.rows, d)
	return s.tick()
}

// entry accounts for one intermediate entry a parser is about to keep.
func (s *sink) entry() error {
	if s.entries++; s.entries > s.maxEntries {
		return ErrTooManyEntries
	}
	return s.tick()
}

// Info is what a parse learns besides the rows: what a lock file covers (see Covers) and what a manifest without a
// lock file is.
type Info struct {
	// a lock file: the directories (relative to the lock's, "." for its own) of the projects it was resolved for,
	// and glob patterns of more (a yarn v1 root's package.json workspaces); nil for the lock files that cover only
	// the manifest next to them
	Dirs, Globs []string
	// Cargo.lock: the names of the packages of the project itself (the root and the workspace members); Globs and
	// Excludes are then the workspace.members and workspace.exclude of the Cargo.toml next to it (also a
	// Cargo.toml's own)
	Members  []string
	Excludes []string
	// Cargo.toml: the package's name ("" for a virtual workspace) and whether it is a workspace root itself
	Name         string
	OwnWorkspace bool
	// lines of the manifest that name a dependency but could not be read (a Gemfile's gem calls that are not plain)
	Unread int
}

// Result is what ParseFull returns.
type Result struct {
	Deps []Dependency
	Info Info
}

// ParseFull reads a manifest and returns at most maxRows rows, or ErrTooManyDependencies, with the Info of the
// parse. A panic of a parser is an ErrParse, and every row is validated: names, versions and licenses are cut of
// control characters and bidirectional marks, a row with an empty or too long value is dropped, and a package listed
// twice in one manifest is one row.
func (f *Format) ParseFull(ctx context.Context, data []byte, find Finder, maxRows int) (res *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("%w: panic", ErrParse)
		}
	}()
	if find == nil {
		find = func(string, bool) []byte { return nil }
	}
	s := newSink(ctx, max(maxRows, 0))
	err = f.parse(s, data, find)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return &Result{Deps: validate(f.Ecosystem, s.rows), Info: s.info}, nil
}

func clean(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
}

func validate(eco string, in []Dependency) []Dependency {
	out := make([]Dependency, 0, len(in))
	seen := map[[3]string]int{}
	for _, d := range in {
		d.Ecosystem = eco
		if len(d.Name) > MaxNameLen*2 || len(d.Version) > MaxVersionLen*2 || len(d.License) > MaxLicenseLen*2 {
			continue // not worth cleaning
		}
		if len(d.Requirement) > MaxVersionLen*2 {
			d.Requirement = ""
		}
		d.Name, d.Version, d.License, d.Requirement = clean(d.Name), clean(d.Version), clean(d.License), clean(d.Requirement)
		if d.Name == "" || len(d.Name) > MaxNameLen || len(d.Version) > MaxVersionLen {
			continue
		}
		if len(d.License) > MaxLicenseLen {
			d.License = ""
		}
		if len(d.Requirement) > MaxVersionLen || d.Version != "" {
			d.Requirement = "" // a pinned row needs none
		}
		k := [3]string{eco, d.Name, d.Version}
		if i, ok := seen[k]; ok {
			out[i].Direct = out[i].Direct || d.Direct
			if out[i].License == "" {
				out[i].License = d.License
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, d)
	}
	return out
}

// lineScanner reads lines of at most maxLineLen bytes and stops (Err reports why) once the context is done, so a
// scan that timed out doesn't finish a long file.
type lineScanner struct {
	*bufio.Scanner
	s   *sink
	err error // the byte pre-pass refused the file
	n   int   // the number of the current line
}

// newScanner reads the lines of a text manifest after the byte pre-pass: a leading UTF-8 byte order mark is removed
// (as js-yaml, yarn and pip do), and a carriage return that doesn't end a CRLF line is refused, since YAML, yarn and
// TOML read it as a line break that bufio.ScanLines doesn't see.
func newScanner(s *sink, data []byte) *lineScanner {
	data, err := prepass(data, false)
	return scannerOf(s, data, err)
}

// newYAMLScanner is newScanner for the YAML lock files (pnpm, yarn): it also refuses tabs, NUL and every other
// control character, a byte order mark after the start, and invalid UTF-8, none of which pnpm or yarn writes.
func newYAMLScanner(s *sink, data []byte) *lineScanner {
	data, err := prepass(data, true)
	return scannerOf(s, data, err)
}

func scannerOf(s *sink, data []byte, err error) *lineScanner {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxLineLen)
	return &lineScanner{Scanner: sc, s: s, err: err}
}

var utf8BOM = []byte("\xef\xbb\xbf")

// prepass is the check of a text manifest's bytes before any line logic (see newScanner and newYAMLScanner).
func prepass(data []byte, strict bool) ([]byte, error) {
	data = bytes.TrimPrefix(data, utf8BOM)
	for rest := data; ; {
		i := bytes.IndexByte(rest, '\r')
		if i < 0 {
			break
		}
		if i+1 >= len(rest) || rest[i+1] != '\n' {
			return nil, parseErr("carriage return")
		}
		rest = rest[i+2:]
	}
	if !strict {
		return data, nil
	}
	if !utf8.Valid(data) {
		return nil, parseErr("invalid UTF-8")
	}
	for _, r := range string(data) { // every \r is part of a CRLF here
		if (r < 0x20 && r != '\n' && r != '\r') || (r >= 0x7f && r <= 0x9f) || r == 0xfeff || r == 0xfffe || r == 0xffff {
			return nil, parseErr("control character")
		}
	}
	return data, nil
}

func (l *lineScanner) Scan() bool {
	if l.err != nil || l.s.tick() != nil {
		return false
	}
	l.n++
	return l.Scanner.Scan()
}

func (l *lineScanner) Err() error {
	if err := l.s.ctx.Err(); err != nil {
		return err
	}
	if l.err != nil {
		return l.err
	}
	return l.Scanner.Err()
}

// scanErr turns the error of a line scan into the parse error, keeping the context and limit errors as they are.
func scanErr(err error, format string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isLimit(err) {
		return err
	}
	return parseErr("%s", format)
}

func parseErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrParse, fmt.Sprintf(format, a...))
}

// PURL builds the package URL of a dependency (https://github.com/package-url/purl-spec) from its stored values,
// never from text of a manifest. It returns "" for an unknown ecosystem or an empty name.
func PURL(eco, name, version string) string {
	var typ, ns, n string
	switch eco {
	case Go:
		typ = "golang"
		ns, n = splitLast(strings.ToLower(name), "/")
	case NPM:
		typ = "npm"
		ns, n = splitLast(strings.ToLower(name), "/")
	case PyPI:
		typ = "pypi"
		n = strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case Maven:
		typ = "maven"
		ns, n, _ = strings.Cut(name, ":")
		if n == "" {
			ns, n = "", ns
		}
	case NuGet:
		typ, n = "nuget", name
	case Cargo:
		typ, n = "cargo", name
	case RubyGems:
		typ, n = "gem", name
	case Packagist:
		typ = "composer"
		ns, n = splitLast(strings.ToLower(name), "/")
	default:
		return ""
	}
	if n == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:" + typ + "/")
	if ns != "" {
		for seg := range strings.SplitSeq(ns, "/") {
			b.WriteString(purlEscape(seg) + "/")
		}
	}
	b.WriteString(purlEscape(n))
	if version != "" {
		b.WriteString("@" + purlEscape(version))
	}
	return b.String()
}

func splitLast(s, sep string) (string, string) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):]
	}
	return "", s
}

// purlEscape percent-encodes everything but the unreserved characters.
func purlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// SafeText cuts a string for display or storage as validate does.
func SafeText(s string) string { return clean(s) }

// ValidPath reports whether p can be stored as the path of a manifest.
func ValidPath(p string) bool {
	return p != "" && len(p) <= MaxPathLen && utf8.ValidString(p) && clean(p) == p && path.Clean(p) == p
}

// cmpOr returns err if it is set, else other.
func cmpOr(err, other error) error {
	if err != nil {
		return err
	}
	return other
}

// maxHelperKeys is the number of names a helper file (a package.json, composer.json, Directory.Packages.props) may
// contribute; real ones have a few hundred. A larger one counts as absent: the manifest's packages are read, but none
// is marked direct (or gets a central version) through it.
const maxHelperKeys = 10000

// HelperCache bounds the work of the helper files (the package.json next to a lock file, ...) of one scan. It keeps
// what is parsed from a file by parser and blob, so a file shared by many manifests is parsed once: the scan hands
// out one slice per blob and registers it with Keep, which also charges its size to the memory budget the parsed
// results share. And it counts the bytes of helper files parsed (each parse not served from the cache) against a
// parse budget; once that is spent, further helpers count as absent, however many manifests ask for them.
type HelperCache struct {
	mu        sync.Mutex
	left      int64 // memory: the kept files and the results parsed from them
	parseLeft int64 // the bytes of helper files that may still be parsed
	kept      map[*byte]bool
	parsed    map[helperKey]any
}

type helperKey struct {
	parser string
	data   *byte // the blob, by the slice the scan keeps of it
}

// NewHelperCache returns a cache that keeps at most budget bytes (of files and parsed results together) and parses
// at most parseBudget bytes of helper files.
func NewHelperCache(budget, parseBudget int64) *HelperCache {
	return &HelperCache{left: budget, parseLeft: parseBudget, kept: map[*byte]bool{}, parsed: map[helperKey]any{}}
}

// Keep reserves the size of a file the caller keeps and hands out again for the same blob, and reports whether it
// fit; only what is parsed from a kept file is cached.
func (h *HelperCache) Keep(data []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if int64(len(data)) > h.left {
		return false
	}
	h.left -= int64(len(data))
	if len(data) > 0 {
		h.kept[&data[0]] = true
	}
	return true
}

// CanParse reports whether a helper file of n bytes may still be parsed (else it counts as absent, and the caller
// need not read it).
func (h *HelperCache) CanParse(n int64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return n <= h.parseLeft
}

type helperCacheKey struct{}

// WithHelperCache returns a context whose parses use h.
func WithHelperCache(ctx context.Context, h *HelperCache) context.Context {
	return context.WithValue(ctx, helperCacheKey{}, h)
}

// helperParsed returns parse()'s result (and its memory cost) for the helper file data, read by the named parser:
// from the cache of ctx if it is there, else parsed (charged to the parse budget) and kept when data is a kept file
// and the memory budget allows. ok is false when the parse budget is spent: the helper then counts as absent.
// Without a cache it just parses.
func helperParsed[T any](ctx context.Context, parser string, data []byte, parse func() (T, int64)) (out T, ok bool) {
	h, _ := ctx.Value(helperCacheKey{}).(*HelperCache)
	if h == nil || len(data) == 0 {
		out, _ = parse()
		return out, true
	}
	key := helperKey{parser, &data[0]}
	h.mu.Lock()
	if v, found := h.parsed[key]; found {
		h.mu.Unlock()
		return v.(T), true
	}
	if int64(len(data)) > h.parseLeft {
		h.mu.Unlock()
		return out, false
	}
	h.parseLeft -= int64(len(data))
	kept := h.kept[key.data]
	h.mu.Unlock()
	out, cost := parse()
	h.mu.Lock()
	defer h.mu.Unlock()
	if cost += 64; kept && cost <= h.left {
		h.left -= cost
		h.parsed[key] = out
	}
	return out, true
}
