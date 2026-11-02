// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A small TOML reader for the manifests without a lock file (Cargo.toml, pyproject.toml). It reads the whole
// statement structure (table headers and key = value lines, with strings, multi-line strings, arrays and inline
// tables that may span lines), so a section header inside a string or an array is never taken for one; it doesn't
// build a document. Anything that isn't TOML as these files use it is a parse error, so a reader that can't tell
// where a value ends fails closed instead of missing or inventing dependencies.

// maxTOMLDepth bounds the nesting of arrays and inline tables.
const maxTOMLDepth = 32

// tomlStmt is one statement: a table header (Header set, Key the table's path) or a key = value pair (Value the raw
// text of the value).
type tomlStmt struct {
	Header bool
	Array  bool // an array of tables, [[key]]
	Key    []string
	Value  string
}

type tomlReader struct {
	s    *sink
	data []byte
	pos  int
	err  error // a limit or the end of the context, met while reading a value
}

func (r *tomlReader) eof() bool { return r.pos >= len(r.data) }

func (r *tomlReader) peek() byte {
	if r.eof() {
		return 0
	}
	return r.data[r.pos]
}

// space skips blanks (not newlines).
func (r *tomlReader) space() {
	for !r.eof() && (r.data[r.pos] == ' ' || r.data[r.pos] == '\t') {
		r.pos++
	}
}

// lineEnd skips blanks and a comment, then requires the end of the line or of the file.
func (r *tomlReader) lineEnd() bool {
	r.space()
	if r.peek() == '#' {
		for !r.eof() && r.data[r.pos] != '\n' {
			r.pos++
		}
	}
	if r.eof() {
		return true
	}
	if r.data[r.pos] == '\r' && r.pos+1 < len(r.data) && r.data[r.pos+1] == '\n' {
		r.pos++
	}
	if r.data[r.pos] == '\n' {
		r.pos++
		return true
	}
	return false
}

func isBareKey(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// key reads a dotted key: bare or quoted parts.
func (r *tomlReader) key() ([]string, bool) {
	var parts []string
	for {
		r.space()
		var part string
		switch c := r.peek(); {
		case c == '"' || c == '\'':
			raw, ok := r.str()
			if !ok || strings.HasPrefix(raw, `"""`) || strings.HasPrefix(raw, "'''") {
				return nil, false
			}
			if part, ok = tomlUnquote(raw); !ok {
				return nil, false
			}
		case isBareKey(c):
			start := r.pos
			for !r.eof() && isBareKey(r.data[r.pos]) {
				r.pos++
			}
			part = string(r.data[start:r.pos])
		default:
			return nil, false
		}
		parts = append(parts, part)
		r.space()
		if r.peek() != '.' {
			return parts, true
		}
		r.pos++
	}
}

// str reads a string of any of the four kinds and returns it raw, quotes included.
func (r *tomlReader) str() (string, bool) {
	start := r.pos
	q := r.data[r.pos]
	multi := r.pos+2 < len(r.data) && r.data[r.pos+1] == q && r.data[r.pos+2] == q
	if multi {
		r.pos += 3
	} else {
		r.pos++
	}
	for !r.eof() {
		c := r.data[r.pos]
		switch {
		case c == '\\' && q == '"':
			r.pos += 2
			continue
		case c == '\n' && !multi:
			return "", false
		case c == q && !multi:
			r.pos++
			return string(r.data[start:r.pos]), true
		case c == q && r.pos+2 < len(r.data) && r.data[r.pos+1] == q && r.data[r.pos+2] == q:
			r.pos += 3
			// up to two more quotes belong to the content
			for i := 0; i < 2 && r.peek() == q; i++ {
				r.pos++
			}
			return string(r.data[start:r.pos]), true
		}
		r.pos++
	}
	return "", false
}

// value reads a value: a string, an array or an inline table (both may span lines; depth bounds the nesting), or a
// bare scalar (number, boolean, date) up to a separator.
func (r *tomlReader) value(depth int) bool {
	if depth > maxTOMLDepth {
		return false
	}
	if err := r.s.tick(); err != nil {
		r.err = err
		return false
	}
	switch c := r.peek(); c {
	case '"', '\'':
		_, ok := r.str()
		return ok
	case '[', '{':
		closeBy := byte(']')
		if c == '{' {
			closeBy = '}'
		}
		r.pos++
		for {
			r.blankLines(c == '[')
			if r.peek() == closeBy {
				r.pos++
				return true
			}
			if c == '{' {
				if _, ok := r.key(); !ok {
					return false
				}
				r.space()
				if r.peek() != '=' {
					return false
				}
				r.pos++
				r.space()
			}
			if !r.value(depth + 1) {
				return false
			}
			r.blankLines(c == '[')
			switch r.peek() {
			case ',':
				r.pos++
			case closeBy:
			default:
				return false
			}
		}
	}
	start := r.pos
	for !r.eof() {
		c := r.data[r.pos]
		if c == ' ' && tomlDate.Match(r.data[start:r.pos]) && tomlTimeStart.Match(r.data[r.pos+1:]) {
			r.pos++ // `1979-05-27 07:32:00`: a date and a time may be parted by a space
			continue
		}
		if c == ',' || c == ']' || c == '}' || c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '#' {
			break
		}
		if c == '"' || c == '\'' || c == '[' || c == '{' || c == '=' {
			return false
		}
		r.pos++
	}
	return r.pos > start
}

var (
	tomlDate      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	tomlTimeStart = regexp.MustCompile(`^[0-9]{2}:`)
)

// blankLines skips blanks, and inside an array also newlines and comments.
func (r *tomlReader) blankLines(newlines bool) {
	for {
		r.space()
		if !newlines {
			return
		}
		switch r.peek() {
		case '#':
			for !r.eof() && r.data[r.pos] != '\n' {
				r.pos++
			}
		case '\n', '\r':
			r.pos++
		default:
			return
		}
	}
}

// next reads the next statement; ok is false at the end, err set when the file isn't TOML as expected.
func (r *tomlReader) next() (st tomlStmt, ok bool, err error) {
	for {
		r.space()
		if r.eof() {
			return st, false, nil
		}
		if c := r.peek(); c == '\n' || c == '#' || c == '\r' {
			if !r.lineEnd() {
				return st, false, ErrParse
			}
			continue
		}
		break
	}
	if err := r.s.tick(); err != nil { // what a caller keeps of a statement it counts itself
		return st, false, err
	}
	if r.peek() == '[' {
		r.pos++
		array := r.peek() == '['
		if array {
			r.pos++
		}
		key, ok := r.key()
		if !ok || r.peek() != ']' {
			return st, false, ErrParse
		}
		r.pos++
		if array {
			if r.peek() != ']' {
				return st, false, ErrParse
			}
			r.pos++
		}
		if !r.lineEnd() {
			return st, false, ErrParse
		}
		return tomlStmt{Header: true, Array: array, Key: key}, true, nil
	}
	key, ok := r.key()
	if !ok || r.peek() != '=' {
		return st, false, ErrParse
	}
	r.pos++
	r.space()
	start := r.pos
	if !r.value(0) {
		return st, false, cmpOr(r.err, ErrParse)
	}
	st = tomlStmt{Key: key, Value: string(r.data[start:r.pos])}
	if !r.lineEnd() {
		return st, false, ErrParse
	}
	return st, true, nil
}

// tomlUnquote decodes a single-line or multi-line string; ok is false for anything else.
func tomlUnquote(raw string) (string, bool) {
	if len(raw) < 2 || !utf8.ValidString(raw) {
		return "", false
	}
	q := raw[0]
	if q != '"' && q != '\'' {
		return "", false
	}
	body := raw[1 : len(raw)-1]
	multi := len(raw) >= 6 && raw[1] == q && raw[2] == q
	if multi {
		body = strings.TrimPrefix(strings.TrimPrefix(raw[3:len(raw)-3], "\r\n"), "\n")
	}
	if q == '\'' {
		return body, true
	}
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if i++; i >= len(body) {
			return "", false
		}
		if multi {
			// a line-ending backslash: the newline and the whitespace after it are left out
			if j := i + len(body[i:]) - len(strings.TrimLeft(body[i:], " \t")); j < len(body) && (body[j] == '\n' || body[j] == '\r') {
				i = j + len(body[j:]) - len(strings.TrimLeft(body[j:], " \t\r\n")) - 1
				continue
			}
		}
		switch body[i] {
		case 'b':
			b.WriteByte('\b')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'f':
			b.WriteByte('\f')
		case 'r':
			b.WriteByte('\r')
		case '"', '\\':
			b.WriteByte(body[i])
		case 'u', 'U':
			n := 4
			if body[i] == 'U' {
				n = 8
			}
			if i+n >= len(body) {
				return "", false
			}
			v, err := strconv.ParseUint(body[i+1:i+1+n], 16, 32)
			if err != nil || !utf8.ValidRune(rune(v)) {
				return "", false
			}
			b.WriteRune(rune(v))
			i += n
		default:
			return "", false // not an escape of TOML
		}
	}
	return b.String(), true
}

// tomlTable reads an inline table into key -> raw value; ok is false if raw isn't one or has a dotted key.
func tomlTable(s *sink, raw string) (map[string]string, bool) {
	if !strings.HasPrefix(raw, "{") {
		return nil, false
	}
	r := &tomlReader{s: s, data: []byte(raw), pos: 1}
	out := map[string]string{}
	for {
		r.space()
		if r.peek() == '}' {
			return out, true
		}
		key, ok := r.key()
		if !ok || r.peek() != '=' {
			return nil, false
		}
		r.pos++
		r.space()
		start := r.pos
		if !r.value(1) {
			return nil, false
		}
		if len(key) != 1 {
			return nil, false // `version.workspace = true`: a field this reader doesn't descend into
		}
		if _, dup := out[key[0]]; dup {
			return nil, false
		}
		out[key[0]] = raw[start:r.pos]
		r.space()
		switch r.peek() {
		case ',':
			r.pos++
		case '}':
		default:
			return nil, false
		}
	}
}

// tomlArray reads an array into its raw elements, counting each as an entry.
func tomlArray(s *sink, raw string) ([]string, error) {
	if !strings.HasPrefix(raw, "[") {
		return nil, parseErr("toml: no array")
	}
	r := &tomlReader{s: s, data: []byte(raw), pos: 1}
	var out []string
	for {
		r.blankLines(true)
		if r.peek() == ']' {
			return out, nil
		}
		start := r.pos
		if !r.value(1) {
			return nil, cmpOr(r.err, parseErr("toml: array"))
		}
		if err := s.entry(); err != nil {
			return nil, err
		}
		out = append(out, raw[start:r.pos])
		r.blankLines(true)
		switch r.peek() {
		case ',':
			r.pos++
		case ']':
		default:
			return nil, parseErr("toml: array")
		}
	}
}
