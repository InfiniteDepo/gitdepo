// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"bytes"
	stdjson "encoding/json" //nolint:depguard // the token API; the memory of a parse must not depend on the input's shape
	"errors"
	"io"
	"strings"
)

// jsonStream reads a JSON document token by token. Values a parser doesn't need are skipped by depth, never
// decoded, so a file costs memory only for what the parser keeps (and counts through the sink).
type jsonStream struct {
	dec *stdjson.Decoder
	s   *sink
}

func newJSONStream(s *sink, data []byte) *jsonStream {
	return &jsonStream{dec: stdjson.NewDecoder(bytes.NewReader(data)), s: s}
}

func (j *jsonStream) tok() (stdjson.Token, error) {
	if err := j.s.tick(); err != nil {
		return nil, err
	}
	t, err := j.dec.Token()
	if errors.Is(err, io.EOF) {
		return nil, io.ErrUnexpectedEOF
	}
	return t, err
}

// skipRest skips what is left of the value whose first token t was just read.
func (j *jsonStream) skipRest(t stdjson.Token) error {
	d, ok := t.(stdjson.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil
	}
	for depth := 1; depth > 0; {
		t, err := j.tok()
		if err != nil {
			return err
		}
		if d, ok := t.(stdjson.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

func (j *jsonStream) skip() error {
	t, err := j.tok()
	if err != nil {
		return err
	}
	return j.skipRest(t)
}

// object reads an object and calls fn for every key; fn has to read or skip the value. A value that is not an
// object is skipped and reported as ok == false.
func (j *jsonStream) object(fn func(key string) error) (ok bool, err error) {
	return j.objectOr(false, fn)
}

// objectOr is object; with emptyList, `[]` (what PHP's json_encode writes for an empty map) is an empty object.
func (j *jsonStream) objectOr(emptyList bool, fn func(key string) error) (ok bool, err error) {
	t, err := j.tok()
	if err != nil {
		return false, err
	}
	if d, isDelim := t.(stdjson.Delim); emptyList && isDelim && d == '[' {
		t, err := j.tok()
		if err != nil {
			return false, err
		}
		if d, isDelim := t.(stdjson.Delim); isDelim && d == ']' {
			return true, nil
		}
		return false, parseErr("json: a list") // with items
	}
	if d, isDelim := t.(stdjson.Delim); !isDelim || d != '{' {
		return false, j.skipRest(t)
	}
	for {
		t, err := j.tok()
		if err != nil {
			return false, err
		}
		if d, isDelim := t.(stdjson.Delim); isDelim && d == '}' {
			return true, nil
		}
		key, isStr := t.(string)
		if !isStr {
			return false, parseErr("json")
		}
		if err := fn(key); err != nil {
			return false, err
		}
	}
}

// array reads an array and calls fn for every element; fn has to read or skip it.
func (j *jsonStream) array(fn func() error) (ok bool, err error) {
	t, err := j.tok()
	if err != nil {
		return false, err
	}
	if d, isDelim := t.(stdjson.Delim); !isDelim || d != '[' {
		return false, j.skipRest(t)
	}
	for {
		if !j.dec.More() {
			if _, err := j.tok(); err != nil { // the closing bracket
				return false, err
			}
			return true, nil
		}
		if err := fn(); err != nil {
			return false, err
		}
	}
}

// str reads a string value; any other value is skipped and gives "".
func (j *jsonStream) str() (string, error) {
	t, err := j.tok()
	if err != nil {
		return "", err
	}
	if s, ok := t.(string); ok {
		return s, nil
	}
	return "", j.skipRest(t)
}

// boolean reads a boolean value; any other value is skipped and gives false.
func (j *jsonStream) boolean() (bool, error) {
	t, err := j.tok()
	if err != nil {
		return false, err
	}
	if b, ok := t.(bool); ok {
		return b, nil
	}
	return false, j.skipRest(t)
}

// keys reads an object and calls fn for each key with the value skipped (the dependency maps: only the names matter).
func (j *jsonStream) keys(fn func(key string) error) error {
	_, err := j.object(func(k string) error {
		if err := fn(k); err != nil {
			return err
		}
		return j.skip()
	})
	return err
}

// license reads a license value: a string, an object with a "type", or a list of them (joined as alternatives).
func (j *jsonStream) license() (string, error) {
	t, err := j.tok()
	if err != nil {
		return "", err
	}
	var parts []string
	var item func(t stdjson.Token) error
	item = func(t stdjson.Token) error {
		switch v := t.(type) {
		case string:
			parts = append(parts, v)
		case stdjson.Delim:
			switch v {
			case '{':
				for {
					kt, err := j.tok()
					if err != nil {
						return err
					}
					if d, ok := kt.(stdjson.Delim); ok && d == '}' {
						return nil
					}
					if kt == "type" {
						vt, err := j.tok()
						if err != nil {
							return err
						}
						if s, ok := vt.(string); ok {
							parts = append(parts, s)
						} else if err := j.skipRest(vt); err != nil {
							return err
						}
					} else if err := j.skip(); err != nil {
						return err
					}
				}
			case '[':
				for n := 0; ; n++ {
					et, err := j.tok()
					if err != nil {
						return err
					}
					if d, ok := et.(stdjson.Delim); ok && d == ']' {
						return nil
					}
					if n >= 16 {
						if err := j.skipRest(et); err != nil {
							return err
						}
						continue
					}
					if err := item(et); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := item(t); err != nil {
		return "", err
	}
	out := strings.Join(parts, " OR ")
	if len(out) > MaxLicenseLen*2 {
		out = ""
	}
	return out, nil
}
