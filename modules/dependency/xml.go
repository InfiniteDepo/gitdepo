// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

// decodeXML decodes a manifest into v. Go's decoder doesn't fetch external entities or expand custom ones (an entity
// that isn't predefined is an error in strict mode), a DOCTYPE that declares entities is refused outright, only
// UTF-8 is read, and the nesting depth is limited because the decoder itself doesn't.
func decodeXML(data []byte, v any, what string) error {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	newDec := func() *xml.Decoder {
		d := xml.NewDecoder(bytes.NewReader(data))
		d.Strict = true
		d.CharsetReader = func(label string, in io.Reader) (io.Reader, error) {
			switch strings.ToLower(label) {
			case "utf-8", "us-ascii":
				return in, nil
			case "iso-8859-1", "latin1", "latin-1", "iso_8859-1":
				// many older poms declare it; every byte maps to the code point of the same value
				return charmap.ISO8859_1.NewDecoder().Reader(in), nil
			}
			return nil, errors.New("charset")
		}
		return d
	}
	d, depth := newDec(), 0
	for {
		tok, err := d.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return parseErr("%s", what)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth++; depth > maxXMLDeep {
				return parseErr("%s", what)
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			if bytes.Contains(bytes.ToUpper(t), []byte("ENTITY")) {
				return parseErr("%s", what)
			}
		}
	}
	if err := newDec().Decode(v); err != nil {
		return parseErr("%s", what)
	}
	return nil
}

// expandProps replaces ${name} (Maven) or $(name) (MSBuild) with values of props, a few levels deep. A reference
// that can't be resolved leaves the result empty: a version that isn't known is stored as no version.
func expandProps(s string, props map[string]string, open, close string) string {
	for range 5 {
		i := strings.Index(s, open)
		if i < 0 {
			return s
		}
		j := strings.Index(s[i:], close)
		if j < 0 {
			return ""
		}
		v, ok := props[s[i+len(open):i+j]]
		if !ok {
			return ""
		}
		s = s[:i] + v + s[i+j+len(close):]
	}
	if strings.Contains(s, open) {
		return ""
	}
	return s
}

type xmlProp struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}
