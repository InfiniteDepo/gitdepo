// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFilter(t *testing.T) {
	for _, c := range []struct {
		state, reason, typ string
		want               Filter
		ignored            []string
	}{
		{"", "", "", Filter{State: "open"}, nil}, // open by default, as the repository list
		{"all", "", "", Filter{State: "all"}, nil},
		{"open", "", "github-token", Filter{State: "open", Type: "github-token"}, nil},
		{"closed", "wont_fix", "", Filter{State: "closed", Reason: "wont_fix"}, nil},
		{"", "revoked", "", Filter{State: "closed", Reason: "revoked"}, nil}, // a reason alone lists closed alerts
		{"all", "revoked", "", Filter{State: "all", Reason: "revoked"}, nil},
		{"open", "revoked", "", Filter{State: "open"}, []string{"reason"}}, // no closed alert is open
		{"bogus", "", "", Filter{State: "open"}, []string{"state"}},
		{"closed", "bogus", "", Filter{State: "closed"}, []string{"reason"}},
		{"", "", "no-such-rule", Filter{State: "open"}, []string{"type"}},
		{"", "", "custom-7", Filter{State: "open", Type: "custom-7"}, nil}, // a custom pattern
		{"", "", strings.Repeat("a", 65), Filter{State: "open"}, []string{"type"}},
		{"bogus", "bogus", "bogus", Filter{State: "open"}, []string{"state", "reason", "type"}},
	} {
		got, ignored := ParseFilter(c.state, c.reason, c.typ)
		assert.Equal(t, c.want, got, "%+v", c)
		assert.Equal(t, c.ignored, ignored, "%+v", c)
	}
}
