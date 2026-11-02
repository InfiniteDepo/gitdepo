// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValueWithInvalid(t *testing.T) {
	type state struct {
		A       int  `json:"a"`
		Invalid bool `json:"-"`
	}
	v := ValueJSON[state]("k").WithInvalid(state{Invalid: true})
	assert.Equal(t, state{A: 1}, v.parse("k", `{"a":1}`))
	assert.Equal(t, state{}, v.parse("k", ""))
	assert.Equal(t, state{Invalid: true}, v.parse("k", "{not json"))
	assert.Equal(t, state{Invalid: true}, v.parse("k", `{"a":"x"}`))

	// without WithInvalid an unparsable value reads as the default
	assert.Equal(t, state{}, ValueJSON[state]("k").parse("k", "{not json"))
}
