// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenericRuleKeepsBackslashesInValues(t *testing.T) {
	d := allRulesDetector(t)
	for name, v := range map[string]string{
		"in the middle":  fake(10, alnum) + `\` + fake(22, alnum),
		"near the end":   fake(24, alnum) + `\` + fake(8, alnum),
		"windows path":   `C:\Users\` + fake(32, alnum),
		"double":         fake(12, alnum) + `\\` + fake(12, alnum),
		"escaped quote":  fake(24, alnum),
		"json in string": fake(24, alnum),
	} {
		content := `password = "` + v + `"`
		if name == "json in string" {
			content = `{\"password\":\"` + v + `\"}`
		}
		assert.Equal(t, 1, countRule(d, content, "generic-secret-assignment"), name)
	}
}

// keywordLine names every keyword of every built-in rule once, so every rule
// is active.
var keywordLine = func() string {
	var words []string
	for _, r := range BuiltinRules() {
		words = append(words, r.Keywords...)
	}
	return strings.Join(words, " ") + "\n"
}()

func TestKeywordLineDoesNotMakeProseExpensive(t *testing.T) {
	d := defaultRulesDetector(t)
	size := 9 << 20 / slowdown // under -race the blob and the budget are a tenth
	d.MaxWork = max(MinMaxWork, WorkPerByte*size) / slowdown
	prose := repeatTo("The quick brown fox jumps over the lazy dog and keeps running home.\n", size)
	start := time.Now()
	_, complete := d.Scan(append([]byte(keywordLine), prose...))
	el := time.Since(start)
	t.Logf("%v complete=%v", el, complete)
	assert.Less(t, el, 2*time.Second*slowdown, "the target is 1 s; 2.7 s without the charge")
	// without the line the same prose is cheap
	start = time.Now()
	_, complete = d.Scan(prose)
	assert.True(t, complete)
	assert.Less(t, time.Since(start), time.Second*slowdown)
}

func TestKeywordLineDoesNotShrinkAShare(t *testing.T) {
	d := allRulesDetector(t)
	id := "AKIA" + fake(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	decoys := strings.Repeat("AKIA"+strings.Repeat("A", 16)+" \n", 512<<10/22)
	fs, _ := d.Scan([]byte(keywordLine + decoys + "id = " + id + "\n"))
	assert.Equal(t, 1, countRuleIn(fs, "aws-access-key-id"))
}
