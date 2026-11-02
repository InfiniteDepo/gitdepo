// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package test

import (
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// brandRe matches the old names in any case, and the new one only when capitalised: gitdepo is always lowercase.
// Word boundaries keep "MyForgejoTeam1" out.
var brandRe = regexp.MustCompile(`.{0,40}((?i:\bforgejo|\bgithat|\bcodehat|\bspoved\b)|\bGitdepo\b|\bGITDEPO\b).{0,40}`)

// BrandAllowed are the exact visible phrases that legitimately name Forgejo, the upstream project or its
// external programs. BrandMentions ignores them; docs/branding.md explains each one.
var BrandAllowed = []string{
	// the footer credit and the migration source name the upstream project
	"based on Forgejo", "Forgejo documentation",
	// the runner is an external program; the setup pages show its command
	"forgejo-runner",
	// links to upstream's documentation, visible when a page prints a URL
	"forgejo.org/docs",
	// the installer's placeholders for the domain and URL are upstream's example host
	"next.forgejo.org",
}

// BrandMentions returns every user-visible old product name ("Forgejo", "GitHat", "CodeHat", "spoved") and
// capitalised "Gitdepo" or "GITDEPO" in an HTML page or mail, with some context.
// It reads the title, meta contents, body text and the alt, title, placeholder and aria-label attributes,
// and ignores the phrases in BrandAllowed.
func BrandMentions(html string) []string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return []string{err.Error()}
	}
	doc.Find("script, style").Remove()
	texts := []string{doc.Find("title").Text(), doc.Find("body").Text()}
	doc.Find("meta[content], [alt], [title], [placeholder], [aria-label]").Each(func(_ int, s *goquery.Selection) {
		for _, attr := range []string{"content", "alt", "title", "placeholder", "aria-label"} {
			if v, ok := s.Attr(attr); ok {
				texts = append(texts, v)
			}
		}
	})
	var hits []string
	for _, text := range texts {
		for _, phrase := range BrandAllowed {
			text = strings.ReplaceAll(text, phrase, "")
		}
		for _, hit := range brandRe.FindAllString(text, -1) {
			hits = append(hits, strings.Join(strings.Fields(hit), " "))
		}
	}
	return hits
}
