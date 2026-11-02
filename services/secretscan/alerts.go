// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"cmp"
	"context"
	"errors"
	"hash/maphash"
	"maps"
	"slices"
	"strings"
	"sync"
	"unicode"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/util"
	vulnerability_service "forgejo.org/services/vulnerability"

	"golang.org/x/text/unicode/norm"
)

// ErrConflict is a change of an alert that its state doesn't allow any more (it changed meanwhile): the caller
// reloads and answers 409.
var ErrConflict = errors.New("the alert changed")

// ErrArchived is a change in an archived repository.
var ErrArchived = errors.New("the repository is archived")

// ErrCommentSecret is a comment the detector finds a secret in. Alert comments are stored, shown and audited, so
// they must not become a second place for the secret.
var ErrCommentSecret = util.NewInvalidArgumentErrorf("the comment looks like a secret")

// commentDetector is the detector of every rule, the generic ones too, for the comment of an alert.
var commentDetector = sync.OnceValues(func() (*secretdetection.Detector, error) {
	return secretdetection.NewDetector(secretdetection.BuiltinRules())
})

// ErrCommentTooCostly is a comment the check would need more work for than its budget: refused, as it can't be checked.
var ErrCommentTooCostly = util.NewInvalidArgumentErrorf("the comment can't be checked, shorten it")

const (
	minCandidateLen   = 16
	maxCandidateLen   = 512 // the longest secret a rule other than a PEM block finds (the detector finds those)
	maxCandidates     = 2000
	maxCandidateBytes = 256 << 10
	maxSplitSteps     = 8 // the = and : of a word that are tried as the start of a secret
)

// commentCandidates is the work of the check of the fingerprints of one comment, shared by all the texts of it.
type commentCandidates struct {
	hashes map[string]struct{}
	seen   map[uint64]struct{} // the candidates already added (a cheap hash of each: no string is kept)
	count  int
	bytes  int
}

var candidateSeed = maphash.MakeSeed()

func newCommentCandidates() *commentCandidates {
	return &commentCandidates{hashes: map[string]struct{}{}, seen: map[uint64]struct{}{}}
}

// add hashes the candidate as it is, lower-cased and upper-cased, when its length can be that of a secret. It fails
// when the comment has used its budget: the cost of a comment is bounded however it is made.
func (c *commentCandidates) add(cand string) error {
	if len(cand) < minCandidateLen || len(cand) > maxCandidateLen {
		return nil
	}
	// a candidate that was added before costs nothing: links and paths repeat their parts
	key := maphash.String(candidateSeed, cand)
	if _, ok := c.seen[key]; ok {
		return nil
	}
	c.seen[key] = struct{}{}
	for _, v := range [...]string{cand, strings.ToLower(cand), strings.ToUpper(cand)} {
		if c.count++; c.count > maxCandidates {
			return ErrCommentTooCostly
		}
		if c.bytes += len(v); c.bytes > maxCandidateBytes {
			return ErrCommentTooCostly
		}
		c.hashes[secretdetection.Fingerprint([]byte(v))] = struct{}{}
	}
	return nil
}

// addComment refuses a comment the detector finds a secret in (the rules don't see a secret that needs its context,
// an AWS secret key: see the fingerprints) and collects the candidates of it. They are the words of the comment (also
// after "key=" or "key:", and without the characters around them that can't be in a secret, as in "**secret**" and
// "secret!"), every run of the characters a secret is made of (also without dots at the ends) and the parts of those
// runs between . / - _ + and = (any number of them from either end). Not caught: a secret glued to letters or digits
// with no separator (a deliberate stash by someone who holds the secret), and, for a viewer without Wiki read, the
// secret of an alert that is only in the wiki (it is left out, so the answer doesn't confirm a hidden secret).
func (c *commentCandidates) addComment(comment string) error {
	d, err := commentDetector()
	if err != nil {
		return err
	}
	if found, _ := d.Scan([]byte(comment)); len(found) > 0 {
		return ErrCommentSecret
	}
	inSecret := func(r rune) bool {
		return r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("+/=_-.", r))
	}
	addWord := func(w string) error { // the word or run, and what follows each = and : (once per word, not per part)
		rest := w
		for range maxSplitSteps + 1 {
			if err := c.add(rest); err != nil {
				return err
			}
			i := strings.IndexAny(rest, "=:")
			if i < 0 {
				break
			}
			rest = rest[i+1:]
		}
		return nil
	}
	for w := range strings.FieldsFuncSeq(comment, func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune("\"'`,;()<>[]{}", r) }) {
		if err := cmp.Or(addWord(w), addWord(strings.TrimFunc(w, func(r rune) bool { return !inSecret(r) }))); err != nil {
			return err
		}
	}
	for run := range strings.FieldsFuncSeq(comment, func(r rune) bool { return !inSecret(r) }) {
		if err := cmp.Or(addWord(run), addWord(strings.Trim(run, "."))); err != nil {
			return err
		}
		// what lies between the . / - _ + and = of the run (a secret can hold some of them: every start and end)
		starts, ends := []int{0}, []int{len(run)}
		for i, r := range run {
			if strings.ContainsRune("./-_+=", r) {
				starts, ends = append(starts, i+1), append(ends, i)
			}
		}
		// a run of more than 100 delimiters is refused, not cut: dropping positions could drop the secret's own ends
		if len(starts) > maxRunPositions {
			return ErrCommentTooCostly
		}
		for _, from := range starts {
			for _, to := range ends {
				if from < to && to-from <= maxCandidateLen {
					if err := c.add(run[from:to]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// maxRunPositions is the most delimiters a run may hold: a comment is short, but one made of delimiters would
// otherwise have as many candidates as the square of its length.
const maxRunPositions = 100

// invisible removes what shows as nothing next to a letter: combining marks, format characters and fillers.
func invisible(r rune) rune {
	if unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf) || r == 0x115f || r == 0x1160 || r == 0x3164 || r == 0xffa0 || r == 0x2800 { // and the Hangul fillers and the braille blank
		return -1
	}
	return r
}

// ErrCommentRequired is a won't fix without a comment (after the cleaning: a comment of invisible characters is none).
var ErrCommentRequired = util.NewInvalidArgumentErrorf("won't fix needs a comment that says why")

// CheckComment cleans a close comment of at most 1,000 bytes and checks that it holds no secret: the text it
// returns is what Close stores. Bulk close calls it once and then CloseChecked for every alert. A bad comment is
// util.ErrInvalidArgument (ErrCommentSecret, ErrCommentTooCostly).
func CheckComment(ctx context.Context, repo *repo_model.Repository, comment string, canReadWiki bool) (string, error) {
	if len(comment) > 4*secretscan_model.MaxCommentLen {
		return "", util.NewInvalidArgumentErrorf("the comment is longer than %d bytes", secretscan_model.MaxCommentLen)
	}
	// no control, bidi or other format characters (they hide a secret from the detector and reorder text)
	comment = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, vulnerability_service.CleanComment(comment)))
	if len(comment) > secretscan_model.MaxCommentLen {
		return "", util.NewInvalidArgumentErrorf("the comment is longer than %d bytes", secretscan_model.MaxCommentLen)
	}
	if comment == "" {
		return "", nil
	}
	// the text as it reads: combining marks and format characters out, look-alikes folded (NFKC); one budget for both
	c := newCommentCandidates()
	texts := []string{comment}
	if folded := strings.Map(invisible, norm.NFKC.String(comment)); folded != comment {
		texts = append(texts, folded)
	}
	for _, text := range texts {
		if err := c.addComment(text); err != nil {
			return "", err
		}
	}
	// read outside the transaction, only for the check (the transaction below changes the one alert with a conditional
	// UPDATE): do the alerts of the repository that the doer can see have one of these fingerprints? Without Wiki read,
	// an alert that is only in the wiki doesn't count, so the answer doesn't confirm a secret of the wiki.
	hit, err := secretscan_model.AnyFingerprint(ctx, repo.ID, slices.Collect(maps.Keys(c.hashes)), !canReadWiki)
	if err != nil {
		return "", err
	}
	if hit {
		return "", ErrCommentSecret
	}
	return comment, nil
}

// Close closes an open alert of the repository as revoked, false_positive, used_in_tests or wont_fix (the reason is the
// state), with an optional comment of at most 1,000 bytes (required for wont_fix). The audit entry is written in the
// same transaction. A bad state or comment is util.ErrInvalidArgument, an unknown alert util.ErrNotExist, an alert that
// isn't open ErrConflict, an archived repository ErrArchived.
func Close(ctx context.Context, repo *repo_model.Repository, doer *user_model.User, index int64, state, comment string, canReadWiki bool) (*secretscan_model.Alert, error) {
	if !slices.Contains(secretscan_model.ClosedStates, state) {
		return nil, util.NewInvalidArgumentErrorf("resolution must be one of %v", secretscan_model.ClosedStates)
	}
	comment, err := CheckComment(ctx, repo, comment, canReadWiki)
	if err != nil {
		return nil, err
	}
	return CloseChecked(ctx, repo, doer, index, state, comment)
}

// CloseChecked is Close for a comment that CheckComment returned.
func CloseChecked(ctx context.Context, repo *repo_model.Repository, doer *user_model.User, index int64, state, comment string) (*secretscan_model.Alert, error) {
	if !slices.Contains(secretscan_model.ClosedStates, state) {
		return nil, util.NewInvalidArgumentErrorf("resolution must be one of %v", secretscan_model.ClosedStates)
	}
	if state == secretscan_model.StateWontFix && comment == "" {
		return nil, ErrCommentRequired
	}
	return changeAlert(ctx, repo, "", func(ctx context.Context) (*secretscan_model.Alert, bool, error) {
		before, err := secretscan_model.CloseAlert(ctx, repo.ID, index, state, comment, doer.ID)
		return before, err == nil, err
	}, index, state, comment)
}

// Reopen reopens a closed alert; an open one is returned as it is.
func Reopen(ctx context.Context, repo *repo_model.Repository, index int64) (*secretscan_model.Alert, error) {
	return changeAlert(ctx, repo, "reopen", func(ctx context.Context) (*secretscan_model.Alert, bool, error) {
		return secretscan_model.ReopenAlert(ctx, repo.ID, index)
	}, index, secretscan_model.StateOpen, "")
}

func changeAlert(ctx context.Context, repo *repo_model.Repository, kind string, do func(context.Context) (*secretscan_model.Alert, bool, error), index int64, state, comment string) (*secretscan_model.Alert, error) {
	if repo.IsArchived {
		return nil, ErrArchived
	}
	var after *secretscan_model.Alert
	err := db.WithTx(ctx, func(ctx context.Context) error {
		before, changed, err := do(ctx)
		if err != nil {
			return err
		}
		if after, err = secretscan_model.GetAlert(ctx, repo.ID, index); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		data := map[string]any{
			"index": before.Index, "rule": before.RuleID, "fingerprint": before.Fingerprint[:min(12, len(before.Fingerprint))],
			"previous_state": before.State, "state": state, "comment": comment,
		}
		if locs, err := secretscan_model.FindLocations(ctx, repo.ID, before.ID, 1); err != nil {
			return err
		} else if len(locs) > 0 {
			data["path"] = locs[0].Path
		}
		// the action keys are literals: TestActionCatalog finds them in the code
		ev := audit_model.Event{TargetType: "secret_scanning_alert", TargetID: before.ID, TargetName: before.RuleID, Data: data}
		if kind == "reopen" {
			ev.Action = "repo.secret_alert.reopened"
		} else {
			ev.Action = "repo.secret_alert.closed"
		}
		return repo_model.RecordRepoTarget(ctx, repo, ev)
	})
	switch {
	case errors.Is(err, secretscan_model.ErrAlertState):
		return nil, ErrConflict
	case err != nil:
		return nil, err
	}
	return after, nil
}
