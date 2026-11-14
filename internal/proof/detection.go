// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/stats"
)

// Proving a detection rule.
//
// The claim: this rule fires on every event in the corpus that is labelled
// as its own, and on nothing else it reads. The checks, in order, each one
// stopping the next only where running it would mean nothing:
//
//  1. valid    — the rule passes detect.Rule.Validate. An invalid rule is
//     refuted here and nothing else is run against it.
//  2. fixtures — its own must-match and must-not-match examples hold. These
//     are the author's, so passing them is necessary and never enough.
//  3. corpus   — replayed over a labelled corpus the author did not write:
//     every entry expecting it caught, nothing else fired on, including
//     false positives somebody already recorded and nobody has fixed.
//
// The verdict is inconclusive when nothing failed but the corpus could not
// have failed the rule: no entry expecting it, or no entry from a source
// it reads expecting quiet. Evidence that cannot contradict a claim does
// not confirm it.

// DetectionVerifier and DetectionVerifierVersion name this verifier in
// every proof it makes. The version moves when what a check does changes.
const (
	DetectionVerifier        = "aertun/detection"
	DetectionVerifierVersion = "1"
	// MaxRuleFile bounds a rule file; real ones are a few kilobytes.
	MaxRuleFile = 1 << 20
)

// DetectionInput is everything a detection proof is made from.
type DetectionInput struct {
	// RuleName is what the subject is called — usually the file name.
	RuleName string
	// Rule is the rule file's exact bytes: the subject is their digest, so
	// what was proven is what was reviewed.
	Rule []byte
	// CorpusName and Corpus are the labelled corpus's name and exact
	// bytes; Entries is it parsed. All empty when there is none, which
	// makes the verdict at best inconclusive.
	CorpusName string
	Corpus     []byte
	Entries    []detect.Labelled
	Author     Author
	Program    string
	Now        time.Time
}

// DetectionEvidence is how much the verdict rests on, so a proof over one
// positive example reads as the weak thing it is.
type DetectionEvidence struct {
	Rule string `json:"rule"`
	// Positives are corpus entries expecting the rule, Caught those it
	// fired on. Negatives are entries from a source it reads expecting it
	// to stay quiet, Quiet those it did.
	Positives int `json:"positives"`
	Caught    int `json:"caught"`
	Negatives int `json:"negatives"`
	Quiet     int `json:"quiet"`
	// RecallLow and SpecificityLow are the 95% Wilson lower bounds.
	RecallLow      float64 `json:"recall_wilson_low"`
	SpecificityLow float64 `json:"specificity_wilson_low"`
	Fixtures       int     `json:"fixtures"`
}

// ProveDetection runs the checks and returns the unsigned statement.
func ProveDetection(in DetectionInput) (*Statement, error) {
	if strings.TrimSpace(in.RuleName) == "" || len(in.Rule) == 0 {
		return nil, fmt.Errorf("a detection proof needs the rule file")
	}
	if len(in.Rule) > MaxRuleFile {
		return nil, fmt.Errorf("the rule file is larger than %d bytes", MaxRuleFile)
	}
	if (len(in.Corpus) == 0) != (in.CorpusName == "") {
		return nil, fmt.Errorf("a corpus needs both its name and its bytes")
	}
	var r detect.Rule
	if err := json.Unmarshal(in.Rule, &r); err != nil {
		return nil, fmt.Errorf("%s is not a detection rule: %w", in.RuleName, err)
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: in.RuleName, Digest: SHA256(in.Rule)}},
		PredicateType: PredicateDetection,
		Predicate: Predicate{
			Author: in.Author,
			Verifier: VerifierID{ID: DetectionVerifier,
				Version: DetectionVerifierVersion, Program: in.Program},
			Materials:  []Material{},
			VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	p := &st.Predicate
	ev := &DetectionEvidence{Rule: r.ID, Fixtures: len(r.Fixtures)}
	p.Detection = ev
	p.Claim = fmt.Sprintf("Rule %q fires on every corpus entry labelled as "+
		"its own and on nothing else it reads.", r.ID)

	if err := r.Validate(); err != nil {
		p.Checks = append(p.Checks, Check{Name: "valid", Detail: err.Error()})
		p.Verdict = Refuted
		return st, nil
	}
	p.Checks = append(p.Checks, Check{Name: "valid", Passed: true,
		Detail: "it names its sources, its condition is well formed, and its fixtures are usable events"})
	p.Checks = append(p.Checks, fixtureCheck(r))

	if in.CorpusName == "" {
		p.Checks = append(p.Checks, Check{Name: "corpus", Passed: true,
			Detail: "no corpus was given; the fixtures are the author's own " +
				"examples and cannot settle the claim"})
	} else {
		p.Materials = append(p.Materials, Material{Name: in.CorpusName,
			Digest: SHA256(in.Corpus), Entries: len(in.Entries)})
		c, err := corpusCheck(r, in.Entries, ev)
		if err != nil {
			return nil, err
		}
		p.Checks = append(p.Checks, c)
	}
	ev.RecallLow, _ = stats.Wilson(ev.Caught, ev.Positives)
	ev.SpecificityLow, _ = stats.Wilson(ev.Quiet, ev.Negatives)

	p.Verdict = Proven
	for _, c := range p.Checks {
		if !c.Passed {
			p.Verdict = Refuted
		}
	}
	if p.Verdict == Proven && (ev.Positives == 0 || ev.Negatives == 0) {
		p.Verdict = Inconclusive
	}
	return st, nil
}

func fixtureCheck(r detect.Rule) Check {
	var failed []string
	results := r.Test()
	for _, res := range results {
		if !res.OK() {
			failed = append(failed, res.Why())
		}
	}
	c := Check{Name: "fixtures", Passed: len(failed) == 0,
		Detail: fmt.Sprintf("%d of %d hold", len(results)-len(failed), len(results))}
	c.Failures, _ = capped(failed)
	return c
}

// corpusCheck replays the rule over the corpus as this rule sees it: an
// entry expecting the rule is a positive, and every other entry is one it
// must stay quiet on — the same reading detect.Replay gives a corpus when
// every rule is replayed together. Entries expecting other rules are kept
// for exactly that reason: this rule firing on them is a false positive.
func corpusCheck(r detect.Rule, entries []detect.Labelled, ev *DetectionEvidence) (Check, error) {
	view := make([]detect.Labelled, 0, len(entries))
	for _, l := range entries {
		mine := false
		for _, id := range l.Expect {
			mine = mine || id == r.ID
		}
		l.Expect = nil
		if mine {
			l.Expect = []string{r.ID}
			ev.Positives++
		} else if reads(r, l.Event.Source) {
			ev.Negatives++
		}
		view = append(view, l)
	}
	out, err := detect.Replay([]detect.Rule{r}, view)
	if err != nil {
		return Check{}, err
	}
	o := out[0]
	ev.Caught = o.Caught
	// A known false positive is still a false positive: proof is stricter
	// than the replay gate, which tolerates them so people keep recording
	// them.
	wrong := append(append([]string{}, o.Wrong...), o.Known...)
	ev.Quiet = max(ev.Negatives-countReadable(r, view, wrong), 0)
	failures := make([]string, 0, len(o.Missed)+len(wrong))
	for _, n := range o.Missed {
		failures = append(failures, "missed: "+n)
	}
	for _, n := range wrong {
		failures = append(failures, "fired on: "+n)
	}
	c := Check{Name: "corpus", Passed: len(failures) == 0}
	shown, more := capped(failures)
	c.Failures = shown
	c.Detail = fmt.Sprintf("caught %d of %d labelled as this rule; quiet on "+
		"%d of %d other entries from sources it reads",
		ev.Caught, ev.Positives, ev.Quiet, ev.Negatives)
	if more > 0 {
		c.Detail += fmt.Sprintf("; %d more failures not listed", more)
	}
	return c, nil
}

// reads reports whether the rule reads a source, the way detect.Rule.Matches
// decides it.
func reads(r detect.Rule, source string) bool {
	for _, s := range r.Sources {
		if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(source)) {
			return true
		}
	}
	return false
}

// countReadable counts the named entries that come from a source the rule
// reads — the negatives a false positive is subtracted from.
func countReadable(r detect.Rule, view []detect.Labelled, names []string) int {
	named := map[string]bool{}
	for _, n := range names {
		named[n] = true
	}
	n := 0
	for _, l := range view {
		if named[l.Name] && reads(r, l.Event.Source) {
			n++
		}
	}
	return n
}
