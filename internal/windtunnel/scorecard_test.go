// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// The aggregate is recomputed from the rows by an independent
// implementation of the arithmetic, over the document's own decoded bytes
// rather than the in-memory structs — so a rendering, a rounding or a count
// that drifted from what the rows say fails here, and the number a
// scorecard prints is the number its rows add up to.
func TestScorecardArithmeticRecomputedIndependently(t *testing.T) {
	card, err := Run(RunOptions{Seed: 7,
		Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := card.Document()
	if err != nil {
		t.Fatal(err)
	}
	var rendered Scorecard
	if err := json.Unmarshal(doc, &rendered); err != nil {
		t.Fatal(err)
	}

	// The independent count, straight from the definition: the denominator
	// is scenarios that carry a must-alert expectation — rows, not legs, so
	// a scenario with two must-alert expects is one, not two.
	var mustAlertScenarios, missed, caught, telemetryOnly, wronglyQuiet,
		twinFires int
	for _, r := range rendered.Rows {
		carries := false
		for _, x := range r.Expects {
			if x.Verdict == VerdictMustAlert {
				carries = true
				if !x.Met {
					missed++
				}
			}
		}
		if carries {
			mustAlertScenarios++
		}
		switch r.Outcome {
		case OutcomeCaughtAlert:
			caught++
		case OutcomeCaughtTelemetry:
			telemetryOnly++
		case OutcomeWronglyQuiet:
			wronglyQuiet++
		case OutcomeMissed:
			// Counted through the unmet must-alerts above.
		}
		if r.Twin.Outcome == TwinFalseFire {
			twinFires++
		}
	}
	// A scenario missed on one leg and met on none must fold to one missed
	// row, not one per unmet expect: rows, not legs, are the denominator.
	missedRows := 0
	for _, r := range rendered.Rows {
		if r.Outcome == OutcomeMissed {
			missedRows++
		}
	}
	a := rendered.Aggregate
	if a.MustAlert != mustAlertScenarios {
		t.Errorf("the document says %d must-alert scenarios; the rows carry "+
			"%d", a.MustAlert, mustAlertScenarios)
	}
	if a.Missed != missedRows {
		t.Errorf("the document says %d missed; the rows fold to %d",
			a.Missed, missedRows)
	}
	if a.Scenarios != len(rendered.Rows) {
		t.Errorf("%d scenarios in the aggregate, %d rows",
			a.Scenarios, len(rendered.Rows))
	}
	if missedRows != 0 {
		// The shipped corpus is all-caught; a miss belongs to the honesty
		// tests, and reaching this branch here means the corpus regressed.
		t.Fatalf("%d row(s) missed; the shipped pack catches the four "+
			"scenarios it carries rules for", missedRows)
	}
	if a.Missed != missedRows || a.Caught != caught ||
		a.TelemetryOnly != telemetryOnly || a.WronglyQuiet != wronglyQuiet ||
		a.TwinFires != twinFires {
		t.Errorf("the aggregate counts do not match the rows: %+v vs "+
			"missed %d caught %d telemetry %d quiet %d twins %d", a,
			missedRows, caught, telemetryOnly, wronglyQuiet, twinFires)
	}

	// The miss rate and its Wilson bounds, from the formula rather than the
	// package's code: the interval is the number no vendor publishes, and
	// it is where a rendering drift would hide.
	p := float64(a.Missed) / float64(a.MustAlert)
	if math.Abs(p-a.MissRate) > 1e-12 {
		t.Errorf("miss rate %g, recomputed %g", a.MissRate, p)
	}
	lo, hi := wilsonIndependent(p, a.MustAlert)
	if math.Abs(lo-a.MissRateLow) > 1e-9 || math.Abs(hi-a.MissRateHigh) > 1e-9 {
		t.Errorf("Wilson bounds %g–%g, recomputed %g–%g", a.MissRateLow,
			a.MissRateHigh, lo, hi)
	}
	// The small-sample honesty the interval exists for: zero misses over
	// four is not a claim of zero, and the upper bound says so.
	if a.Missed == 0 && a.MustAlert == 4 && a.MissRateHigh < 0.4 {
		t.Errorf("the upper Wilson bound over four scenarios is %g; the "+
			"whole point of the interval is that 0 of 4 is not 0%%",
			a.MissRateHigh)
	}

	// The grids: every row appears in its family, and the technique grid
	// counts each scenario once per technique it stages.
	families := map[string]int{}
	for _, f := range rendered.Families {
		for _, r := range rendered.Rows {
			if r.Family == f.Family {
				families[f.Family]++
			}
		}
		if f.Tested != families[f.Family] {
			t.Errorf("family %s says %d tested, the rows carry %d", f.Family,
				f.Tested, families[f.Family])
		}
	}
	techs := map[string]int{}
	for _, r := range rendered.Rows {
		for _, tech := range r.Techniques {
			techs[tech]++
		}
	}
	for _, tt := range rendered.Techniques {
		if tt.Tested != techs[tt.Technique] {
			t.Errorf("technique %s says %d tested, the rows stage it %d time(s)",
				tt.Technique, tt.Tested, techs[tt.Technique])
		}
	}
}

// wilsonIndependent is the Wilson score interval written from its
// definition for this test, so the package's port of internal/bench's
// wilson is checked against the mathematics rather than against itself.
func wilsonIndependent(p float64, n int) (lo, hi float64) {
	const z = 1.959963984540054 // the two-sided 95% normal quantile
	den := 1 + z*z/float64(n)
	centre := (p + z*z/(2*float64(n))) / den
	half := z / den * math.Sqrt(p*(1-p)/float64(n)+z*z/(4*float64(n)*float64(n)))
	lo, hi = centre-half, centre+half
	if lo < 0 {
		lo = 0
	}
	if hi > 1 {
		hi = 1
	}
	return lo, hi
}

// An edited scorecard refuses to verify — the digest is the only thing
// standing between a rendered number and a number somebody typed in.
func TestScorecardRefusesAnEdit(t *testing.T) {
	card, err := Run(RunOptions{Seed: 7,
		Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := card.Document()
	if err != nil {
		t.Fatal(err)
	}
	if err := card.Verify(); err != nil {
		t.Fatalf("the document as written does not verify: %v", err)
	}

	// One number, changed after the fact.
	edited := strings.Replace(string(doc), `"miss_rate": 0`,
		`"miss_rate": 0.25`, 1)
	if edited == string(doc) {
		t.Fatal("the edit found nothing to change; the test is testing " +
			"nothing and must be rewritten against the document as written")
	}
	var tampered Scorecard
	if err := json.Unmarshal([]byte(edited), &tampered); err != nil {
		t.Fatal(err)
	}
	err = tampered.Verify()
	if err == nil || !strings.Contains(err.Error(), "edited since it was written") {
		t.Fatalf("an edited scorecard verified (%v); every rendered number "+
			"must be traceable to the file it came from or exposed as "+
			"edited", err)
	}

	// And a document from another schema is refused rather than
	// best-effort rendered.
	tampered.Schema = "aertun/windtunnel-scorecard/v0"
	if err := tampered.Verify(); err == nil ||
		!strings.Contains(err.Error(), "this build reads") {
		t.Errorf("a v0 document gave %v", err)
	}
}

// Sealing is deterministic, and the digest covers everything except itself
// and the signature — so the same document seals to the same digest, and
// the signature is a check on top of a check.
func TestScorecardSealIsDeterministicAndCoversTheDocument(t *testing.T) {
	card, err := Run(RunOptions{Seed: 7,
		Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	first := card.SHA256
	if err := card.seal(); err != nil {
		t.Fatal(err)
	}
	if card.SHA256 != first {
		t.Fatalf("sealing twice moved the digest from %s to %s", first,
			card.SHA256)
	}
	// The signed-out form carries the digest; the digest carries the rows.
	card.Rows[0].SessionEvents++
	if err := card.Verify(); err == nil {
		t.Fatal("a changed row still verified; the digest must cover the " +
			"rows or it seals nothing")
	}
	card.Rows[0].SessionEvents--
	if err := card.Verify(); err != nil {
		t.Fatalf("restoring the row did not restore the verification: %v", err)
	}
}

// The summary names what ran before how it went, states the aggregate with
// its bounds, and says when it is unsigned — one screen a founder can read,
// and no claim the document does not carry.
func TestScorecardSummarizeNamesWhatRanBeforeHowItWent(t *testing.T) {
	card, err := Run(RunOptions{Seed: 7,
		Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	s := card.Summarize()
	for _, want := range []string{
		"mode replay, scoring reference",
		"base stream " + FixtureName,
		"reference pack",
		"corpus " + CorpusName,
		"missed 0 of 4 must-alert",
		"95% Wilson",
		"benign twins: 0 false fire(s) of 6",
		"declared blinds:",
		"unsigned: no key was supplied",
		"document sha256 ",
		"event-time-to-attribution",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the summary never says %q; what ran comes before how it "+
				"went, and the reader of a number needs its names", want)
		}
	}
	for _, l := range card.Scenarios {
		if !strings.Contains(s, l.ID) {
			t.Errorf("the summary never names scenario %s", l.ID)
		}
		if !strings.Contains(s, l.Twin) {
			t.Errorf("the summary never names twin %s", l.Twin)
		}
	}
}

// A note that wraps stays under what it is a note about: every line after
// the first is hung inside the lead's own indent, whatever depth that is,
// no line is wider than the terminal it was broken for unless one word is,
// and no word is lost or added on the way.
func TestAWrappedNoteHangsUnderItsLead(t *testing.T) {
	note := strings.Repeat("counting events over a window is a different question from matching one ", 4)
	for _, lead := range []string{"  ", "        ", "      refused \"a rule\": ", "  scoring blind: "} {
		got := hang(lead, note)
		lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
		if len(lines) < 3 || !strings.HasPrefix(lines[0], lead) || !strings.HasSuffix(got, "\n") {
			t.Fatalf("lead %q: %q", lead, got)
		}
		indent := len(lead) - len(strings.TrimLeft(lead, " "))
		for _, l := range lines[1:] {
			if in := len(l) - len(strings.TrimLeft(l, " ")); in != indent+2 {
				t.Errorf("lead %q: a continuation line is indented %d, want %d: %q", lead, in, indent+2, l)
			}
		}
		for _, l := range lines {
			if len(l) > 78 {
				t.Errorf("lead %q: a line is %d wide: %q", lead, len(l), l)
			}
		}
		if a, b := strings.Fields(got), strings.Fields(lead+note); strings.Join(a, " ") != strings.Join(b, " ") {
			t.Errorf("lead %q: the words changed", lead)
		}
	}
	if got := hang("  ", ""); got != "\n" {
		t.Errorf("nothing to say: %q", got)
	}
}
