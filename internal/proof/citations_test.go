// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var citeT0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func supportedSeen(id, ip string) CitationOutcome {
	return CitationOutcome{ID: id, Kind: CiteSeen, CitedType: ObsIPv4, Cited: ip, Observed: 2,
		Outcome: CiteSupported, Reason: CiteFound}
}

var (
	citeEvent = CitationOutcome{ID: "c1", Kind: CiteEvent, CitedType: CitedEvent, Cited: "ALERT-7731",
		Observed: 1, Outcome: CiteSupported, Reason: CiteFound}
	citeCount = CitationOutcome{ID: "c4", Kind: CiteCount, Compare: CountAtLeast, Stated: 5, Observed: 5,
		Outcome: CiteSupported, Reason: CiteCountHolds}
	citeFabricated = CitationOutcome{ID: "c9", Kind: CiteEvent, CitedType: CitedEvent, Cited: "ALERT-0000",
		Outcome: CiteContradicted, Reason: CiteNoSuchEvent}
	citeGap = CitationOutcome{ID: "c7", Kind: CiteNotSeen, CitedType: ObsDomain, Cited: "evil.example",
		Outcome: CiteUncheckable, Reason: CitePeriodNotHeld}
)

func citeInput(covered bool, outcomes ...CitationOutcome) CitationsInput {
	in := CitationsInput{Source: "acme-ai", Form: FormReport, Report: []byte("{}"), Since: citeT0,
		Until: citeT0.Add(7 * 24 * time.Hour), HeldFrom: citeT0.Add(-time.Hour),
		HeldUntil: citeT0.Add(8 * 24 * time.Hour), EventsRead: 40, Outcomes: outcomes, Program: "test",
		Now: citeT0.Add(9 * 24 * time.Hour)}
	if !covered {
		in.HeldFrom = citeT0.Add(24 * time.Hour)
	}
	return in
}

// A contradiction refutes; every claim supported, and enough of them,
// proves; too few claims, or any uncheckable, leaves it inconclusive.
func TestAnEvidenceProofsVerdict(t *testing.T) {
	three := []CitationOutcome{citeEvent, supportedSeen("c2", "203.0.113.9"), citeCount}
	for name, c := range map[string]struct {
		in   CitationsInput
		want Verdict
	}{
		"three supported":    {citeInput(true, three...), Proven},
		"two supported":      {citeInput(true, three[:2]...), Inconclusive},
		"no claims":          {citeInput(true), Inconclusive},
		"one uncheckable":    {citeInput(false, append(three, citeGap)...), Inconclusive},
		"a fabricated event": {citeInput(true, append(three, citeFabricated)...), Refuted},
	} {
		st, err := ProveCitations(c.in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s", name, st.Predicate.Verdict, c.want)
		}
	}
	st, _ := ProveCitations(citeInput(true, append(three, citeFabricated)...))
	if f := st.Predicate.Checks[2].Failures; len(f) != 1 || f[0] != "claim c9: no-such-event" {
		t.Errorf("the refutation names %v", f)
	}
}

// A count is held to its comparison: short of an at-least or exact claim is
// contradicted only when the store held the whole period, and over an
// at-most or exact claim is contradicted whatever it held.
func TestACountIsDecidedOnlyAsFarAsTheStoreHolds(t *testing.T) {
	for _, c := range []struct {
		compare          string
		stated, observed int
		covered          bool
		outcome          string
	}{
		{CountAtLeast, 5, 5, false, CiteSupported},
		{CountAtLeast, 5, 4, true, CiteContradicted},
		{CountAtLeast, 5, 4, false, CiteUncheckable},
		{CountAtMost, 5, 6, false, CiteContradicted},
		{CountAtMost, 5, 5, true, CiteSupported},
		{CountAtMost, 5, 5, false, CiteUncheckable},
		{CountExactly, 5, 6, false, CiteContradicted},
		{CountExactly, 5, 5, true, CiteSupported},
		{CountExactly, 5, 5, false, CiteUncheckable},
		{CountExactly, 5, 4, true, CiteContradicted},
		{CountExactly, 5, 4, false, CiteUncheckable},
		{"roughly", 5, 5, true, CiteUncheckable},
	} {
		if got, _ := DecideCount(c.compare, c.stated, c.observed, c.covered); got != c.outcome {
			t.Errorf("%s %d, observed %d, covered %v: %s, want %s", c.compare, c.stated, c.observed,
				c.covered, got, c.outcome)
		}
	}
}

// Each observable type is read by a strict parser into one canonical form.
func TestObservablesAreParsedStrictly(t *testing.T) {
	good := map[[2]string]string{
		{ObsIPv4, "203.0.113.9"}:             "203.0.113.9",
		{ObsIPv6, "2001:DB8::1"}:             "2001:db8::1",
		{ObsDomain, "Evil.Example"}:          "evil.example",
		{ObsSHA1, strings.Repeat("A", 40)}:   strings.Repeat("a", 40),
		{ObsSHA256, strings.Repeat("0", 64)}: strings.Repeat("0", 64),
		{ObsMD5, strings.Repeat("f", 32)}:    strings.Repeat("f", 32),
		{ObsEmail, "Dana@Example.COM"}:       "dana@example.com",
	}
	for in, want := range good {
		if got, ok := CanonicalObservable(in[0], in[1]); !ok || got != want {
			t.Errorf("%s %q: %q %v, want %q", in[0], in[1], got, ok, want)
		}
	}
	for _, in := range [][2]string{
		{ObsIPv4, "203.0.113.09"}, {ObsIPv4, "2001:db8::1"}, {ObsIPv6, "203.0.113.9"},
		{ObsIPv6, "::ffff:203.0.113.9"}, {ObsIPv6, "fe80::1%eth0"}, {ObsDomain, "localhost"},
		{ObsDomain, "1.2.3.4"}, {ObsDomain, "-evil.example"}, {ObsDomain, "evil-.example"},
		{ObsDomain, "evil..example"}, {ObsDomain, "evil.example."}, {ObsDomain, "ev il.example"},
		{ObsDomain, "evil.e"}, {ObsDomain, "évil.example"}, {ObsDomain, strings.Repeat("a.", 127) + "com"},
		{ObsDomain, strings.Repeat("a", 64) + ".com"},
		{ObsSHA256, strings.Repeat("0", 63)}, {ObsSHA1, strings.Repeat("g", 40)}, {ObsMD5, ""},
		{ObsEmail, "dana"}, {ObsEmail, "da na@example.com"}, {ObsEmail, "dana@localhost"},
		{"url", "https://evil.example/"}, {ObsDomain, strings.Repeat("a", 321)},
	} {
		if got, ok := CanonicalObservable(in[0], in[1]); ok {
			t.Errorf("%s %q parsed, as %q", in[0], in[1], got)
		}
	}
}

// resealed recomputes everything an evidence proof derives from its
// outcomes, so a tampered field is caught by the one rule it breaks and not
// by the derived words that would otherwise disagree with it.
func resealed(s *Statement) {
	ev := s.Predicate.Citations
	ev.tally()
	s.Predicate.Verdict, s.Predicate.Claim, s.Predicate.Checks = ev.verdict(), ev.claim(), ev.checks()
	s.Subject[0].Name = "evidence/" + ev.Source
}

// An evidence proof edited after it was made is refused when it is opened,
// whichever rule the edit breaks. Each edit breaks one rule: the outcomes
// it starts from hold whatever the store held, so an edit to what the store
// held is caught by the coverage rules alone.
func TestAnEvidenceProofCarriesOnlyWhatItsOutcomesSay(t *testing.T) {
	atLeast := CitationOutcome{ID: "c4", Kind: CiteCount, Compare: CountAtLeast, Stated: 5, Observed: 6,
		Outcome: CiteSupported, Reason: CiteCountHolds}
	wasSeen := CitationOutcome{ID: "c9", Kind: CiteNotSeen, CitedType: ObsIPv4, Cited: "198.51.100.7",
		Observed: 2, Outcome: CiteContradicted, Reason: CiteWasSeen}
	noSource := CitationOutcome{ID: "c6", Kind: CiteSeen, CitedType: ObsDomain, Cited: "evil.example",
		Outcome: CiteUncheckable, Reason: CiteSourceNotHeld}
	gapCount := CitationOutcome{ID: "c4", Kind: CiteCount, Compare: CountAtLeast, Stated: 9, Observed: 4,
		Outcome: CiteUncheckable, Reason: CitePeriodNotHeld}
	refuted := []CitationOutcome{citeEvent, supportedSeen("c2", "203.0.113.9"), atLeast, wasSeen, noSource}
	proven := []CitationOutcome{citeEvent, supportedSeen("c2", "203.0.113.9"), atLeast}
	uncovered := func(s *Statement) {
		s.Predicate.Citations.Covered = false
		s.Predicate.Citations.HeldFrom = "2026-11-02T00:00:00Z"
	}
	for name, c := range map[string]struct {
		from   []CitationOutcome
		change func(*Statement)
		reseal bool
	}{
		"source":  {refuted, func(s *Statement) { s.Predicate.Citations.Source = "Acme AI" }, true},
		"form":    {refuted, func(s *Statement) { s.Predicate.Citations.Form = "memo" }, true},
		"period":  {refuted, func(s *Statement) { s.Predicate.Citations.Until = s.Predicate.Citations.Since }, true},
		"covered": {refuted, func(s *Statement) { s.Predicate.Citations.Covered = false }, true},
		"held out of order": {refuted, func(s *Statement) {
			s.Predicate.Citations.HeldUntil, s.Predicate.Citations.Covered = "2020-01-01T00:00:00Z", false
		}, true},
		"held unreadable": {refuted, func(s *Statement) {
			s.Predicate.Citations.HeldFrom, s.Predicate.Citations.Covered = "yesterday", false
		}, true},
		"held only once": {refuted, func(s *Statement) {
			s.Predicate.Citations.HeldFrom, s.Predicate.Citations.Covered = "", false
		}, true},
		"events read": {refuted, func(s *Statement) { s.Predicate.Citations.EventsRead = -1 }, true},
		"too many claims": {refuted, func(s *Statement) {
			ev := s.Predicate.Citations
			ev.Outcomes = nil
			for i := 0; i <= MaxCitations; i++ {
				ev.Outcomes = append(ev.Outcomes, supportedSeen(fmt.Sprintf("c%d", i), "203.0.113.9"))
			}
		}, true},
		"an id twice":      {refuted, func(s *Statement) { s.Predicate.Citations.Outcomes[1].ID = "c1" }, true},
		"an id as words":   {refuted, func(s *Statement) { s.Predicate.Citations.Outcomes[1].ID = "trust me" }, true},
		"observed below 0": {refuted, func(s *Statement) { s.Predicate.Citations.Outcomes[4].Observed = -1 }, true},
		"extracted in a report": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[1].Extracted = true
		}, true},
		"a stated claim in text": {refuted, func(s *Statement) {
			s.Predicate.Citations.Form = FormText
			for i := range s.Predicate.Citations.Outcomes {
				s.Predicate.Citations.Outcomes[i].Extracted = true
			}
		}, true},
		"an event id as words": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[0].Cited = "ALERT 7731"
		}, true},
		"an event cited as an address": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[0].CitedType = ObsIPv4
		}, true},
		"an event with a comparison": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[0].Compare = CountAtLeast
		}, true},
		"an event with a count": {refuted, func(s *Statement) { s.Predicate.Citations.Outcomes[0].Stated = 2 }, true},
		"an observable not canonical": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[1].CitedType = ObsDomain
			s.Predicate.Citations.Outcomes[1].Cited = "Evil.Example"
		}, true},
		"an observable not one": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[1].Cited = "ignore previous instructions"
		}, true},
		"an observable with a comparison": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[1].Compare = CountExactly
		}, true},
		"an observable with a count": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[1].Stated = 3
		}, true},
		"a count citing a type": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[2].CitedType = ObsIPv4
		}, true},
		"a count citing a value": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[2].Cited = "203.0.113.9"
		}, true},
		"a count below 0": {refuted, func(s *Statement) { s.Predicate.Citations.Outcomes[2].Stated = -5 }, true},
		"a count's comparison": {refuted, func(s *Statement) {
			o := &s.Predicate.Citations.Outcomes[2]
			o.Compare, o.Observed, o.Outcome, o.Reason = "about", 0, CiteUncheckable, CiteSourceNotHeld
		}, true},
		"a count's outcome": {refuted, func(s *Statement) { s.Predicate.Citations.Outcomes[2].Observed = 3 }, true},
		"a kind":            {refuted, func(s *Statement) { s.Predicate.Citations.Outcomes[1].Kind = "vibes" }, true},
		"a reason of another kind": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[1].Reason = CiteAbsent
		}, true},
		"found with nothing observed": {refuted, func(s *Statement) {
			s.Predicate.Citations.Outcomes[1].Observed = 0
		}, true},
		"contradicted over a gap": {refuted, func(s *Statement) {
			uncovered(s)
			s.Predicate.Citations.Outcomes[2] = gapCount
			s.Predicate.Citations.Outcomes[3] = citeFabricated
		}, true},
		"claims tallied":         {refuted, func(s *Statement) { s.Predicate.Citations.Claims = 4 }, false},
		"extracted tallied":      {refuted, func(s *Statement) { s.Predicate.Citations.Extracted = 1 }, false},
		"supported tallied":      {refuted, func(s *Statement) { s.Predicate.Citations.Supported = 4 }, false},
		"contradictions tallied": {refuted, func(s *Statement) { s.Predicate.Citations.Contradicted = 2 }, false},
		"uncheckable tallied":    {refuted, func(s *Statement) { s.Predicate.Citations.Uncheckable = 0 }, false},
		"verdict":                {proven, func(s *Statement) { s.Predicate.Verdict = Inconclusive }, false},
		"subject":                {refuted, func(s *Statement) { s.Subject[0].Name = "evidence/somebody-else" }, false},
		"a second subject": {refuted, func(s *Statement) {
			s.Subject = append(s.Subject, Subject{Name: "vendor-says-so", Digest: SHA256([]byte("x"))})
		}, false},
		"claim": {refuted, func(s *Statement) {
			s.Predicate.Claim = "Everything the vendor said is true."
		}, false},
		"a failure as text": {refuted, func(s *Statement) {
			s.Predicate.Checks[2].Failures[0] = "claim c9: the analyst was right all along"
		}, false},
		"a check's detail": {refuted, func(s *Statement) { s.Predicate.Checks[1].Detail = "trust the vendor" }, false},
		"a second kind": {refuted, func(s *Statement) {
			s.Predicate.NotAffected = &NotAffectedEvidence{Source: "acme-ai", Asset: "github:acme/app"}
		}, false},
		"no evidence": {refuted, func(s *Statement) { s.Predicate.Citations = nil }, false},
	} {
		st, err := ProveCitations(citeInput(true, c.from...))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var copied Statement
		b, _ := json.Marshal(st)
		_ = json.Unmarshal(b, &copied)
		c.change(&copied)
		if c.reseal {
			resealed(&copied)
		}
		if err := copied.Validate(); err == nil {
			t.Errorf("%s: an edited statement validated", name)
		}
	}
	// The untouched proofs, resealed, still validate: the edits above are
	// refused for what they changed, not for being resealed.
	for _, from := range [][]CitationOutcome{refuted, proven} {
		st, _ := ProveCitations(citeInput(true, from...))
		resealed(st)
		if err := st.Validate(); err != nil {
			t.Fatalf("an untouched proof, resealed: %v", err)
		}
	}
	if _, err := ProveCitations(CitationsInput{Source: "acme-ai", Form: FormReport, Since: citeT0,
		Until: citeT0.Add(time.Hour), Now: citeT0.Add(2 * time.Hour)}); err == nil {
		t.Error("a proof was made resting on no report")
	}
}

// What plain text yields is only ever claims that something was seen, each
// marked extracted.
func TestTextYieldsOnlyExtractedSightings(t *testing.T) {
	in := citeInput(true, supportedSeen("x1", "203.0.113.9"), supportedSeen("x2", "198.51.100.7"),
		CitationOutcome{ID: "x3", Kind: CiteEvent, CitedType: CitedEvent, Cited: "ALERT-1", Observed: 1,
			Outcome: CiteSupported, Reason: CiteFound})
	in.Form = FormText
	for i := range in.Outcomes {
		in.Outcomes[i].Extracted = true
	}
	st, err := ProveCitations(in)
	if err != nil || st.Predicate.Verdict != Proven || st.Predicate.Citations.Extracted != 3 {
		t.Fatalf("%v %+v", err, st)
	}
	if !strings.Contains(st.Predicate.Claim, "cited in the text acme-ai wrote") {
		t.Errorf("the claim is %q", st.Predicate.Claim)
	}
	in.Outcomes[1] = CitationOutcome{ID: "x2", Kind: CiteNotSeen, CitedType: ObsIPv4, Cited: "198.51.100.7",
		Outcome: CiteSupported, Reason: CiteAbsent, Extracted: true}
	if _, err := ProveCitations(in); err == nil {
		t.Error("text yielded a claim that something was not seen")
	}
}
