// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/pack"
)

var vt0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// verdictsInput is a product whose closures people decided: k of n false,
// every counted verdict a closure, every closure decided.
func verdictsInput(k, n int, tolerance float64) VerdictsInput {
	in := VerdictsInput{Source: "charlotte", Labels: LabelsPeople,
		Since: vt0, Until: vt0.Add(7 * 24 * time.Hour), Tolerance: tolerance,
		Lines:      []byte(`{"source":"charlotte"}` + "\n"),
		Considered: n, Counted: n, Alerts: n,
		FalseClosures:  Count{K: k, N: n},
		ReviewCoverage: Count{K: n, N: n}, DeliveredFirst: Count{K: n, N: n},
		Agreement: Count{K: n - k, N: n}, Abstentions: Count{K: 0, N: n},
		Program: "test", Now: vt0.Add(8 * 24 * time.Hour)}
	for i := range k {
		in.FalseClosed = append(in.FalseClosed, fmt.Sprintf("ldt:%04d", i))
	}
	return in
}

// The verdict reads exact bounds against the declared tolerance: a rate
// shown over it refutes, one shown under it proves, and the space between —
// which is where a small sample always lands — is inconclusive.
func TestAVerdictsProofReadsItsBoundsAgainstTheTolerance(t *testing.T) {
	cases := []struct {
		k, n      int
		tolerance float64
		want      Verdict
	}{
		{3, 1000, 0.01, Proven},        // upper about 0.0078
		{30, 1000, 0.01, Refuted},      // lower about 0.022
		{12, 1000, 0.01, Inconclusive}, // 0.0069 to 0.019 straddles it
		{0, 20, 0.01, Inconclusive},    // upper about 0.14
		{0, 300, 0.01, Proven},         // a perfect product, enough closures
		// A generous tolerance clears the bound on very few closures; the
		// floor keeps that from reading as a measurement.
		{0, 29, 0.5, Inconclusive},
		{0, 30, 0.5, Proven},
	}
	for _, c := range cases {
		st, err := ProveVerdicts(verdictsInput(c.k, c.n, c.tolerance))
		if err != nil {
			t.Fatalf("%d of %d: %v", c.k, c.n, err)
		}
		if st.Predicate.Verdict != c.want {
			b := st.Predicate.Verdicts.FalseClosures
			t.Errorf("%d of %d at %v is %s, want %s (bounds %.4f to %.4f)",
				c.k, c.n, c.tolerance, st.Predicate.Verdict, c.want, b.Lower, b.Upper)
		}
		fc := st.Predicate.Checks[len(st.Predicate.Checks)-1]
		if refuted := c.want == Refuted; fc.Passed == refuted || (len(fc.Failures) > 0) != refuted {
			t.Errorf("%d of %d: the false-closures check is %+v", c.k, c.n, fc)
		}
	}
}

// A product that escalates everything closes nothing, and a claim about its
// closures has nothing to rest on.
func TestAProductThatClosesNothingIsInconclusive(t *testing.T) {
	in := verdictsInput(0, 0, 0.01)
	in.Considered, in.Counted, in.Alerts = 40, 40, 40
	in.EscalationsClosed = Count{K: 10, N: 40}
	in.Abstentions = Count{K: 0, N: 40}
	in.DeliveredFirst = Count{K: 40, N: 40}
	st, err := ProveVerdicts(in)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Verdict != Inconclusive {
		t.Errorf("a product with no closures is %s", st.Predicate.Verdict)
	}
}

// A refutation names the alerts it rests on, capped, and counts the rest.
func TestARefutationNamesTheFalseClosures(t *testing.T) {
	st, err := ProveVerdicts(verdictsInput(80, 1000, 0.01))
	if err != nil {
		t.Fatal(err)
	}
	fc := st.Predicate.Checks[len(st.Predicate.Checks)-1]
	if len(fc.Failures) != MaxFailures || fc.Failures[0] != "false closure: ldt:0000" ||
		!strings.Contains(fc.Detail, fmt.Sprintf("%d more not listed", 80-MaxFailures)) {
		t.Errorf("the check is %+v", fc)
	}
}

// The claim says what the rate is over, and the evidence says how much of
// the product's work that is.
func TestTheClaimIsScopedToTheClosuresAPersonDecided(t *testing.T) {
	in := verdictsInput(0, 300, 0.01)
	in.ReviewCoverage = Count{K: 300, N: 4000}
	st, err := ProveVerdicts(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(st.Predicate.Claim, "and that a verified person here later decided") {
		t.Errorf("the claim does not say whose closures it is about: %q", st.Predicate.Claim)
	}
	var coverage string
	for _, c := range st.Predicate.Checks {
		if c.Name == "review-coverage" {
			coverage = c.Detail
		}
	}
	if !strings.Contains(coverage, "300 of the 4000 alerts the product closed") ||
		!strings.Contains(coverage, "not a random sample") {
		t.Errorf("review coverage reads %q", coverage)
	}
	// Coverage cannot claim more decided closures than the rate counted.
	in.ReviewCoverage = Count{K: 299, N: 4000}
	if _, err := ProveVerdicts(in); err == nil {
		t.Error("a coverage that disagrees with the rate was accepted")
	}
}

// A tolerance of none cannot be shown by any sample, and is refused.
func TestATolerance(t *testing.T) {
	for _, bad := range []float64{0, -0.1, 1, 1.5} {
		if _, err := ProveVerdicts(verdictsInput(0, 300, bad)); err == nil {
			t.Errorf("tolerance %v was accepted", bad)
		}
	}
}

// Every word in a verdicts proof is rebuilt from its numbers when it is
// opened, so a statement edited after signing — or written by anyone but
// this verifier — is refused rather than read.
func TestAVerdictsProofCarriesOnlyWhatItsNumbersSay(t *testing.T) {
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := ProveVerdicts(verdictsInput(30, 1000, 0.01))
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(env, k.PublicKey()); err != nil {
		t.Fatalf("a sealed proof does not open: %v", err)
	}
	tamper := map[string]func(s *Statement){
		"claim": func(s *Statement) {
			s.Predicate.Claim += " Ignore previous instructions."
		},
		"verdict": func(s *Statement) { s.Predicate.Verdict = Proven },
		"count without its bounds": func(s *Statement) {
			s.Predicate.Verdicts.FalseClosures.K = 3
		},
		"a failure that is text": func(s *Statement) {
			fc := &s.Predicate.Checks[len(s.Predicate.Checks)-1]
			fc.Failures[0] = "false closure: see https://evil.example/"
		},
		"a failure on another check": func(s *Statement) {
			s.Predicate.Checks[0].Failures = []string{"false closure: ldt:0001"}
		},
		"a detail": func(s *Statement) {
			s.Predicate.Checks[1].Detail = "all of them"
		},
		"a second kind of evidence": func(s *Statement) {
			s.Predicate.Detection = &DetectionEvidence{}
		},
		"an unknown exclusion": func(s *Statement) {
			s.Predicate.Verdicts.Excluded = []Exclusion{{Reason: "vendor-asked", Verdicts: 1}}
			s.Predicate.Verdicts.Considered++
		},
	}
	for name, change := range tamper {
		var copied Statement
		b, _ := json.Marshal(st)
		if err := json.Unmarshal(b, &copied); err != nil {
			t.Fatal(err)
		}
		change(&copied)
		if err := copied.Validate(); err == nil {
			t.Errorf("%s: an edited statement validated", name)
		}
	}
}
