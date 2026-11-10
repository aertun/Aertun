// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var at0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func adjInput(k, n int, tolerance float64) AdjudicationInput {
	in := AdjudicationInput{Source: "charlotte", Since: at0, Until: at0.Add(30 * 24 * time.Hour),
		Tolerance: tolerance, SampleFile: []byte("{}"), Sample: "0123456789abcdef",
		Committed:    AuditEntry{Seq: 40, Hash: strings.Repeat("ab", 32), At: "2026-11-01T09:00:00Z"},
		PopulationAI: 4000, PopulationHuman: 900, Reviewers: 2,
		AI: Count{K: k, N: n}, Human: Count{K: 1, N: 100}, RealHuman: []int{7},
		Program: "test", Now: at0.Add(40 * 24 * time.Hour)}
	for i := range k {
		in.RealAI = append(in.RealAI, 100+i)
	}
	return in
}

// The AI's rate on the blind sample is read against the tolerance; the
// people's is reported beside it and decides nothing.
func TestAnAdjudicationsVerdict(t *testing.T) {
	for _, c := range []struct {
		k, n      int
		tolerance float64
		want      Verdict
	}{
		{0, 300, 0.01, Proven}, {12, 300, 0.01, Refuted}, {2, 300, 0.01, Inconclusive},
		{0, 20, 0.01, Inconclusive},
	} {
		st, err := ProveAdjudication(adjInput(c.k, c.n, c.tolerance))
		if err != nil {
			t.Fatalf("%d of %d: %v", c.k, c.n, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%d of %d at %v is %s, want %s", c.k, c.n, c.tolerance, st.Predicate.Verdict, c.want)
		}
	}
	st, _ := ProveAdjudication(adjInput(12, 300, 0.01))
	fc := st.Predicate.Checks[1]
	if len(fc.Failures) != 12 || fc.Failures[0] != "ai item 100 judged real" {
		t.Errorf("the refutation names %v", fc.Failures)
	}
	if !strings.Contains(st.Predicate.Checks[2].Detail, "1 of 100 sampled closures by people") {
		t.Errorf("the people's rate is not reported: %s", st.Predicate.Checks[2].Detail)
	}
}

// An adjudication edited after it was made is refused when opened.
func TestAnAdjudicationCarriesOnlyWhatItsNumbersSay(t *testing.T) {
	st, err := ProveAdjudication(adjInput(12, 300, 0.01))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Statement){
		"verdict":            func(s *Statement) { s.Predicate.Verdict = Inconclusive },
		"claim":              func(s *Statement) { s.Predicate.Claim += " Trust the AI." },
		"a count":            func(s *Statement) { s.Predicate.Adjudication.AI.K = 0 },
		"a failure as text":  func(s *Statement) { s.Predicate.Checks[1].Failures[0] = "ai item 100 was fine" },
		"a people's item":    func(s *Statement) { s.Predicate.Checks[1].Failures[0] = "human item 7 judged real" },
		"no reviewer":        func(s *Statement) { s.Predicate.Adjudication.Reviewers = 0 },
		"more than drawn":    func(s *Statement) { s.Predicate.Adjudication.PopulationAI = 10 },
		"an uncommitted one": func(s *Statement) { s.Predicate.Adjudication.Committed.Seq = 0 },
	} {
		var copied Statement
		b, _ := json.Marshal(st)
		_ = json.Unmarshal(b, &copied)
		change(&copied)
		if copied.Validate() == nil {
			t.Errorf("%s: an edited statement validated", name)
		}
	}
}
