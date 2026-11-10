// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func claimInput(k, n int, closed bool) ClaimInput {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return ClaimInput{Name: "charlotte-98", Card: strings.Repeat("cd", 32), Source: "charlotte",
		Metric: "agreement", Direction: "at-least", Threshold: 0.98, Confidence: 0.95,
		Labels:      LabelsPeople,
		Registered:  AuditEntry{Seq: 12, Hash: strings.Repeat("ab", 32), At: "2026-10-01T00:00:00Z"},
		WindowStart: start, WindowEnd: start.Add(30 * 24 * time.Hour), Closed: closed,
		Count: Count{K: k, N: n}, CardFile: []byte("{}"), Program: "test", Now: start.Add(31 * 24 * time.Hour)}
}

// A claim is decided on its own bound, at its own confidence, and only once
// its window has closed.
func TestAClaimsVerdict(t *testing.T) {
	for _, c := range []struct {
		k, n   int
		closed bool
		want   Verdict
	}{
		{995, 1000, true, Proven}, {900, 1000, true, Refuted}, {980, 1000, true, Inconclusive},
		{995, 1000, false, Inconclusive}, {900, 1000, false, Inconclusive}, {29, 29, true, Inconclusive},
	} {
		st, err := ProveClaim(claimInput(c.k, c.n, c.closed))
		if err != nil {
			t.Fatalf("%d of %d: %v", c.k, c.n, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%d of %d, closed %v: %s, want %s", c.k, c.n, c.closed, st.Predicate.Verdict, c.want)
		}
	}
	st, _ := ProveClaim(claimInput(995, 1000, true))
	if !strings.Contains(st.Predicate.Claim, "registered at audit entry 12 before any of that data arrived") {
		t.Errorf("the claim does not say when it was registered: %s", st.Predicate.Claim)
	}
}

// A claim proof edited after it was made is refused when opened.
func TestAClaimProofCarriesOnlyWhatItsCountSays(t *testing.T) {
	st, err := ProveClaim(claimInput(900, 1000, true))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Statement){
		"verdict":    func(s *Statement) { s.Predicate.Verdict = Proven },
		"count":      func(s *Statement) { s.Predicate.ClaimTest.K = 999 },
		"threshold":  func(s *Statement) { s.Predicate.ClaimTest.Threshold = 0.85 },
		"still open": func(s *Statement) { s.Predicate.ClaimTest.Closed = false },
		"a metric":   func(s *Statement) { s.Predicate.ClaimTest.Metric = "accuracy" },
		"a failure":  func(s *Statement) { s.Predicate.Checks[1].Failures = []string{"see vendor deck"} },
		"claim":      func(s *Statement) { s.Predicate.Claim = "The vendor is right." },
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
