// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"testing"
	"time"
)

func naInput(supported, uncheckable int, contradictions ...VEXContradiction) NotAffectedInput {
	reasons := map[string]int{}
	if supported > 0 {
		reasons[VEXVersionOutside] = supported
	}
	if uncheckable > 0 {
		reasons[VEXNotNamedDirectly] = uncheckable
	}
	return NotAffectedInput{Source: "acme-scanner", Asset: "github:acme/app", Document: []byte("{}"),
		Statements: 10, NotAffected: supported + uncheckable + len(contradictions),
		Supported: supported, Uncheckable: uncheckable, Reasons: reasons, Contradictions: contradictions,
		Program: "test", Now: time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)}
}

var contra = VEXContradiction{Advisory: "GHSA-aaaa-bbbb-cccc", Component: "go:github.com/x/lib",
	Reason: VEXSymbolReferenced}

// A contradiction refutes; every statement supported proves; anything
// uncheckable leaves it inconclusive.
func TestANotAffectedProofsVerdict(t *testing.T) {
	for name, c := range map[string]struct {
		in   NotAffectedInput
		want Verdict
	}{
		"all supported":   {naInput(3, 0), Proven},
		"one uncheckable": {naInput(3, 1), Inconclusive},
		"nothing checked": {naInput(0, 0), Inconclusive},
		"a contradiction": {naInput(3, 0, contra), Refuted},
	} {
		st, err := ProveNotAffected(c.in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s", name, st.Predicate.Verdict, c.want)
		}
	}
	st, _ := ProveNotAffected(naInput(3, 0, contra))
	if f := st.Predicate.Checks[1].Failures; len(f) != 1 ||
		f[0] != "contradicted: GHSA-aaaa-bbbb-cccc in go:github.com/x/lib, symbol-referenced" {
		t.Errorf("the refutation names %v", f)
	}
}

// A not-affected proof edited after it was made is refused when opened.
func TestANotAffectedProofCarriesOnlyWhatItsCountsSay(t *testing.T) {
	st, err := ProveNotAffected(naInput(3, 1, contra))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Statement){
		"verdict":           func(s *Statement) { s.Predicate.Verdict = Inconclusive },
		"a reason":          func(s *Statement) { s.Predicate.NotAffected.Reasons[0].Reason = "vendor-says-so" },
		"a failure as text": func(s *Statement) { s.Predicate.Checks[1].Failures[0] = "contradicted: trust me" },
		"a supported reason as a contradiction": func(s *Statement) {
			s.Predicate.Checks[1].Failures[0] = "contradicted: GHSA-aaaa in go:x, version-outside"
		},
		"a count": func(s *Statement) { s.Predicate.NotAffected.Supported = 4 },
		"a contradiction dropped": func(s *Statement) {
			s.Predicate.NotAffected.Contradicted = 0
			s.Predicate.Checks[1].Failures = nil
		},
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
