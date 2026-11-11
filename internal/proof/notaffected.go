// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// A not-affected proof: a VEX document's "not affected" statements about one
// asset, held against this program's bill of materials, advisories and
// reachability analysis for it (internal/vexcheck).
//
// Vendors, scanners and AI triage tools close vulnerability alerts with
// statements nobody checks. Each statement here comes to one of three
// things, for a reason in a closed set of words: contradicted by the
// evidence, supported by evidence that could have contradicted it, or
// uncheckable. The proof is refuted when any is contradicted, and names
// them; proven only when every one was checked and supported; inconclusive
// otherwise — which is what most documents will be, because most statements
// say something this program cannot test, and saying so is the point.

// NotAffectedVerifier and its version name this verifier.
const (
	NotAffectedVerifier        = "aertun/not-affected"
	NotAffectedVerifierVersion = "1"
)

// PredicateNotAffected is the predicate of a not-affected proof.
const PredicateNotAffected = "https://aertun.github.io/proof/not-affected/v1"

// The reasons a statement comes to what it does: contradicted, supported or
// uncheckable. internal/vexcheck takes them from here, so a reason it gives
// is one a proof may carry.
const (
	VEXComponentPresent  = "component-present"
	VEXVulnerableVersion = "vulnerable-version"
	VEXSymbolReferenced  = "symbol-referenced"
	VEXVersionOutside    = "version-outside"
	VEXNotInTheBill      = "not-in-the-bill"
	VEXNoAdvisory        = "no-advisory-here"
	VEXNoPackage         = "no-package-named"
	VEXNoBill            = "no-bill-for-the-asset"
	VEXVersionUndecided  = "version-undecided"
	VEXBackported        = "distribution-backports"
	VEXNotAnalysed       = "reach-not-analysed"
	VEXNotNamedDirectly  = "not-named-directly"
	VEXNotCheckable      = "justification-not-checkable"
)

// VEXReasons are every reason, contradicting ones first.
func VEXReasons() []string {
	return []string{VEXComponentPresent, VEXVulnerableVersion, VEXSymbolReferenced,
		VEXVersionOutside, VEXNotInTheBill, VEXNoAdvisory, VEXNoPackage, VEXNoBill,
		VEXVersionUndecided, VEXBackported, VEXNotAnalysed, VEXNotNamedDirectly, VEXNotCheckable}
}

var vexContradicts = map[string]bool{VEXComponentPresent: true, VEXVulnerableVersion: true,
	VEXSymbolReferenced: true}

// ReasonCount is how many statement-and-package pairs came to one reason.
type ReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// NotAffectedEvidence is what the statements came to, as counts.
type NotAffectedEvidence struct {
	// Source is the operator's short name for whoever wrote the document;
	// Asset the asset it is about, as its bill was imported under.
	Source string `json:"source"`
	Asset  string `json:"asset"`
	// Statements is every statement the document made, NotAffected those
	// tested, and Checked the statement-and-package pairs they came to.
	Statements   int           `json:"statements"`
	NotAffected  int           `json:"not_affected"`
	Checked      int           `json:"checked"`
	Supported    int           `json:"supported"`
	Contradicted int           `json:"contradicted"`
	Uncheckable  int           `json:"uncheckable"`
	Reasons      []ReasonCount `json:"reasons"`
}

// VEXContradiction names one contradicted statement.
type VEXContradiction struct {
	Advisory, Component, Reason string
}

// NotAffectedInput is what a not-affected proof is made from.
type NotAffectedInput struct {
	Source, Asset string
	// Document is the VEX document as read: what the subject's digest is
	// over.
	Document                []byte
	Statements, NotAffected int
	Supported, Uncheckable  int
	Reasons                 map[string]int
	Contradictions          []VEXContradiction
	Materials               []Material
	Program                 string
	Now                     time.Time
}

var (
	assetShape     = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}:[!-~]{1,256}$`)
	advisoryShape  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	componentShape = regexp.MustCompile(`^[a-z0-9][a-z0-9. -]{0,31}:[!-~]{1,256}$`)
)

func vexFailure(c VEXContradiction) string {
	return "contradicted: " + c.Advisory + " in " + c.Component + ", " + c.Reason
}

func validVEXFailure(s string) bool {
	rest, ok := strings.CutPrefix(s, "contradicted: ")
	if !ok {
		return false
	}
	adv, rest, ok := strings.Cut(rest, " in ")
	if !ok || !advisoryShape.MatchString(adv) {
		return false
	}
	i := strings.LastIndex(rest, ", ")
	if i < 0 {
		return false
	}
	return componentShape.MatchString(rest[:i]) && vexContradicts[rest[i+2:]]
}

// ProveNotAffected builds the unsigned statement.
func ProveNotAffected(in NotAffectedInput) (*Statement, error) {
	if !ValidVerdictSource(in.Source) || !assetShape.MatchString(in.Asset) {
		return nil, fmt.Errorf("a not-affected proof names who wrote the document and the asset it is about")
	}
	if len(in.Document) == 0 {
		return nil, fmt.Errorf("a not-affected proof rests on the document it checked")
	}
	reasons := map[string]int{}
	for k, v := range in.Reasons {
		reasons[k] = v
	}
	for _, c := range in.Contradictions {
		reasons[c.Reason]++
	}
	ev := &NotAffectedEvidence{Source: in.Source, Asset: in.Asset, Statements: in.Statements,
		NotAffected: in.NotAffected, Supported: in.Supported, Uncheckable: in.Uncheckable,
		Contradicted: len(in.Contradictions)}
	ev.Checked = ev.Supported + ev.Uncheckable + ev.Contradicted
	for _, r := range VEXReasons() {
		if n := reasons[r]; n > 0 {
			ev.Reasons = append(ev.Reasons, ReasonCount{Reason: r, Count: n})
		}
	}
	var failures []string
	for _, c := range in.Contradictions {
		failures = append(failures, vexFailure(c))
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "vex/" + in.Source, Digest: SHA256(in.Document)}},
		PredicateType: PredicateNotAffected,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: NotAffectedVerifier, Version: NotAffectedVerifierVersion,
				Program: in.Program},
			Materials:   append([]Material{}, in.Materials...),
			Checks:      ev.checks(failures),
			NotAffected: ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *NotAffectedEvidence) claim() string {
	return fmt.Sprintf("Every not_affected statement %s made about %s holds against this "+
		"program's bill of materials, advisories and reachability analysis for it.", ev.Source, ev.Asset)
}

func (ev *NotAffectedEvidence) verdict() Verdict {
	switch {
	case ev.Contradicted > 0:
		return Refuted
	case ev.Checked > 0 && ev.Supported == ev.Checked:
		return Proven
	}
	return Inconclusive
}

func (ev *NotAffectedEvidence) checks(failures []string) []Check {
	read := Check{Name: "read", Passed: true,
		Detail: fmt.Sprintf("%d statement(s), %d of them not_affected, about %d package(s) in all; "+
			"the rest were not tested", ev.Statements, ev.NotAffected, ev.Checked)}
	var parts []string
	for _, r := range ev.Reasons {
		parts = append(parts, fmt.Sprintf("%d %s", r.Count, r.Reason))
	}
	held := Check{Name: "held-to-the-evidence", Passed: ev.Contradicted == 0,
		Detail: fmt.Sprintf("%d supported, %d contradicted, %d uncheckable (%s)", ev.Supported,
			ev.Contradicted, ev.Uncheckable, strings.Join(parts, ", "))}
	shown, more := capped(failures)
	held.Failures = shown
	if more > 0 {
		held.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	return []Check{read, held}
}

func (ev *NotAffectedEvidence) validate(s *Statement) error {
	if !ValidVerdictSource(ev.Source) || !assetShape.MatchString(ev.Asset) {
		return fmt.Errorf("a not-affected proof names who wrote the document and the asset it is about")
	}
	order := map[string]int{}
	for i, r := range VEXReasons() {
		order[r] = i + 1
	}
	last, contradicting, supporting, total := 0, 0, 0, 0
	for _, r := range ev.Reasons {
		at := order[r.Reason]
		if at == 0 || at <= last || r.Count <= 0 {
			return fmt.Errorf("a reason is not one this version has, is out of order, or counts nothing")
		}
		last = at
		total += r.Count
		switch {
		case vexContradicts[r.Reason]:
			contradicting += r.Count
		case r.Reason == VEXVersionOutside:
			supporting += r.Count
		}
	}
	if ev.Statements < ev.NotAffected || ev.NotAffected < 0 || ev.Supported < 0 || ev.Uncheckable < 0 ||
		ev.Checked != ev.Supported+ev.Contradicted+ev.Uncheckable || total != ev.Checked ||
		contradicting != ev.Contradicted || supporting != ev.Supported {
		return fmt.Errorf("the statements' counts do not add up")
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the counts make this %s, not %s", want, s.Predicate.Verdict)
	}
	var failures []string
	for _, c := range s.Predicate.Checks {
		for _, f := range c.Failures {
			if c.Name != "held-to-the-evidence" || !validVEXFailure(f) {
				return fmt.Errorf("a failure in a not-affected proof names an advisory, a package " +
					"and a reason, and nothing else")
			}
			failures = append(failures, f)
		}
	}
	if len(failures) != min(ev.Contradicted, MaxFailures) {
		return fmt.Errorf("the failures listed are not the contradictions counted")
	}
	failures = append(failures, make([]string, ev.Contradicted-len(failures))...)
	return sameWords(s, "vex/"+ev.Source, ev.claim(), ev.checks(failures))
}
