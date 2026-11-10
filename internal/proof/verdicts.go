// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// A verdicts proof: what another vendor's AI said about alerts, scored
// against what people decided about the same alerts.
//
// # The claim
//
// One rate leads, because it is the error that costs: a false closure, an
// alert the product closed as false-positive or benign that a person found
// real — one minus the reliability of its closures. The operator declares
// the tolerance the product is held to before the proof is made, and the
// verdict reads the exact one-sided bounds against it:
//
//   - refuted when the lower bound is over the tolerance: the product closes
//     real alerts more often than that, and the refutation names them;
//   - proven when the upper bound is at or under it, on at least MinSample
//     closures;
//   - inconclusive between, which is what too few closures always give.
//
// A claim of no false closures at all is not offered. Any product at volume
// makes one in the end, so that claim would refute every product and tell
// none of them apart.
//
// # What the rate is over
//
// Closures a person later decided. People do not re-examine a random sample
// of what an AI closed — they look at what looked wrong, or what arrived on a
// quiet day — so the rate over those is not the product's rate over all its
// closures, and the claim says so in its own words. Review coverage, the
// share of its closures somebody decided, is a number in the evidence. The
// unbiased rate over all closures needs a sample drawn at random and judged
// blind, which is a different proof.
//
// # Whose clock
//
// A verdict counts only if it was given before the disposition, because a
// product that learns from analysts and answers after them agrees with
// them. The time it was given is the product's own word; the evidence also
// counts how many counted verdicts were delivered here before the
// disposition, which is a time this program stamped and the vendor cannot
// move. A file imported in one batch after the fact has none, and says so.
//
// # What is in it
//
// Nothing a vendor or an attacker wrote. Its words are this package's closed
// sets, its names are the operator's short name for the product and alert
// ids in the one shape they are kept in, and everything else is a number.
// The claim and the checks are rebuilt from the evidence when a statement is
// validated, so a statement carrying any other text is refused.

// VerdictsVerifier and VerdictsVerifierVersion name this verifier.
const (
	VerdictsVerifier        = "aertun/verdicts"
	VerdictsVerifierVersion = "1"
)

// Where the dispositions came from.
const (
	// LabelsPeople are decisions verified people recorded here.
	LabelsPeople = "aertun-decisions"
	// LabelsReported are dispositions the vendor's export reports, which
	// nothing here can check.
	LabelsReported = "source-reported"
)

// Count is k of n, before any bound is put on it.
type Count struct{ K, N int }

// VerdictsEvidence is the score, with the counts behind every rate.
type VerdictsEvidence struct {
	Source    string  `json:"source"`
	Labels    string  `json:"labels"`
	Since     string  `json:"since"`
	Until     string  `json:"until"`
	Tolerance float64 `json:"tolerance"`
	// Considered are the product's verdicts in the period; each is either
	// Counted or in Excluded with its reason.
	Considered int         `json:"considered"`
	Counted    int         `json:"counted"`
	Excluded   []Exclusion `json:"excluded"`
	// Alerts are the alerts at least one counted verdict was about.
	Alerts      int `json:"alerts"`
	MinClosures int `json:"min_closures"`
	// FalseClosures is closing answers on alerts a person found real, of
	// the closing answers a person decided: the rate the verdict reads.
	FalseClosures Bound `json:"false_closures"`
	// ReviewCoverage is the closures a person decided, of every alert the
	// product closed in the period that this store could link.
	ReviewCoverage Rate `json:"review_coverage"`
	// DeliveredFirst is the counted verdicts delivered here before the
	// disposition, of all counted.
	DeliveredFirst    Rate `json:"delivered_before_disposition"`
	Agreement         Rate `json:"agreement"`
	EscalationsClosed Rate `json:"escalations_closed"`
	Abstentions       Rate `json:"abstentions"`
	Consistency       Rate `json:"consistency"`
}

// VerdictsInput is what a verdicts proof is made from.
type VerdictsInput struct {
	Source       string
	Labels       string
	Since, Until time.Time
	Tolerance    float64
	// Lines are the considered verdicts, one JSON object per line, in the
	// order they were scored: what the subject's digest is over.
	Lines []byte

	Considered, Counted, Alerts int
	Excluded                    map[string]int
	FalseClosures               Count
	// FalseClosed are the ids of the falsely closed alerts, sorted.
	FalseClosed []string
	ReviewCoverage, DeliveredFirst, Agreement, EscalationsClosed,
	Abstentions, Consistency Count

	// Materials are what else was read: the audit log's head, and the
	// finding register when the labels are people's decisions.
	Materials []Material
	Program   string
	Now       time.Time
}

// ProveVerdicts builds the unsigned statement.
func ProveVerdicts(in VerdictsInput) (*Statement, error) {
	if !ValidVerdictSource(in.Source) || !knownLabels(in.Labels) || !in.Since.Before(in.Until) {
		return nil, fmt.Errorf("a verdicts proof needs a source, a label source and a period")
	}
	if !validTolerance(in.Tolerance) {
		return nil, fmt.Errorf("the tolerance is a rate between 0 and 1, more than none: "+
			"no sample can show a rate of exactly zero, and %v is not one", in.Tolerance)
	}
	if len(in.Lines) == 0 {
		return nil, fmt.Errorf("the product gave no verdicts in the period, so there is nothing to prove")
	}
	ev := &VerdictsEvidence{Source: in.Source, Labels: in.Labels,
		Since: day(in.Since), Until: day(in.Until), Tolerance: in.Tolerance,
		Considered: in.Considered, Counted: in.Counted, Excluded: Exclusions(in.Excluded),
		Alerts: in.Alerts, MinClosures: MinSample,
		FalseClosures:     ExactBound(in.FalseClosures.K, in.FalseClosures.N),
		ReviewCoverage:    WilsonRate(in.ReviewCoverage.K, in.ReviewCoverage.N),
		DeliveredFirst:    WilsonRate(in.DeliveredFirst.K, in.DeliveredFirst.N),
		Agreement:         WilsonRate(in.Agreement.K, in.Agreement.N),
		EscalationsClosed: WilsonRate(in.EscalationsClosed.K, in.EscalationsClosed.N),
		Abstentions:       WilsonRate(in.Abstentions.K, in.Abstentions.N),
		Consistency:       WilsonRate(in.Consistency.K, in.Consistency.N)}
	if len(in.FalseClosed) != in.FalseClosures.K {
		return nil, fmt.Errorf("%d false closures are named for %d counted",
			len(in.FalseClosed), in.FalseClosures.K)
	}
	var failures []string
	if ev.verdict() == Refuted {
		for _, id := range in.FalseClosed {
			failures = append(failures, alertFailure(id))
		}
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "verdicts/" + in.Source, Digest: SHA256(in.Lines)}},
		PredicateType: PredicateVerdicts,
		Predicate: Predicate{
			Claim:     ev.claim(),
			Verdict:   ev.verdict(),
			Verifier:  VerifierID{ID: VerdictsVerifier, Version: VerdictsVerifierVersion, Program: in.Program},
			Materials: append([]Material{}, in.Materials...),
			Checks:    ev.checks(failures),
			Verdicts:  ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	// The whole statement, as Seal will check it: a verdict that disagrees
	// with its checks is caught here, not when somebody tries to sign it.
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func knownLabels(l string) bool { return l == LabelsPeople || l == LabelsReported }

func (ev *VerdictsEvidence) who() string {
	if ev.Labels == LabelsReported {
		return "a person " + ev.Source + " reports"
	}
	return "a verified person here"
}

func (ev *VerdictsEvidence) tolerance() string {
	return strconv.FormatFloat(ev.Tolerance, 'g', -1, 64)
}

func (ev *VerdictsEvidence) claim() string {
	return fmt.Sprintf("Of the alerts %s closed as false-positive or benign between %s and %s, "+
		"before anybody decided them, and that %s later decided, a share of at most %s "+
		"were ones they found real.", ev.Source, ev.Since, ev.Until, ev.who(), ev.tolerance())
}

func (ev *VerdictsEvidence) verdict() Verdict {
	b := ev.FalseClosures
	switch {
	case b.Lower > ev.Tolerance:
		return Refuted
	case b.N >= MinSample && b.Upper <= ev.Tolerance:
		return Proven
	}
	return Inconclusive
}

// checks are the proof's checks, from the evidence and, when it is refuted,
// the false closures' names: the last lists at most MaxFailures and counts
// the rest.
func (ev *VerdictsEvidence) checks(failures []string) []Check {
	joined := fmt.Sprintf("%d verdicts in the period; %d counted, on %d alerts",
		ev.Considered, ev.Counted, ev.Alerts)
	for _, e := range ev.Excluded {
		joined += fmt.Sprintf("; %d excluded as %s", e.Verdicts, e.Reason)
	}
	joined += fmt.Sprintf("; %d of the %d counted were delivered here before the "+
		"disposition, and the rest carry only the product's own time",
		ev.DeliveredFirst.K, ev.DeliveredFirst.N)
	coverage := fmt.Sprintf("%d of the %d alerts the product closed were later decided by %s; "+
		"the rate is over those, which are not a random sample of its closures",
		ev.ReviewCoverage.K, ev.ReviewCoverage.N, ev.who())
	b := ev.FalseClosures
	fc := Check{Name: "false-closures", Passed: ev.verdict() != Refuted,
		Detail: fmt.Sprintf("%d of %d closures were alerts %s found real; the rate is "+
			"between %.4f and %.4f (exact, one-sided, 95%% each), against a tolerance of %s",
			b.K, b.N, ev.who(), b.Lower, b.Upper, ev.tolerance())}
	if b.N < MinSample {
		fc.Detail += fmt.Sprintf("; fewer than the %d closures a proven verdict needs", MinSample)
	}
	shown, more := capped(failures)
	fc.Failures = shown
	if more > 0 {
		fc.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	return []Check{{Name: "joined", Passed: true, Detail: joined},
		{Name: "review-coverage", Passed: true, Detail: coverage}, fc}
}

// validate refuses evidence whose numbers do not add up, do not support
// the verdict, or do not account for every word the statement says.
func (ev *VerdictsEvidence) validate(s *Statement) error {
	if !ValidVerdictSource(ev.Source) || !knownLabels(ev.Labels) || !validPeriod(ev.Since, ev.Until) {
		return fmt.Errorf("the verdicts evidence does not name a source, a label source and a period")
	}
	if !validTolerance(ev.Tolerance) {
		return fmt.Errorf("the verdicts evidence's tolerance is not a rate more than none")
	}
	excluded, err := excludedTotal(ev.Excluded)
	if err != nil {
		return err
	}
	if ev.Considered <= 0 || ev.Counted < 0 || ev.Counted+excluded != ev.Considered ||
		ev.Alerts < 0 || ev.Alerts > ev.Counted {
		return fmt.Errorf("the verdicts counted and excluded do not add up to those considered")
	}
	if !ev.FalseClosures.valid() {
		return fmt.Errorf("the false closures' bounds do not follow from their counts")
	}
	for _, r := range []Rate{ev.ReviewCoverage, ev.DeliveredFirst, ev.Agreement,
		ev.EscalationsClosed, ev.Abstentions, ev.Consistency} {
		if !r.valid() {
			return fmt.Errorf("a rate's interval does not follow from its counts")
		}
	}
	if ev.Abstentions.N != ev.Alerts ||
		ev.Agreement.N+ev.EscalationsClosed.N+ev.Abstentions.K != ev.Alerts ||
		ev.FalseClosures.N > ev.Agreement.N || ev.Consistency.N > ev.Alerts ||
		ev.ReviewCoverage.K != ev.FalseClosures.N || ev.DeliveredFirst.N != ev.Counted {
		return fmt.Errorf("the rates are not over the alerts and verdicts the evidence counts")
	}
	if ev.MinClosures != MinSample {
		return fmt.Errorf("the evidence's minimum is not this version's")
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("%d false closures in %d against a tolerance of %s is %s, not %s",
			ev.FalseClosures.K, ev.FalseClosures.N, ev.tolerance(), want, s.Predicate.Verdict)
	}
	var failures []string
	for _, c := range s.Predicate.Checks {
		for _, f := range c.Failures {
			if c.Name != "false-closures" || !validAlertFailure(f) {
				return fmt.Errorf("a failure in a verdicts proof names an alert by id and nothing else")
			}
			failures = append(failures, f)
		}
	}
	listed := 0
	if ev.verdict() == Refuted {
		listed = min(ev.FalseClosures.K, MaxFailures)
	}
	if len(failures) != listed {
		return fmt.Errorf("the failures listed are not the false closures a refutation names")
	}
	if listed > 0 {
		failures = append(failures, make([]string, ev.FalseClosures.K-len(failures))...)
	}
	return sameWords(s, "verdicts/"+ev.Source, ev.claim(), ev.checks(failures))
}

// sameWords requires a statement's subject name, claim and checks to be
// exactly the ones its evidence produces, so no sentence in it came from
// anywhere but the numbers and closed sets beside it.
func sameWords(s *Statement, subject, claim string, checks []Check) error {
	if len(s.Subject) != 1 || s.Subject[0].Name != subject {
		return fmt.Errorf("the subject is not %s", subject)
	}
	if s.Predicate.Claim != claim {
		return fmt.Errorf("the claim is not the sentence its evidence makes")
	}
	a, _ := json.Marshal(stripFailures(s.Predicate.Checks))
	b, _ := json.Marshal(stripFailures(checks))
	if string(a) != string(b) {
		return fmt.Errorf("the checks are not the ones its evidence makes")
	}
	return nil
}

// stripFailures drops the names a check lists, which the caller has
// checked for shape and count, so the rest compares exactly.
func stripFailures(cs []Check) []Check {
	out := make([]Check, len(cs))
	for i, c := range cs {
		c.Failures = nil
		out[i] = c
	}
	return out
}
