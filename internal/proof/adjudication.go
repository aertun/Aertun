// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// An adjudication proof: closures judged again, blind, on a random sample
// committed before anybody looked (internal/adjudicate).
//
// # Why this and not the verdicts proof
//
// A verdicts proof counts the closures somebody happened to decide, and
// people look again at what looked wrong; that rate is not the product's.
// Here the sample is drawn at random from every closure the product's AI
// made in the period, decided or not, and from every closure people made,
// and committed to the signed audit log before the first item is shown. A
// reviewer sees each item's evidence and not who closed it, or how, or which
// of the two it came from; nobody who closed an item may judge it; and the
// judgements never become decisions on the findings, so a product that
// learns from analysts cannot learn the answers. The share judged real is
// each side's false-closure rate, unbiased.
//
// # The claim
//
// The AI's rate is read against a tolerance declared when the proof is made,
// with the exact one-sided bounds, as a verdicts proof reads it: refuted when
// the lower bound is over it, naming the items; proven when the upper bound
// is at or under it on at least MinSample items; inconclusive between. The
// people's rate is measured the same way and reported beside it, because
// "better than the analysts" needs both numbers, and a claim about the AI
// that hid the analysts' rate would be half a measurement.

// AdjudicationVerifier and its version name this verifier.
const (
	AdjudicationVerifier        = "aertun/adjudicate"
	AdjudicationVerifierVersion = "1"
)

// PredicateAdjudication is the predicate of an adjudication proof.
const PredicateAdjudication = "https://aertun.github.io/proof/adjudication/v1"

// AdjudicationEvidence is the review, as counts.
type AdjudicationEvidence struct {
	Source    string  `json:"source"`
	Since     string  `json:"since"`
	Until     string  `json:"until"`
	Tolerance float64 `json:"tolerance"`
	// Sample names the draw; Committed the audit entry it was committed in,
	// which every judgement follows; EarlierDraws how many samples of the
	// same product were committed before it.
	Sample       string     `json:"sample"`
	Committed    AuditEntry `json:"committed"`
	EarlierDraws int        `json:"earlier_draws"`
	// PopulationAI and PopulationHuman are the closures each stratum was
	// drawn from; Unlinked the AI's closures no single finding carries.
	PopulationAI    int `json:"population_ai"`
	PopulationHuman int `json:"population_human"`
	Unlinked        int `json:"unlinked"`
	// AI and Human are each stratum's items and how many were judged real.
	AI          Bound `json:"ai_false_closures"`
	Human       Bound `json:"human_false_closures"`
	Reviewers   int   `json:"reviewers"`
	MinClosures int   `json:"min_closures"`
}

// AuditEntry names an entry of the signed, hash-chained audit log: anybody
// holding the log checks it is there with `aertun auditlog prove SEQ`.
type AuditEntry struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
	At   string `json:"at"`
}

func (a AuditEntry) valid() bool {
	_, err := time.Parse(time.RFC3339Nano, a.At)
	return a.Seq > 0 && hex64.MatchString(a.Hash) && err == nil
}

// AdjudicationInput is what an adjudication proof is made from.
type AdjudicationInput struct {
	Source       string
	Since, Until time.Time
	Tolerance    float64
	// SampleFile is the sample's file as committed: what the subject's
	// digest is over.
	SampleFile []byte
	Sample     string
	Committed  AuditEntry

	EarlierDraws, PopulationAI, PopulationHuman, Unlinked, Reviewers int
	AI, Human                                                        Count
	// RealAI and RealHuman are the item numbers judged real.
	RealAI, RealHuman []int

	Materials []Material
	Program   string
	Now       time.Time
}

var (
	sampleShape = regexp.MustCompile(`^[0-9a-f]{16}$`)
	itemFailure = regexp.MustCompile(`^(ai|human) item ([0-9]+) judged real$`)
)

func itemFailureOf(stratum string, n int) string {
	return stratum + " item " + strconv.Itoa(n) + " judged real"
}

// ProveAdjudication builds the unsigned statement.
func ProveAdjudication(in AdjudicationInput) (*Statement, error) {
	if !ValidVerdictSource(in.Source) || !in.Since.Before(in.Until) || !sampleShape.MatchString(in.Sample) {
		return nil, fmt.Errorf("an adjudication names a product, a period and a sample")
	}
	if !validTolerance(in.Tolerance) {
		return nil, fmt.Errorf("the tolerance is a rate between 0 and 1, more than none")
	}
	if len(in.SampleFile) == 0 || !in.Committed.valid() {
		return nil, fmt.Errorf("an adjudication rests on a committed sample")
	}
	if len(in.RealAI) != in.AI.K || len(in.RealHuman) != in.Human.K {
		return nil, fmt.Errorf("the items named real are not the ones counted")
	}
	ev := &AdjudicationEvidence{Source: in.Source, Since: day(in.Since), Until: day(in.Until),
		Tolerance: in.Tolerance, Sample: in.Sample, Committed: in.Committed,
		EarlierDraws: in.EarlierDraws, PopulationAI: in.PopulationAI,
		PopulationHuman: in.PopulationHuman, Unlinked: in.Unlinked,
		AI: ExactBound(in.AI.K, in.AI.N), Human: ExactBound(in.Human.K, in.Human.N),
		Reviewers: in.Reviewers, MinClosures: MinSample}
	var failures []string
	if ev.verdict() == Refuted {
		for _, n := range in.RealAI {
			failures = append(failures, itemFailureOf("ai", n))
		}
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "adjudication/" + in.Sample, Digest: SHA256(in.SampleFile)}},
		PredicateType: PredicateAdjudication,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: AdjudicationVerifier, Version: AdjudicationVerifierVersion,
				Program: in.Program},
			Materials:    append([]Material{}, in.Materials...),
			Checks:       ev.checks(failures),
			Adjudication: ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *AdjudicationEvidence) tolerance() string {
	return strconv.FormatFloat(ev.Tolerance, 'g', -1, 64)
}

func (ev *AdjudicationEvidence) claim() string {
	return fmt.Sprintf("Of the alerts %s's AI closed as false-positive or benign between %s and %s, "+
		"judged again blind on a random sample committed before the review, a share of at most %s "+
		"were real.", ev.Source, ev.Since, ev.Until, ev.tolerance())
}

func (ev *AdjudicationEvidence) verdict() Verdict {
	switch {
	case ev.AI.Lower > ev.Tolerance:
		return Refuted
	case ev.AI.N >= MinSample && ev.AI.Upper <= ev.Tolerance:
		return Proven
	}
	return Inconclusive
}

func (ev *AdjudicationEvidence) checks(failures []string) []Check {
	committed := Check{Name: "committed-first", Passed: true,
		Detail: fmt.Sprintf("sample %s, drawn at random from %d closure(s) by the AI and %d by people "+
			"(%d of the AI's on no single finding, left out), was committed at audit entry %d before "+
			"any item was shown; %d sample(s) of %s were committed before it; %d reviewer(s), none "+
			"of whom closed an item they judged", ev.Sample, ev.PopulationAI, ev.PopulationHuman,
			ev.Unlinked, ev.Committed.Seq, ev.EarlierDraws, ev.Source, ev.Reviewers)}
	ai := Check{Name: "ai-false-closures", Passed: ev.verdict() != Refuted,
		Detail: fmt.Sprintf("%d of %d sampled closures by the AI were judged real; the rate is between "+
			"%.4f and %.4f (exact, one-sided, 95%% each), against a tolerance of %s",
			ev.AI.K, ev.AI.N, ev.AI.Lower, ev.AI.Upper, ev.tolerance())}
	if ev.AI.N < MinSample {
		ai.Detail += fmt.Sprintf("; fewer than the %d a proven verdict needs", MinSample)
	}
	shown, more := capped(failures)
	ai.Failures = shown
	if more > 0 {
		ai.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	human := Check{Name: "human-false-closures", Passed: true,
		Detail: fmt.Sprintf("for comparison, %d of %d sampled closures by people were judged real; "+
			"between %.4f and %.4f", ev.Human.K, ev.Human.N, ev.Human.Lower, ev.Human.Upper)}
	return []Check{committed, ai, human}
}

func (ev *AdjudicationEvidence) validate(s *Statement) error {
	if !ValidVerdictSource(ev.Source) || !validPeriod(ev.Since, ev.Until) ||
		!sampleShape.MatchString(ev.Sample) || !ev.Committed.valid() || !validTolerance(ev.Tolerance) {
		return fmt.Errorf("the adjudication does not name a product, a period, a committed sample and a tolerance")
	}
	if ev.EarlierDraws < 0 || ev.PopulationAI < 0 || ev.PopulationHuman < 0 || ev.Unlinked < 0 ||
		ev.Reviewers < 0 || !ev.AI.valid() || !ev.Human.valid() ||
		ev.AI.N > ev.PopulationAI || ev.Human.N > ev.PopulationHuman ||
		(ev.AI.N+ev.Human.N > 0 && ev.Reviewers == 0) {
		return fmt.Errorf("the adjudication's counts or bounds do not add up")
	}
	if ev.MinClosures != MinSample {
		return fmt.Errorf("the evidence's minimum is not this version's")
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("%d of %d judged real against %s is %s, not %s",
			ev.AI.K, ev.AI.N, ev.tolerance(), want, s.Predicate.Verdict)
	}
	var failures []string
	for _, c := range s.Predicate.Checks {
		for _, f := range c.Failures {
			m := itemFailure.FindStringSubmatch(f)
			if c.Name != "ai-false-closures" || m == nil || m[1] != "ai" {
				return fmt.Errorf("a failure in an adjudication names a sampled item and nothing else")
			}
			failures = append(failures, f)
		}
	}
	listed := 0
	if ev.verdict() == Refuted {
		listed = min(ev.AI.K, MaxFailures)
	}
	if len(failures) != listed {
		return fmt.Errorf("the failures listed are not the items a refutation names")
	}
	if listed > 0 {
		failures = append(failures, make([]string, ev.AI.K-len(failures))...)
	}
	return sameWords(s, "adjudication/"+ev.Sample, ev.claim(), ev.checks(failures))
}
