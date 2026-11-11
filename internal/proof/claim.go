// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/aertun/aertun/internal/stats"
)

// A claim proof: a vendor's claim, written down as a test before the data it
// is tested on existed, and tested once its window closed (internal/claim).
//
// "98% agreement" can be made true afterwards by choosing the metric, the
// population, the period and the day to stop looking. A claim card fixes all
// of them first and commits its digest to the signed audit log; only data
// that arrived after that entry, inside the card's window, is counted; and
// nothing is decided until the window has closed. The proof carries the
// card's terms, the registration it was committed in, the count and its
// exact interval at the card's own confidence:
//
//   - proven when the bound on the claimed side clears the threshold, on at
//     least MinSample alerts;
//   - refuted when the bound on the other side fails it;
//   - inconclusive otherwise, and always while the window is open.

// ClaimVerifier and its version name this verifier.
const (
	ClaimVerifier        = "aertun/claim"
	ClaimVerifierVersion = "1"
)

// PredicateClaim is the predicate of a claim proof.
const PredicateClaim = "https://aertun.github.io/proof/claim/v1"

// ClaimMetrics are the metrics a card can name, and how a sentence says each.
var ClaimMetrics = map[string]string{
	"agreement":                  "the share of its dispositions that matched the person's",
	"false-closures":             "the share of its closures a person found real",
	"escalations-closed":         "the share of its escalations a person closed",
	"abstentions":                "the share of alerts it declined to answer",
	"consistency":                "the share of alerts answered more than once whose answers all agreed",
	"adjudicated-false-closures": "the share of its closures a blind reviewer judged real",
}

// ClaimEvidence is the card's terms and what testing it found.
type ClaimEvidence struct {
	Name        string  `json:"name"`
	Card        string  `json:"card_sha256"`
	Source      string  `json:"source"`
	Metric      string  `json:"metric"`
	Direction   string  `json:"direction"`
	Threshold   float64 `json:"threshold"`
	Confidence  float64 `json:"confidence"`
	Labels      string  `json:"labels,omitempty"`
	MinSeverity string  `json:"min_severity,omitempty"`
	// Registered is the audit entry the card was committed in; WindowStart
	// and WindowEnd the period counted from it.
	Registered  AuditEntry `json:"registered"`
	WindowStart string     `json:"window_start"`
	WindowEnd   string     `json:"window_end"`
	// Closed is whether the window had closed when the test ran.
	Closed      bool    `json:"closed"`
	K           int     `json:"k"`
	N           int     `json:"n"`
	Low         float64 `json:"low"`
	High        float64 `json:"high"`
	MinClosures int     `json:"min_closures"`
}

// ClaimInput is what a claim proof is made from.
type ClaimInput struct {
	Name, Card, Source, Metric, Direction, Labels, MinSeverity string
	Threshold, Confidence                                      float64
	Registered                                                 AuditEntry
	WindowStart, WindowEnd                                     time.Time
	Closed                                                     bool
	Count                                                      Count
	// CardFile is the card as registered: what the subject's digest is over.
	CardFile  []byte
	Materials []Material
	Program   string
	Now       time.Time
}

var (
	claimName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)
	severity  = map[string]bool{"": true, "low": true, "medium": true, "high": true, "critical": true}
)

// ProveClaim builds the unsigned statement.
func ProveClaim(in ClaimInput) (*Statement, error) {
	lo, hi := stats.ClopperPearson(in.Count.K, in.Count.N, in.Confidence)
	ev := &ClaimEvidence{Name: in.Name, Card: in.Card, Source: in.Source, Metric: in.Metric,
		Direction: in.Direction, Threshold: in.Threshold, Confidence: in.Confidence,
		Labels: in.Labels, MinSeverity: in.MinSeverity, Registered: in.Registered,
		WindowStart: in.WindowStart.UTC().Format(time.RFC3339), WindowEnd: in.WindowEnd.UTC().Format(time.RFC3339),
		Closed: in.Closed, K: in.Count.K, N: in.Count.N, Low: lo, High: hi, MinClosures: MinSample}
	if len(in.CardFile) == 0 {
		return nil, fmt.Errorf("a claim proof rests on the card as it was registered")
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "claim/" + in.Name, Digest: SHA256(in.CardFile)}},
		PredicateType: PredicateClaim,
		Predicate: Predicate{
			Claim:     ev.claim(),
			Verdict:   ev.verdict(),
			Verifier:  VerifierID{ID: ClaimVerifier, Version: ClaimVerifierVersion, Program: in.Program},
			Materials: append([]Material{}, in.Materials...),
			Checks:    ev.checks(),
			ClaimTest: ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *ClaimEvidence) words() string {
	return ClaimMetrics[ev.Metric]
}

func (ev *ClaimEvidence) side() string {
	if ev.Direction == "at-least" {
		return "at least"
	}
	return "at most"
}

func num(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

func (ev *ClaimEvidence) claim() string {
	pop := ""
	if ev.MinSeverity != "" {
		pop = ", on alerts of severity " + ev.MinSeverity + " or worse"
	}
	return fmt.Sprintf("For %s's AI, %s%s, between %s and %s, is %s %s: claim %s, registered at "+
		"audit entry %d before any of that data arrived.", ev.Source, ev.words(), pop,
		ev.WindowStart, ev.WindowEnd, ev.side(), num(ev.Threshold), ev.Name, ev.Registered.Seq)
}

func (ev *ClaimEvidence) holds() bool {
	if !ev.Closed || ev.N < MinSample {
		return false
	}
	if ev.Direction == "at-least" {
		return ev.Low >= ev.Threshold
	}
	return ev.High <= ev.Threshold
}

func (ev *ClaimEvidence) fails() bool {
	if !ev.Closed || ev.N == 0 {
		return false
	}
	if ev.Direction == "at-least" {
		return ev.High < ev.Threshold
	}
	return ev.Low > ev.Threshold
}

func (ev *ClaimEvidence) verdict() Verdict {
	switch {
	case ev.fails():
		return Refuted
	case ev.holds():
		return Proven
	}
	return Inconclusive
}

func (ev *ClaimEvidence) checks() []Check {
	window := Check{Name: "window-closed", Passed: true,
		Detail: fmt.Sprintf("the window ran %s to %s and had closed when this ran", ev.WindowStart, ev.WindowEnd)}
	if !ev.Closed {
		window.Detail = fmt.Sprintf("the window runs %s to %s and is still open, so nothing is "+
			"decided: a test run every day and kept the day it passed is not pre-registered",
			ev.WindowStart, ev.WindowEnd)
	}
	result := Check{Name: "the-claim", Passed: ev.verdict() != Refuted,
		Detail: fmt.Sprintf("%d of %d; between %.4f and %.4f (exact, two-sided, at %s), against %s %s",
			ev.K, ev.N, ev.Low, ev.High, num(ev.Confidence), ev.side(), num(ev.Threshold))}
	if ev.N < MinSample && ev.verdict() != Refuted {
		result.Detail += fmt.Sprintf("; fewer than the %d a proven verdict needs", MinSample)
	}
	return []Check{window, result}
}

func (ev *ClaimEvidence) validate(s *Statement) error {
	if !claimName.MatchString(ev.Name) || !hex64.MatchString(ev.Card) || !ValidVerdictSource(ev.Source) {
		return fmt.Errorf("a claim proof names its card, by name and digest, and a product")
	}
	if _, ok := ClaimMetrics[ev.Metric]; !ok || (ev.Direction != "at-least" && ev.Direction != "at-most") {
		return fmt.Errorf("a claim proof names one of the metrics and a direction")
	}
	if !validTolerance(ev.Threshold) || !(ev.Confidence >= 0.5 && ev.Confidence < 1) {
		return fmt.Errorf("a claim's threshold is a rate and its confidence at least 0.5")
	}
	if ev.Labels != "" && !knownLabels(ev.Labels) || !severity[ev.MinSeverity] {
		return fmt.Errorf("a claim's population is named by closed words only")
	}
	if !ev.Registered.valid() || !validPeriod(ev.WindowStart, ev.WindowEnd) {
		return fmt.Errorf("a claim proof names its registration and its window")
	}
	if ev.K < 0 || ev.N < 0 || ev.K > ev.N {
		return fmt.Errorf("a claim's count is k of n")
	}
	lo, hi := stats.ClopperPearson(ev.K, ev.N, ev.Confidence)
	if !approx(lo, ev.Low) || !approx(hi, ev.High) || ev.MinClosures != MinSample {
		return fmt.Errorf("the claim's interval does not follow from its count")
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the count makes this %s, not %s", want, s.Predicate.Verdict)
	}
	for _, c := range s.Predicate.Checks {
		if len(c.Failures) > 0 {
			return fmt.Errorf("a claim proof lists no failures: its count is the answer")
		}
	}
	return sameWords(s, "claim/"+ev.Name, ev.claim(), ev.checks())
}
