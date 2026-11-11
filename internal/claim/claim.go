// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package claim turns a vendor's claim into a test written down before the
// data it is tested on exists.
//
// # Why pre-register
//
// "98% agreement" can be made true after the fact by choosing the metric,
// the population, the period and the moment to stop looking. A card fixes
// all of them first: which metric (from verdict scoring or blind review),
// which product, which alerts, the threshold and its direction, the
// confidence, and how long the window runs. Registering it writes the
// card's digest into the signed, hash-chained audit log, and only data that
// arrives after that entry is counted — so nobody, including whoever
// registered it, can have seen the data the test runs on.
//
// # The verdict
//
// The metric's exact interval at the card's confidence (Clopper–Pearson,
// internal/stats) decides it: proven when the bound on the claimed side
// clears the threshold, refuted when the bound on the other side fails it,
// inconclusive otherwise — and inconclusive whatever the data say until the
// window has closed, because a test that may be run every day and kept the
// day it passes is not pre-registered.
package claim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/aertun/aertun/internal/adjudicate"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/stats"
	"github.com/aertun/aertun/internal/telemetry"
	"github.com/aertun/aertun/internal/verdict"
)

// Metric is what a card measures.
type Metric string

const (
	// Agreement is the share of the AI's dispositions that matched the
	// person's (internal/verdict).
	Agreement Metric = "agreement"
	// FalseClosures is the share of the AI's closures the person found real.
	FalseClosures Metric = "false-closures"
	// EscalationsClosed is the share of the AI's escalations the person closed.
	EscalationsClosed Metric = "escalations-closed"
	// Abstentions is the share of alerts the AI declined to answer.
	Abstentions Metric = "abstentions"
	// Consistency is the share of alerts answered more than once whose
	// answers all agreed.
	Consistency Metric = "consistency"
	// AdjudicatedFalseClosures is the share of the AI's closures a blind
	// reviewer judged real, in the one sample drawn for the card
	// (internal/adjudicate).
	AdjudicatedFalseClosures Metric = "adjudicated-false-closures"
)

// Metrics lists every metric.
func Metrics() []Metric {
	return []Metric{Agreement, FalseClosures, EscalationsClosed, Abstentions,
		Consistency, AdjudicatedFalseClosures}
}

// Known reports whether m is a metric.
func (m Metric) Known() bool {
	for _, x := range Metrics() {
		if x == m {
			return true
		}
	}
	return false
}

// Of picks the metric's count out of a verdict score.
func (m Metric) Of(s verdict.Score) (verdict.Count, bool) {
	switch m {
	case Agreement:
		return s.Agreement, true
	case FalseClosures:
		return s.FalseClosures, true
	case EscalationsClosed:
		return s.EscalationsClosed, true
	case Abstentions:
		return s.Abstentions, true
	case Consistency:
		return s.Consistency, true
	}
	return verdict.Count{}, false
}

// Direction is which side of the threshold the claim is on.
type Direction string

const (
	AtLeast Direction = "at-least"
	AtMost  Direction = "at-most"
)

// Severities are the floors a card's population can name.
var Severities = map[string]telemetry.Severity{
	"low": telemetry.SeverityLow, "medium": telemetry.SeverityMedium,
	"high": telemetry.SeverityHigh, "critical": telemetry.SeverityCritical,
}

// Population narrows which alerts count, by closed-set filters only: a
// free-text filter is a filter nobody can be held to.
type Population struct {
	// Labels is where the dispositions come from, for the verdict metrics.
	Labels verdict.LabelSource `json:"labels,omitempty"`
	// MinSeverity keeps alerts whose finding is at least this severe.
	MinSeverity string `json:"min_severity,omitempty"`
}

// Card is a pre-registered test of a claim.
type Card struct {
	Name string `json:"name"`
	// Nonce is random, so two cards with the same terms have different
	// digests and each registration is its own.
	Nonce      string     `json:"nonce"`
	Source     string     `json:"source"`
	Metric     Metric     `json:"metric"`
	Population Population `json:"population"`
	Threshold  float64    `json:"threshold"`
	Direction  Direction  `json:"direction"`
	Confidence float64    `json:"confidence"`
	// WindowDays is how long after registration data is counted.
	WindowDays int `json:"window_days"`
}

var (
	nameShape  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)
	nonceShape = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// MaxWindowDays bounds a window to a year: a claim tested over longer is a
// claim about a product that has since changed.
const MaxWindowDays = 366

// ValidName reports whether s can name a card.
func ValidName(s string) bool { return nameShape.MatchString(s) }

// Validate refuses a card that does not say exactly what will be tested.
func (c Card) Validate() error {
	if !ValidName(c.Name) {
		return fmt.Errorf("a card's name is 2 to 48 of a-z, 0-9 and -, starting with a letter")
	}
	if !nonceShape.MatchString(c.Nonce) {
		return fmt.Errorf("the card's nonce is not 16 bytes of hex")
	}
	if !verdict.ValidSource(c.Source) {
		return fmt.Errorf("the source is not a short lower-case name")
	}
	if !c.Metric.Known() {
		return fmt.Errorf("the metric is not one of agreement, false-closures, " +
			"escalations-closed, abstentions, consistency or adjudicated-false-closures")
	}
	if c.Metric == AdjudicatedFalseClosures {
		if c.Population.Labels != "" {
			return fmt.Errorf("a blind review is its own label; the card names no label source")
		}
	} else if !c.Population.Labels.Known() {
		return fmt.Errorf("the labels are aertun-decisions or source-reported")
	}
	if c.Population.MinSeverity != "" {
		if _, ok := Severities[c.Population.MinSeverity]; !ok {
			return fmt.Errorf("the severity floor is low, medium, high or critical")
		}
		if c.Population.Labels == verdict.Reported {
			return fmt.Errorf("a severity floor reads the finding, and source-reported " +
				"labels have none")
		}
	}
	if math.IsNaN(c.Threshold) || c.Threshold <= 0 || c.Threshold >= 1 {
		return fmt.Errorf("the threshold is a rate strictly between 0 and 1")
	}
	if c.Direction != AtLeast && c.Direction != AtMost {
		return fmt.Errorf("the direction is at-least or at-most")
	}
	if math.IsNaN(c.Confidence) || c.Confidence < 0.5 || c.Confidence >= 1 {
		return fmt.Errorf("the confidence is at least 0.5 and below 1")
	}
	if c.WindowDays < 1 || c.WindowDays > MaxWindowDays {
		return fmt.Errorf("the window is 1 to %d days", MaxWindowDays)
	}
	return nil
}

// Digest is the sha256 of the card's terms, which the audit log records.
func (c Card) Digest() string {
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Window is the period data is counted over, from the registration entry.
func (c Card) Window(registered time.Time) (start, end time.Time) {
	return registered, registered.Add(time.Duration(c.WindowDays) * 24 * time.Hour)
}

// RegisteredAction is the audit action a card is registered under.
const RegisteredAction = "claim.registered"

// RegisterDetail is what the registration records: the digest, which is
// the commitment, and the terms in words for whoever reads the log.
func (c Card) RegisterDetail() map[string]string {
	d := map[string]string{"claim": c.Name, "sha256": c.Digest(), "source": c.Source,
		"metric": string(c.Metric), "direction": string(c.Direction),
		"threshold":   strconv.FormatFloat(c.Threshold, 'g', -1, 64),
		"confidence":  strconv.FormatFloat(c.Confidence, 'g', -1, 64),
		"window_days": strconv.Itoa(c.WindowDays)}
	if c.Population.Labels != "" {
		d["labels"] = string(c.Population.Labels)
	}
	if c.Population.MinSeverity != "" {
		d["min_severity"] = c.Population.MinSeverity
	}
	return d
}

// Registration finds the one audit entry that registered this card, after
// checking the chain it sits in. A card whose terms were edited since has
// a digest no entry records, and is refused rather than tested.
func Registration(events []audit.Event, c Card) (adjudicate.Entry, error) {
	if ok, problems := audit.Verify(events); !ok {
		return adjudicate.Entry{}, fmt.Errorf("the audit log does not verify at entry %d (%s); "+
			"a registration in it cannot be relied on", problems[0].Seq, problems[0].Reason)
	}
	var found []adjudicate.Entry
	digest := c.Digest()
	for _, e := range events {
		if e.Action != RegisteredAction || e.Detail["sha256"] != digest || e.Detail["claim"] != c.Name {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.At)
		if err != nil {
			continue
		}
		found = append(found, adjudicate.Entry{Seq: e.Seq, Hash: e.Hash, At: at})
	}
	if len(found) != 1 {
		return adjudicate.Entry{}, fmt.Errorf("card %s is registered %d times in the audit log "+
			"under its present terms; a card is tested only against its one registration, "+
			"and terms changed since registering match none", c.Name, len(found))
	}
	return found[0], nil
}

// Outcome is what testing a card found.
type Outcome struct {
	Count     verdict.Count
	Low, High float64
	// Closed is whether the window had closed when the test ran.
	Closed bool
	// Holds is the bound on the claimed side clearing the threshold, and
	// Fails the bound on the other side failing it. Neither is set before
	// the window closes, and both unset is inconclusive.
	Holds, Fails bool
}

// Evaluate decides a card on a count. The interval is two-sided at the
// card's confidence, so each side of the decision errs at most half of
// what the confidence leaves.
func (c Card) Evaluate(n verdict.Count, closed bool) Outcome {
	o := Outcome{Count: n, Closed: closed}
	o.Low, o.High = stats.ClopperPearson(n.K, n.N, c.Confidence)
	if n.N == 0 {
		return o
	}
	// A claim cannot be shown to hold on a handful of alerts, whatever the
	// bound says at a confidence somebody chose: the same floor every other
	// proof here keeps under its proven verdict. Failing needs no floor —
	// one bound past the threshold is a counterexample at any size.
	switch c.Direction {
	case AtLeast:
		o.Holds, o.Fails = o.Low >= c.Threshold, o.High < c.Threshold
	case AtMost:
		o.Holds, o.Fails = o.High <= c.Threshold, o.Low > c.Threshold
	}
	if n.N < proof.MinSample {
		o.Holds = false
	}
	if !closed {
		o.Holds, o.Fails = false, false
	}
	return o
}
