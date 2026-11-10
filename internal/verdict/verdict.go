// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package verdict measures another vendor's AI triage against what people
// decided about the same alerts.
//
// # Why
//
// Security teams are sold AI analysts whose accuracy is stated by the
// vendor and cannot be checked from outside: an agreement figure is usually
// agreement with the vendor's own staff, on the vendor's own data. The
// buyer has what the vendor does not — its own analysts' decisions on its
// own alerts — and that is evidence the vendor's model did not write. This
// package records what the vendor's AI said, alert by alert, joins it to
// the person's disposition of the same alert, and counts.
//
// # What it refuses to count
//
// A verdict given after the person decided is not independent evidence:
// some products learn from the analyst, and a model that read the answer
// agrees with it. Only verdicts given before the disposition count, and the
// rest are reported as excluded with the reason, never dropped silently.
//
// # What it keeps
//
// Only what can be checked: the product's validated short name, the alert's
// key in a validated shape, a word from a closed set, a confidence, and two
// times. Alert titles, descriptions and the vendor's reasons are written by
// the vendor or by whoever raised the alert, so the import refuses files
// that carry them rather than storing text that could later reach a proof
// or a screen.
package verdict

import (
	"fmt"
	"math"
	"time"

	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/telemetry"
)

// Word is what a vendor's AI said about an alert, and also what a person
// decided it was: a disposition is the first three.
type Word string

const (
	Real          Word = "real"
	FalsePositive Word = "false-positive"
	Benign        Word = "benign"
	// Escalate is the AI passing the alert to a person without deciding it.
	Escalate Word = "escalate"
	// Abstain is the AI declining to answer.
	Abstain Word = "abstain"
)

// Words lists every verdict word, in the order people read them.
func Words() []Word { return []Word{Real, FalsePositive, Benign, Escalate, Abstain} }

// Known reports whether w is a verdict word.
func (w Word) Known() bool {
	for _, x := range Words() {
		if x == w {
			return true
		}
	}
	return false
}

// Disposition reports whether w is something a person decides an alert
// was: real, false-positive or benign.
func (w Word) Disposition() bool { return w == Real || w == FalsePositive || w == Benign }

// Closes reports whether w takes an alert off the queue as not worth
// acting on.
func (w Word) Closes() bool { return w == FalsePositive || w == Benign }

// ValidSource reports whether s can name a vendor's product here: the shape
// a verdicts proof accepts, so a name this package stores is one a proof
// can carry.
func ValidSource(s string) bool { return proof.ValidVerdictSource(s) }

// ValidAlert reports whether s has the shape of an alert key: the shape a
// detection run carries an alert id onto a finding in
// (telemetry.ValidAlertID), so a key that could never have been linked is
// refused at the import rather than counted as unlinked.
func ValidAlert(s string) bool { return telemetry.ValidAlertID(s) }

// Skew is how far ahead of this machine's clock a time in an import may
// be. A verdict given in the future did not happen; a few minutes covers a
// vendor's clock running ahead of ours.
const Skew = 5 * time.Minute

// Verdict is one answer a vendor's AI gave about one alert.
type Verdict struct {
	// Source is the product, by a short name the operator chose.
	Source string `json:"source"`
	// Alert is the alert's key in that product.
	Alert string `json:"alert"`
	Says  Word   `json:"verdict"`
	// Confidence is the product's own, between 0 and 1, when it gave one.
	Confidence *float64 `json:"confidence,omitempty"`
	// At is when the verdict was given, as the product reports it.
	At time.Time `json:"at"`
	// Reported is the disposition the product says a person made of the
	// alert, and ReportedAt when. Source-reported: the vendor says so,
	// and nothing here can check it.
	Reported   Word      `json:"reported,omitempty"`
	ReportedAt time.Time `json:"reported_at,omitzero"`
	// Imported is when this program took delivery, stamped by the import
	// rather than read from the file, so the clock a pre-registered claim
	// counts from is one the vendor cannot move.
	Imported time.Time `json:"imported"`
}

// Validate refuses a verdict whose fields are not what this package
// stores. now bounds the times: nothing can have happened after it.
func (v Verdict) Validate(now time.Time) error {
	if !ValidSource(v.Source) {
		return fmt.Errorf("the source is not a short lower-case name (2 to 32 of a-z, 0-9 and -)")
	}
	if !ValidAlert(v.Alert) {
		return fmt.Errorf("the alert key is not an identifier (1 to 128 of letters, digits, '.', '_', ':' and '-')")
	}
	if !v.Says.Known() {
		return fmt.Errorf("the verdict is not one of real, false-positive, benign, escalate or abstain")
	}
	if c := v.Confidence; c != nil && (math.IsNaN(*c) || *c < 0 || *c > 1) {
		return fmt.Errorf("the confidence is not a number between 0 and 1")
	}
	if v.At.IsZero() || v.At.After(now.Add(Skew)) {
		return fmt.Errorf("the verdict's time is missing or in the future")
	}
	if v.Reported == "" {
		if !v.ReportedAt.IsZero() {
			return fmt.Errorf("a disposition time without a disposition says nothing")
		}
		return nil
	}
	if !v.Reported.Disposition() {
		return fmt.Errorf("the disposition is not one of real, false-positive or benign")
	}
	if v.ReportedAt.IsZero() || v.ReportedAt.After(now.Add(Skew)) {
		return fmt.Errorf("a disposition needs the time it was made, and not one in the " +
			"future: without it nothing can say whether the verdict came before it")
	}
	return nil
}

// Same reports whether two records are one verdict delivered twice, so an
// import of a file already imported adds nothing.
func Same(a, b Verdict) bool {
	ca, cb := a.Confidence, b.Confidence
	sameConf := (ca == nil && cb == nil) || (ca != nil && cb != nil && *ca == *cb)
	return a.Source == b.Source && a.Alert == b.Alert && a.Says == b.Says &&
		a.At.Equal(b.At) && a.Reported == b.Reported &&
		a.ReportedAt.Equal(b.ReportedAt) && sameConf
}
