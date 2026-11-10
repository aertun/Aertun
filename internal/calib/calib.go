// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package calib fits the threshold an analyst's answers must clear, on what
// people ruled, and certifies it in a signed statement that expires.
//
// A fixed threshold is a guess about a property of one model asked one way:
// how often an answer it gives at a given score is wrong. That property
// changes with the model, the adapter it runs with, the prompt template it
// is asked through and the mix of findings it sees, so the threshold is
// measured instead — on findings people have already ruled — and the
// measurement travels with what it was measured on.
//
// # What is measured
//
// The error that matters is a false closure: a closing suggestion
// (false-positive or benign) on a finding a person ruled real. For each
// candidate threshold on proof.CalibrationGrid, the closing suggestions
// scoring at or above it are counted, and so are the false closures among
// them. The Clopper–Pearson upper bound on the false-closure rate is taken
// at confidence 1−δ/m, m the number of candidates: the Bonferroni
// correction, because the threshold is chosen by looking at all m bounds
// and the one chosen must still hold at 1−δ. All m hold together with at
// least that probability, so whichever is chosen does too. The lowest
// candidate whose bound is at or under ε is certified — the lowest, because
// a lower threshold lets more suggestions through, and every certified
// candidate keeps the same promise.
//
// # Which score
//
// An answer carries two scores: the confidence the model stated, and, when
// the endpoint gave them, the probability of the tokens of the word it
// chose. They are different measurements and a threshold fitted on one
// means nothing on the other, so a certificate names its channel and a
// gate applies it only to answers scored on that channel.
//
// # What a certificate is bound to
//
// The model's name, the adapter's digest, the prompt template's digest and
// the task family, by value; the expiry by date. internal/decide refuses a
// certificate that differs from the analyst it gates in any of them, that
// has expired, that is not proven, or whose signatures do not both verify
// against the key the operator handed it — and falls back to the threshold
// the decider declares, saying so. Labels are verdicts people recorded,
// verified; a model's suggestion is never one, and the caller is the place
// that reads the audit log and keeps only those.
package calib

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// Verifier and VerifierVersion name the fit in every certificate.
const (
	Verifier        = "aertun/calibration"
	VerifierVersion = "1"
)

// LabelReal is the analyst's word for a finding that should not have
// happened — the label a false closure is a closing suggestion on. The two
// closing words are the finding states of the same names.
const LabelReal = "real"

func closing(word string) bool {
	return word == string(finding.FalsePositive) || word == string(finding.Benign)
}

func knownWord(word string) bool { return word == LabelReal || closing(word) }

// Point is one labelled verdict: what the analyst answered on a finding a
// person ruled, and what they ruled.
type Point struct {
	// Verdict is the analyst's closed-set word, empty when it gave none.
	Verdict string `json:"verdict"`
	// Confidence is the stated-channel score; Probability the token
	// channel's, nil when the endpoint gave no token probabilities.
	Confidence  float64  `json:"confidence"`
	Probability *float64 `json:"probability,omitempty"`
	// Label is what a verified person ruled.
	Label string `json:"label"`
}

func (p Point) score(channel string) (float64, bool) {
	if channel == proof.ChannelLogprob {
		if p.Probability == nil {
			return 0, false
		}
		return *p.Probability, true
	}
	return p.Confidence, true
}

func (p Point) valid() error {
	if !knownWord(p.Label) {
		return fmt.Errorf("%q is not a label", p.Label)
	}
	if p.Verdict != "" && !knownWord(p.Verdict) {
		return fmt.Errorf("%q is not a verdict", p.Verdict)
	}
	if !(p.Confidence >= 0 && p.Confidence <= 1) {
		return fmt.Errorf("a confidence of %v is not a score", p.Confidence)
	}
	if p.Probability != nil && !(*p.Probability >= 0 && *p.Probability <= 1) {
		return fmt.Errorf("a probability of %v is not a score", *p.Probability)
	}
	return nil
}

// Channel is the channel a set of points can be fitted on: the token
// channel when every answered point carries a token probability, and the
// stated channel otherwise. Mixed is stated, because a threshold fitted on
// the answers that happened to carry probabilities would be fitted on a
// sample chosen by whatever made the others not carry them.
func Channel(points []Point) string {
	answered := 0
	for _, p := range points {
		if p.Verdict == "" {
			continue
		}
		answered++
		if p.Probability == nil {
			return proof.ChannelStated
		}
	}
	if answered == 0 {
		return proof.ChannelStated
	}
	return proof.ChannelLogprob
}

// Fit is what the candidates showed.
type Fit struct {
	// Threshold is the certified candidate when Certified, and otherwise
	// the candidate whose bound came closest to ε.
	Threshold     float64
	Closures      int
	FalseClosures int
	Upper         float64
	Certified     bool
	// Possible says some candidate had enough closing suggestions that a
	// record with no false closure would have been certified: evidence
	// that could have passed, which is what makes a failure a refutation
	// rather than too little to go on.
	Possible bool
}

// FitThreshold examines every candidate on proof.CalibrationGrid and
// certifies the lowest whose Bonferroni-corrected bound is at or under eps.
func FitThreshold(points []Point, channel string, eps, delta float64) Fit {
	grid := proof.CalibrationGrid()
	m := len(grid)
	var best Fit
	best.Upper = math.Inf(1)
	possible := false
	for _, t := range grid {
		n, k := 0, 0
		for _, p := range points {
			s, ok := p.score(channel)
			if !ok || !closing(p.Verdict) || s < t {
				continue
			}
			n++
			if p.Label == LabelReal {
				k++
			}
		}
		u := proof.CalibrationUpper(k, n, delta, m)
		if u <= eps {
			return Fit{Threshold: t, Closures: n, FalseClosures: k, Upper: u,
				Certified: true, Possible: true}
		}
		possible = possible || proof.CalibrationUpper(0, n, delta, m) <= eps
		if u < best.Upper {
			best = Fit{Threshold: t, Closures: n, FalseClosures: k, Upper: u}
		}
	}
	best.Possible = possible
	return best
}

// Input is everything a certificate is made from.
type Input struct {
	Model    string
	Adapter  string
	Template string
	Family   string
	// Points are the labelled verdicts, every label a verified person's.
	Points  []Point
	Epsilon float64
	Delta   float64
	// ValidFor is how long the certificate holds, at most
	// proof.MaxCalibrationValidity.
	ValidFor time.Duration
	// LeftOut is how many decisions the caller read and did not use
	// because a verified person did not record them.
	LeftOut int
	Author  proof.Author
	Program string
	Now     time.Time
}

var reFamily = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
var reHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Certify fits the threshold and returns the unsigned certificate,
// whatever the verdict: a fit that certified nothing is signed like one
// that did, because knowing a model could not be certified on this
// evidence is what the next attempt needs.
func Certify(in Input) (*proof.Statement, error) {
	switch {
	case strings.TrimSpace(in.Model) == "" || len(in.Model) > 200:
		return nil, fmt.Errorf("a certificate names the model it is about, in under 200 bytes")
	case in.Adapter != "" && !reHex64.MatchString(in.Adapter):
		return nil, fmt.Errorf("the adapter digest %q is not a lower-case sha256", in.Adapter)
	case !reHex64.MatchString(in.Template):
		return nil, fmt.Errorf("the template digest is not a lower-case sha256")
	case !reFamily.MatchString(in.Family):
		return nil, fmt.Errorf("%q is not a task family", in.Family)
	case !(in.Epsilon > 0 && in.Epsilon < 1):
		return nil, fmt.Errorf("epsilon is a rate between 0 and 1, not %v", in.Epsilon)
	case !(in.Delta > 0 && in.Delta < 1):
		return nil, fmt.Errorf("delta is a risk between 0 and 1, not %v", in.Delta)
	case in.ValidFor <= 0 || in.ValidFor > proof.MaxCalibrationValidity:
		return nil, fmt.Errorf("a certificate holds for some time up to %v", proof.MaxCalibrationValidity)
	case in.LeftOut < 0:
		return nil, fmt.Errorf("a count of decisions left out cannot be negative")
	}
	real := 0
	for i, p := range in.Points {
		if err := p.valid(); err != nil {
			return nil, fmt.Errorf("verdict %d: %w", i+1, err)
		}
		if p.Label == LabelReal {
			real++
		}
	}
	material, err := json.Marshal(in.Points)
	if err != nil {
		return nil, err
	}
	channel := Channel(in.Points)
	fit := FitThreshold(in.Points, channel, in.Epsilon, in.Delta)
	now := in.Now.UTC().Truncate(time.Second)
	m := len(proof.CalibrationGrid())
	ev := &proof.CalibrationEvidence{
		Model: in.Model, Adapter: in.Adapter, Template: in.Template, Family: in.Family,
		Channel: channel, Epsilon: in.Epsilon, Delta: in.Delta,
		Method: proof.CalibrationMethod, Candidates: m,
		Cases: len(in.Points), Real: real,
		Threshold: fit.Threshold, Closures: fit.Closures, FalseClosures: fit.FalseClosures,
		Upper:   fit.Upper,
		Expires: now.Add(in.ValidFor).Format(time.RFC3339),
	}
	st := &proof.Statement{
		Type: proof.StatementType,
		Subject: []proof.Subject{{Name: in.Model,
			Digest: proof.AnalystDigest(in.Model, in.Adapter, in.Template)}},
		PredicateType: proof.PredicateCalibration,
		Predicate: proof.Predicate{
			Claim: fmt.Sprintf("At or above the certified threshold, at most %g of %s's "+
				"closing suggestions on %s, scored on the %s channel, are on findings a "+
				"person ruled real, with confidence %g.", in.Epsilon, in.Model, in.Family,
				channel, 1-in.Delta),
			Author: in.Author,
			Verifier: proof.VerifierID{ID: Verifier, Version: VerifierVersion,
				Program: in.Program},
			Materials: []proof.Material{{Name: "verdicts people ruled",
				Digest: proof.SHA256(material), Entries: len(in.Points)}},
			Calibration: ev,
			VerifiedAt:  now.Format(time.RFC3339),
		},
	}
	p := &st.Predicate
	p.Checks = append(p.Checks, proof.Check{Name: "labels", Passed: true,
		Detail: fmt.Sprintf("%d verdict(s) recorded by verified people, %d of them real; "+
			"%d decision(s) recorded by anybody else were left out",
			len(in.Points), real, in.LeftOut)})
	closures := proof.Check{Name: "false-closures", Passed: true}
	switch {
	case fit.Certified:
		p.Verdict = proof.Proven
		closures.Detail = fmt.Sprintf("at threshold %.2f, %d of %d closing suggestion(s) "+
			"were on findings a person ruled real; the bound at confidence 1-%g/%d is "+
			"%.4f, at or under %g", fit.Threshold, fit.FalseClosures, fit.Closures,
			in.Delta, m, fit.Upper, in.Epsilon)
	case fit.Possible:
		p.Verdict = proof.Refuted
		closures.Passed = false
		closures.Detail = fmt.Sprintf("no candidate threshold bounds the rate at or under "+
			"%g; the closest, %.2f, had %d of %d closing suggestion(s) on findings ruled "+
			"real, bounded at %.4f", in.Epsilon, fit.Threshold, fit.FalseClosures,
			fit.Closures, fit.Upper)
	default:
		p.Verdict = proof.Inconclusive
		closures.Detail = fmt.Sprintf("no candidate threshold had enough closing "+
			"suggestions for even a record with no false closure to bound the rate at "+
			"or under %g; the closest, %.2f, had %d of %d, bounded at %.4f",
			in.Epsilon, fit.Threshold, fit.FalseClosures, fit.Closures, fit.Upper)
	}
	p.Checks = append(p.Checks, closures)
	if err := st.Validate(); err != nil {
		return nil, fmt.Errorf("the certificate does not hold together: %w", err)
	}
	return st, nil
}

// Binding is what a certificate must name to gate an analyst: the model,
// the adapter's digest (empty for none), the prompt template's digest and
// the task family.
type Binding struct {
	Model    string
	Adapter  string
	Template string
	Family   string
}

// Why a certificate was refused. A closed set: the reason a person reads
// for a fallback is one of these words, never anything the document said.
const (
	RefusedUnreadable = "unreadable"
	RefusedSignature  = "signatures do not verify"
	RefusedKind       = "not a calibration certificate"
	RefusedNotProven  = "certifies no threshold"
	RefusedModel      = "for another model"
	RefusedAdapter    = "for another adapter"
	RefusedTemplate   = "for another prompt template"
	RefusedFamily     = "for another task family"
	RefusedNotYet     = "not yet valid"
	RefusedExpired    = "expired"
)

// Refusal is a certificate that may not gate anything, and why.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return "the calibration certificate is " + r.Reason }

// Reason is why err refused a certificate, or RefusedUnreadable for an
// error that is not a Refusal.
func Reason(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return RefusedUnreadable
}

// ClockSkew is how far in the future a certificate's moment may be and
// still be in force: the machine that made it and the one checking it
// need not agree to the second.
const ClockSkew = 5 * time.Minute

// Check opens a certificate against the key the operator handed over and
// returns its evidence only if it may gate the analyst want names at now.
// Both signatures are verified before anything in the document is read.
func Check(envelope []byte, key pack.KeyPublic, want Binding, now time.Time) (*proof.CalibrationEvidence, error) {
	env, err := proof.ParseEnvelope(envelope)
	if err != nil {
		return nil, &Refusal{RefusedUnreadable}
	}
	st, err := proof.Open(env, key)
	if err != nil {
		return nil, &Refusal{RefusedSignature}
	}
	if st.PredicateType != proof.PredicateCalibration || st.Predicate.Calibration == nil {
		return nil, &Refusal{RefusedKind}
	}
	ev := st.Predicate.Calibration
	switch {
	case st.Predicate.Verdict != proof.Proven:
		return nil, &Refusal{RefusedNotProven}
	case ev.Model != want.Model:
		return nil, &Refusal{RefusedModel}
	case ev.Adapter != want.Adapter:
		return nil, &Refusal{RefusedAdapter}
	case ev.Template != want.Template:
		return nil, &Refusal{RefusedTemplate}
	case ev.Family != want.Family:
		return nil, &Refusal{RefusedFamily}
	}
	// Validate has already parsed both moments.
	from, _ := time.Parse(time.RFC3339, st.Predicate.VerifiedAt)
	until, _ := time.Parse(time.RFC3339, ev.Expires)
	if from.After(now.Add(ClockSkew)) {
		return nil, &Refusal{RefusedNotYet}
	}
	if !now.Before(until) {
		return nil, &Refusal{RefusedExpired}
	}
	return ev, nil
}
