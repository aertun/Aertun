// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/stats"
)

// A calibration certificate: the threshold an analyst's answers must clear
// before one is offered, fitted on what people ruled and signed.
//
// The claim is about one analyst — a model, the adapter it runs with and
// the prompt template it is asked through, all by name or digest — on one
// task family: at or above the certified threshold, the share of its
// closing suggestions (false-positive or benign) that are on findings a
// person ruled real is at most ε, with confidence 1−δ.
//
// The fit (internal/calib) examines a fixed grid of candidate thresholds,
// and choosing the best of many candidates by their bounds would overstate
// the confidence of the one chosen. So every candidate's Clopper–Pearson
// bound is taken at confidence 1−δ/m, m the size of the grid — the
// Bonferroni correction — and then all m bounds hold together with
// probability at least 1−δ, including whichever was chosen. Method names
// that, and Validate recomputes the bound from the counts, so a
// certificate cannot carry a bound its own counts do not support.

// PredicateCalibration is the predicate of a calibration certificate.
const PredicateCalibration = "https://aertun.github.io/proof/calibration/v1"

// CalibrationMethod names how the bound was taken: Clopper–Pearson at
// δ divided by the number of candidates on CalibrationGrid.
const CalibrationMethod = "clopper-pearson-upper, bonferroni over the candidate grid"

// The channels an answer's score can come from: the confidence the model
// stated, or the probability the endpoint gave the tokens of the word it
// chose. A threshold fitted on one means nothing on the other.
const (
	ChannelStated  = "stated"
	ChannelLogprob = "logprob"
)

// MaxCalibrationValidity bounds how long a certificate may claim to hold.
// Calibration is a measurement of a model on a mix of findings, and both
// drift; a certificate that outlived them would vouch for a model nobody
// measured.
const MaxCalibrationValidity = 90 * 24 * time.Hour

// CalibrationGrid is every threshold a fit may certify, fixed before any
// data is read — the candidates a Bonferroni correction counts must not
// depend on the data they are corrected over. Hundredths from 0.50 to
// 1.00: below a half, an answer is not the most likely one on its own
// channel's say-so.
func CalibrationGrid() []float64 {
	out := make([]float64, 0, 51)
	for i := 50; i <= 100; i++ {
		out = append(out, float64(i)/100)
	}
	return out
}

// CalibrationEvidence is everything a calibration certificate says, as
// exact counts and the bound computed from them.
type CalibrationEvidence struct {
	// Model, Adapter and Template are what the certificate binds to: the
	// model's name, the sha256 of the adapter it runs with (empty for
	// none) and the sha256 of the prompt template it is asked through.
	Model    string `json:"model"`
	Adapter  string `json:"adapter_sha256,omitempty"`
	Template string `json:"template_sha256"`
	// Family is the task the threshold gates — the decider's name.
	Family string `json:"family"`
	// Channel is which score the threshold is compared with.
	Channel string  `json:"channel"`
	Epsilon float64 `json:"epsilon"`
	Delta   float64 `json:"delta"`
	Method  string  `json:"method"`
	// Candidates is how many thresholds were examined: the m of δ/m.
	Candidates int `json:"candidates"`
	// Cases is how many labelled verdicts the fit read; Real how many of
	// them a person ruled real.
	Cases int `json:"cases"`
	Real  int `json:"real"`
	// Threshold is the candidate the counts below are at: the certified
	// threshold when the verdict is proven, and otherwise the candidate
	// whose bound came closest to ε.
	Threshold float64 `json:"threshold"`
	// Closures is how many closing suggestions scored at or above
	// Threshold, and FalseClosures how many of those a person ruled real.
	Closures      int `json:"closures"`
	FalseClosures int `json:"false_closures"`
	// Upper is the Clopper–Pearson upper bound on the false-closure rate
	// behind FalseClosures of Closures, at confidence 1−Delta/Candidates.
	Upper float64 `json:"false_closure_upper"`
	// Expires is when the certificate stops holding, RFC 3339.
	Expires string `json:"expires"`
}

var (
	reFamily = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	// boundSlack is how far a recomputed bound may differ from the signed
	// one: floating point may differ in the last places between machines,
	// and nothing about a guarantee lives there.
	boundSlack = 1e-9
)

// AnalystDigest names an analyst for a subject: the model, the adapter and
// the prompt template it was asked through, so a statement about one
// analyst cannot be read as being about another that shares a name.
func AnalystDigest(model, adapter, template string) Digest {
	sum := sha256.Sum256([]byte(model + "\x00" + adapter + "\x00" + template))
	return Digest{"sha256": hex.EncodeToString(sum[:])}
}

// CalibrationUpper is the bound a certificate states for its counts, so
// the fit and the check compute it in one place.
func CalibrationUpper(falseClosures, closures int, delta float64, candidates int) float64 {
	return stats.ClopperPearsonUpper(falseClosures, closures, 1-delta/float64(candidates))
}

func onGrid(t float64) bool {
	for _, g := range CalibrationGrid() {
		if t == g {
			return true
		}
	}
	return false
}

// validate refuses a calibration statement whose numbers do not hold
// together.
func (e *CalibrationEvidence) validate(s *Statement) error {
	p := s.Predicate
	switch {
	case strings.TrimSpace(e.Model) == "" || len(e.Model) > 200:
		return fmt.Errorf("a calibration certificate names the model, in under 200 bytes")
	case e.Adapter != "" && !hex64.MatchString(e.Adapter):
		return fmt.Errorf("the adapter digest is not a lower-case sha256")
	case !hex64.MatchString(e.Template):
		return fmt.Errorf("the template digest is not a lower-case sha256")
	case !reFamily.MatchString(e.Family):
		return fmt.Errorf("%q is not a task family", e.Family)
	case e.Channel != ChannelStated && e.Channel != ChannelLogprob:
		return fmt.Errorf("%q is not a channel; it is %s or %s", e.Channel, ChannelStated, ChannelLogprob)
	case !(e.Epsilon > 0 && e.Epsilon < 1) || !(e.Delta > 0 && e.Delta < 1):
		return fmt.Errorf("epsilon and delta are each between 0 and 1")
	case e.Method != CalibrationMethod || e.Candidates != len(CalibrationGrid()):
		return fmt.Errorf("the method is not one this version can check")
	case e.Cases < 0 || e.Real < 0 || e.Real > e.Cases:
		return fmt.Errorf("the case counts do not add up")
	case e.Closures < 0 || e.FalseClosures < 0 || e.FalseClosures > e.Closures ||
		e.Closures > e.Cases || e.FalseClosures > e.Real:
		return fmt.Errorf("the closure counts do not add up")
	case !onGrid(e.Threshold):
		return fmt.Errorf("the threshold %v is not one of the candidates", e.Threshold)
	}
	if len(s.Subject) != 1 || s.Subject[0].Name != e.Model ||
		s.Subject[0].Digest["sha256"] != AnalystDigest(e.Model, e.Adapter, e.Template)["sha256"] {
		return fmt.Errorf("the subject is not the analyst the evidence names")
	}
	want := CalibrationUpper(e.FalseClosures, e.Closures, e.Delta, e.Candidates)
	if math.IsNaN(e.Upper) || math.Abs(e.Upper-want) > boundSlack {
		return fmt.Errorf("the bound %v does not follow from %d of %d at %s",
			e.Upper, e.FalseClosures, e.Closures, CalibrationMethod)
	}
	if p.Verdict == Proven && e.Upper > e.Epsilon {
		return fmt.Errorf("a proven certificate's bound %v is over its epsilon %v", e.Upper, e.Epsilon)
	}
	from, _ := time.Parse(time.RFC3339, p.VerifiedAt)
	until, err := time.Parse(time.RFC3339, e.Expires)
	if err != nil {
		return fmt.Errorf("expires is not RFC 3339: %w", err)
	}
	if !until.After(from) || until.Sub(from) > MaxCalibrationValidity {
		return fmt.Errorf("a certificate expires after it was made and within %v of it",
			MaxCalibrationValidity)
	}
	return nil
}
