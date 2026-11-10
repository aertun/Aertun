// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package analyst

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/calib"
	"github.com/aertun/aertun/internal/decide"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// The calibration fit counts a false closure as a closing word on a finding
// labelled with the analyst's word for real: the two packages must spell
// the three words alike, or every label would read as something else.
func TestCalibrationSpeaksTheAnalystsWords(t *testing.T) {
	if calib.LabelReal != Real {
		t.Fatalf("calib's real is %q and the analyst's is %q", calib.LabelReal, Real)
	}
	pts := []calib.Point{{Verdict: FalsePositive, Confidence: 0.9, Label: Real},
		{Verdict: Benign, Confidence: 0.9, Label: Real}}
	if f := calib.FitThreshold(pts, proof.ChannelStated, 0.5, 0.5); f.FalseClosures != 2 {
		t.Errorf("the analyst's closing words were not read as closures: %+v", f)
	}
}

// A certificate for this analyst's template lowers the gate for the
// question and for the counterfactual re-ask alike, and the reason a person
// reads says a certificate set it.
func TestACertifiedThresholdGatesTheTriage(t *testing.T) {
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var points []calib.Point
	for i := 0; i < 200; i++ {
		points = append(points, calib.Point{Verdict: Benign, Confidence: 0.92, Label: Benign})
	}
	at := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	st, err := calib.Certify(calib.Input{Model: "test", Template: decide.TemplateDigest(Decider()),
		Family: Decider().Name, Points: points, Epsilon: 0.05, Delta: 0.05,
		ValidFor: 24 * time.Hour, Now: at})
	if err != nil {
		t.Fatal(err)
	}
	env, err := proof.Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := json.Marshal(env)
	cal := &decide.Calibration{Certificate: cert, Key: k.PublicKey(), Now: at.Add(time.Hour)}

	m := &model{answer: says(Benign, 0.6)}
	state, trace := Gather(f("f1", "dana", "open", "sign-in failed"), nil, false, now)
	plain, err := Ask(context.Background(), m, state, trace)
	if err != nil || plain.To != "" || plain.Certificate != "" {
		t.Fatalf("at the declared threshold: %+v, %v", plain, err)
	}
	s, err := AskWith(context.Background(), m, state, trace, cal)
	if err != nil {
		t.Fatal(err)
	}
	if s.To != "benign" || !s.Certified || s.Threshold != 0.5 || s.Certificate != decide.CertificateUsed ||
		s.CounterfactualChanged {
		t.Fatalf("with the certificate: %+v", s)
	}
	if !strings.Contains(s.Reason, "threshold 0.50 that a signed calibration certificate sets") {
		t.Errorf("the reason: %q", s.Reason)
	}

	// Expired, the same certificate is refused and the declared gate holds.
	cal.Now = at.Add(25 * time.Hour)
	s, err = AskWith(context.Background(), m, state, trace, cal)
	if err != nil || s.To != "" || s.Certified || s.Certificate != "refused: "+calib.RefusedExpired {
		t.Errorf("with an expired certificate: %+v, %v", s, err)
	}
}
