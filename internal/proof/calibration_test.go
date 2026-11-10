// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"strings"
	"testing"
	"time"
)

const tmpl = "abababababababababababababababababababababababababababababababab"

// calibrationStatement is a proven certificate written out by hand: 200
// closing suggestions at threshold 0.71, none on a real finding.
func calibrationStatement() *Statement {
	ev := &CalibrationEvidence{Model: "m", Template: tmpl, Family: "triage",
		Channel: ChannelStated, Epsilon: 0.05, Delta: 0.05, Method: CalibrationMethod,
		Candidates: len(CalibrationGrid()), Cases: 240, Real: 40, Threshold: 0.71,
		Closures: 200, FalseClosures: 0, Upper: CalibrationUpper(0, 200, 0.05, 51),
		Expires: tnow.Add(30 * 24 * time.Hour).Format(time.RFC3339)}
	return &Statement{Type: StatementType,
		Subject:       []Subject{{Name: "m", Digest: AnalystDigest("m", "", tmpl)}},
		PredicateType: PredicateCalibration,
		Predicate: Predicate{Verdict: Proven, Claim: "a threshold holds",
			Verifier:    VerifierID{ID: "aertun/calibration", Version: "1"},
			Checks:      []Check{{Name: "false-closures", Passed: true}},
			Calibration: ev, VerifiedAt: tnow.Format(time.RFC3339)}}
}

func TestACalibrationCertificateRoundTrips(t *testing.T) {
	k := mustKey(t)
	env, err := Seal(calibrationStatement(), k)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(env, k.PublicKey())
	if err != nil || st.Predicate.Calibration.Closures != 200 {
		t.Fatalf("%+v, %v", st, err)
	}
}

// Validate accepts exactly the predicates that exist, each with its own
// evidence and no other kind beside it.
func TestEachPredicateCarriesItsOwnEvidenceAndNoOther(t *testing.T) {
	cases := map[string]func() *Statement{
		"a detection proof with no evidence": func() *Statement {
			st := prove(t, goodCorpus(t))
			st.Predicate.Detection = nil
			return st
		},
		"a detection proof with calibration evidence": func() *Statement {
			st := prove(t, goodCorpus(t))
			st.Predicate.Calibration = calibrationStatement().Predicate.Calibration
			return st
		},
		"a calibration certificate with no evidence": func() *Statement {
			st := calibrationStatement()
			st.Predicate.Calibration = nil
			return st
		},
		"a predicate this version does not know": func() *Statement {
			st := calibrationStatement()
			st.PredicateType = "https://aertun.github.io/proof/vibes/v1"
			return st
		},
		"calibration evidence under the detection predicate": func() *Statement {
			st := calibrationStatement()
			st.PredicateType = PredicateDetection
			return st
		},
	}
	for name, build := range cases {
		if err := build().Validate(); err == nil {
			t.Errorf("%s validated", name)
		}
	}
	if err := calibrationStatement().Validate(); err != nil {
		t.Errorf("the well-formed certificate: %v", err)
	}
}

// The signed bound is recomputed from the signed counts, and the counts
// have to be possible.
func TestACalibrationBoundMustFollowFromItsCounts(t *testing.T) {
	for name, edit := range map[string]func(*CalibrationEvidence){
		"a bound smaller than the counts allow": func(e *CalibrationEvidence) { e.Upper = 0.01 },
		"more false closures than closures":     func(e *CalibrationEvidence) { e.FalseClosures = 201 },
		"more false closures than real cases":   func(e *CalibrationEvidence) { e.FalseClosures, e.Closures = 41, 210 },
		"a method this version cannot check":    func(e *CalibrationEvidence) { e.Method = "eyeballed" },
		"fewer candidates than were examined":   func(e *CalibrationEvidence) { e.Candidates = 1 },
		"a channel that is not one":             func(e *CalibrationEvidence) { e.Channel = "vibes" },
		"an adapter that is not a digest":       func(e *CalibrationEvidence) { e.Adapter = "lora" },
	} {
		st := calibrationStatement()
		edit(st.Predicate.Calibration)
		err := st.Validate()
		if err == nil {
			t.Errorf("%s validated", name)
		}
	}
	st := calibrationStatement()
	st.Predicate.Calibration.Epsilon = 0.001
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "over its epsilon") {
		t.Errorf("a proven certificate over its epsilon: %v", err)
	}
}
