// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package calib

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/stats"
)

var tnow = time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)

const template = "1111111111111111111111111111111111111111111111111111111111111111"

// world is a synthetic analyst whose false-closure rate is known exactly:
// every case is a closing suggestion with a stated confidence s drawn
// uniformly from [0.5, 1), and a person ruled it real with probability
// 0.25·(1−s)/0.5 — so the true false-closure rate among suggestions at or
// above a threshold t is 0.25·(1−t), and 0.05 is crossed at t = 0.8.
// Interleaved are answers of "real", which are never closures and must
// not move the fit.
type world struct{ rng *rand.Rand }

func (w world) draw(n int) []Point {
	out := make([]Point, 0, n)
	for len(out) < n {
		if w.rng.Float64() < 0.2 {
			out = append(out, Point{Verdict: LabelReal, Confidence: w.rng.Float64(), Label: LabelReal})
			continue
		}
		s := 0.5 + 0.5*w.rng.Float64()
		label := "benign"
		if w.rng.Float64() < 0.25*(1-s)/0.5 {
			label = LabelReal
		}
		verdict := "benign"
		if w.rng.IntN(2) == 0 {
			verdict = "false-positive"
		}
		out = append(out, Point{Verdict: verdict, Confidence: s, Label: label})
	}
	return out
}

func trueRate(t float64) float64 { return 0.25 * (1 - t) }

// measuredRate is the false-closure rate among closing suggestions at or
// above t, counted on points the fit never saw.
func measuredRate(points []Point, t float64) float64 {
	n, k := 0, 0
	for _, p := range points {
		if closing(p.Verdict) && p.Confidence >= t {
			n++
			if p.Label == LabelReal {
				k++
			}
		}
	}
	return float64(k) / float64(n)
}

// The promise a certificate makes, tested the way it is made: across many
// labelled sets drawn from one world, the threshold certified on each keeps
// the false-closure rate — measured on a large set the fit never saw, and
// worked out exactly from the world — under ε in at least 1−δ of them. A fit
// that picked the lowest threshold whose observed rate was under ε, without
// a bound, lands near 0.8 and breaks the promise about half the time.
func TestTheCertifiedThresholdKeepsFalseClosuresUnderEpsilonAcrossResamples(t *testing.T) {
	const (
		eps, delta = 0.05, 0.05
		resamples  = 400
		n          = 6000
	)
	w := world{rng: rand.New(rand.NewPCG(7, 11))}
	holdout := w.draw(200000)
	certified, overMeasured, overTrue := 0, 0, 0
	for i := 0; i < resamples; i++ {
		f := FitThreshold(w.draw(n), proof.ChannelStated, eps, delta)
		if !f.Certified {
			continue
		}
		certified++
		if measuredRate(holdout, f.Threshold) > eps {
			overMeasured++
		}
		if trueRate(f.Threshold) > eps {
			overTrue++
		}
	}
	if certified < resamples*9/10 {
		t.Fatalf("only %d of %d resamples certified a threshold; the test "+
			"measures nothing if the fit never commits", certified, resamples)
	}
	t.Logf("%d of %d resamples certified a threshold; false closures over %v "+
		"in %d of them measured, %d exactly", certified, resamples, eps,
		overMeasured, overTrue)
	if limit := int(delta * resamples); overMeasured > limit || overTrue > limit {
		t.Errorf("the certified threshold let false closures over %v in %d "+
			"(measured) and %d (exactly) of %d resamples; at confidence %v at "+
			"most %d may", eps, overMeasured, overTrue, resamples, 1-delta, limit)
	}
}

// The correction is exactly Bonferroni over the grid: the bound a fit
// states is Clopper–Pearson at δ/m, m the number of candidates. One hundred
// closing suggestions, none of them wrong, bound the rate under 5% at 95%
// for one threshold looked at alone (1 − 0.05^(1/100) ≈ 0.0295) and not
// once 51 were looked at (1 − (0.05/51)^(1/100) ≈ 0.0669), so the honest
// verdict is that the evidence is too thin.
func TestTheBoundIsCorrectedForEveryThresholdExamined(t *testing.T) {
	var points []Point
	for i := 0; i < 100; i++ {
		points = append(points, Point{Verdict: "benign", Confidence: 0.95, Label: "benign"})
	}
	m := len(proof.CalibrationGrid())
	if m != 51 {
		t.Fatalf("the grid has %d candidates", m)
	}
	f := FitThreshold(points, proof.ChannelStated, 0.05, 0.05)
	want := stats.ClopperPearsonUpper(0, 100, 1-0.05/51)
	if f.Certified || math.Abs(f.Upper-want) > 1e-12 {
		t.Errorf("fit %+v; the corrected bound is %v and does not certify", f, want)
	}
	if alone := stats.ClopperPearsonUpper(0, 100, 0.95); alone > 0.05 {
		t.Fatalf("the uncorrected bound %v would not have certified either; "+
			"the test shows nothing", alone)
	}
	st := certify(t, points)
	if st.Predicate.Verdict != proof.Inconclusive {
		t.Errorf("verdict %s", st.Predicate.Verdict)
	}
}

func certify(t *testing.T, points []Point) *proof.Statement {
	t.Helper()
	st, err := Certify(Input{Model: "gpt-oss:20b", Template: template, Family: "triage",
		Points: points, Epsilon: 0.05, Delta: 0.05, ValidFor: 30 * 24 * time.Hour,
		LeftOut: 2, Program: "test", Now: tnow})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// clean is a labelled set that certifies: n closing suggestions at 0.92
// that people ruled benign, and some lower-scored ones that were real.
func clean(n int) []Point {
	var out []Point
	for i := 0; i < n; i++ {
		out = append(out, Point{Verdict: "benign", Confidence: 0.92, Label: "benign"})
	}
	for i := 0; i < 40; i++ {
		out = append(out, Point{Verdict: "false-positive", Confidence: 0.7, Label: LabelReal})
	}
	return out
}

func TestEachVerdictIsEarnedByItsCounts(t *testing.T) {
	st := certify(t, clean(200))
	ev := st.Predicate.Calibration
	if st.Predicate.Verdict != proof.Proven || ev.Threshold != 0.71 || ev.Closures != 200 ||
		ev.FalseClosures != 0 || ev.Cases != 240 || ev.Real != 40 {
		t.Fatalf("verdict %s, evidence %+v", st.Predicate.Verdict, ev)
	}
	if ev.Upper != stats.ClopperPearsonUpper(0, 200, 1-0.05/51) || ev.Upper > 0.05 {
		t.Errorf("the signed bound %v is not the corrected bound of its counts", ev.Upper)
	}
	if !strings.Contains(st.Predicate.Checks[0].Detail, "2 decision(s) recorded by anybody else") {
		t.Errorf("the labels check does not say what was left out: %q", st.Predicate.Checks[0].Detail)
	}

	// Plenty of closing suggestions, and too many of them on real findings
	// at every threshold: evidence that could have certified, and did not.
	var wrong []Point
	for i := 0; i < 400; i++ {
		label := "benign"
		if i%5 == 0 {
			label = LabelReal
		}
		wrong = append(wrong, Point{Verdict: "benign", Confidence: 0.99, Label: label})
	}
	if st := certify(t, wrong); st.Predicate.Verdict != proof.Refuted ||
		st.Predicate.Calibration.FalseClosures != 80 || st.Predicate.Calibration.Closures != 400 {
		t.Errorf("a model that closes real findings a fifth of the time: %s %+v",
			st.Predicate.Verdict, st.Predicate.Calibration)
	}

	// Nothing to go on is inconclusive, never proven.
	if st := certify(t, nil); st.Predicate.Verdict != proof.Inconclusive {
		t.Errorf("an empty set is %s", st.Predicate.Verdict)
	}
	if st := certify(t, clean(3)); st.Predicate.Verdict != proof.Inconclusive {
		t.Errorf("three closing suggestions are %s", st.Predicate.Verdict)
	}
}

func TestTheChannelIsTheOneEveryAnswerWasScoredOn(t *testing.T) {
	p := 0.97
	logprob := []Point{{Verdict: "benign", Confidence: 0.6, Probability: &p, Label: "benign"},
		{Verdict: "", Confidence: 0, Label: LabelReal}}
	if got := Channel(logprob); got != proof.ChannelLogprob {
		t.Errorf("every answer carried a probability and the channel is %s", got)
	}
	mixed := append(logprob, Point{Verdict: "real", Confidence: 0.9, Label: LabelReal})
	if got := Channel(mixed); got != proof.ChannelStated {
		t.Errorf("a mixed set was fitted on %s", got)
	}
	// On the token channel the threshold is held against the probability,
	// not the stated confidence.
	var points []Point
	for i := 0; i < 200; i++ {
		points = append(points, Point{Verdict: "benign", Confidence: 0.55, Probability: &p, Label: "benign"})
	}
	st := certify(t, points)
	if ev := st.Predicate.Calibration; ev.Channel != proof.ChannelLogprob || ev.Threshold != 0.5 ||
		ev.Closures != 200 {
		t.Errorf("evidence %+v", ev)
	}
}

func TestAnInputThatCannotBeCertifiedHonestlyIsRefused(t *testing.T) {
	base := Input{Model: "m", Template: template, Family: "triage", Epsilon: 0.05,
		Delta: 0.05, ValidFor: time.Hour, Now: tnow}
	for name, mut := range map[string]func(*Input){
		"no model":            func(in *Input) { in.Model = "" },
		"a short template":    func(in *Input) { in.Template = "abc" },
		"an adapter not hex":  func(in *Input) { in.Adapter = "lora-v2" },
		"a family with space": func(in *Input) { in.Family = "tri age" },
		"epsilon of one":      func(in *Input) { in.Epsilon = 1 },
		"delta of zero":       func(in *Input) { in.Delta = 0 },
		"no validity":         func(in *Input) { in.ValidFor = 0 },
		"a year of validity":  func(in *Input) { in.ValidFor = 365 * 24 * time.Hour },
		"a label not a word":  func(in *Input) { in.Points = []Point{{Label: "probably"}} },
		"a score over one":    func(in *Input) { in.Points = []Point{{Verdict: "benign", Confidence: 1.5, Label: "benign"}} },
	} {
		in := base
		mut(&in)
		if _, err := Certify(in); err == nil {
			t.Errorf("%s was certified", name)
		}
	}
}

// sealed signs a proven certificate for the binding below.
func sealed(t *testing.T, k *pack.Key, edit func(*proof.Statement)) []byte {
	t.Helper()
	st := certify(t, clean(200))
	if edit != nil {
		edit(st)
	}
	env, err := proof.Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env)
	return b
}

var bound = Binding{Model: "gpt-oss:20b", Template: template, Family: "triage"}

func TestACertificateGatesOnlyTheAnalystItNames(t *testing.T) {
	k, _ := pack.GenerateKey()
	cert := sealed(t, k, nil)
	ev, err := Check(cert, k.PublicKey(), bound, tnow.Add(time.Hour))
	if err != nil || ev.Threshold != 0.71 {
		t.Fatalf("a valid certificate: %+v, %v", ev, err)
	}
	other := "2222222222222222222222222222222222222222222222222222222222222222"
	for want, b := range map[string]Binding{
		RefusedTemplate: {Model: bound.Model, Template: other, Family: "triage"},
		RefusedModel:    {Model: "gpt-oss:120b", Template: template, Family: "triage"},
		RefusedAdapter:  {Model: bound.Model, Adapter: other, Template: template, Family: "triage"},
		RefusedFamily:   {Model: bound.Model, Template: template, Family: "detect-tune"},
	} {
		if _, err := Check(cert, k.PublicKey(), b, tnow.Add(time.Hour)); Reason(err) != want {
			t.Errorf("binding %+v: %v, want %q", b, err, want)
		}
	}
}

func TestACertificateHoldsOnlyWhileItIsInForce(t *testing.T) {
	k, _ := pack.GenerateKey()
	cert := sealed(t, k, nil)
	for at, want := range map[time.Time]string{
		tnow.Add(30 * 24 * time.Hour):           RefusedExpired,
		tnow.Add(31 * 24 * time.Hour):           RefusedExpired,
		tnow.Add(-ClockSkew - time.Second):      RefusedNotYet,
		tnow.Add(-ClockSkew + time.Second):      "",
		tnow.Add(30*24*time.Hour - time.Second): "",
	} {
		_, err := Check(cert, k.PublicKey(), bound, at)
		if (want == "" && err != nil) || (want != "" && Reason(err) != want) {
			t.Errorf("at %s: %v, want %q", at, err, want)
		}
	}
}

func TestACertificateThatDoesNotVerifyIsRefused(t *testing.T) {
	k, _ := pack.GenerateKey()
	cert := sealed(t, k, nil)
	other, _ := pack.GenerateKey()
	if _, err := Check(cert, other.PublicKey(), bound, tnow); Reason(err) != RefusedSignature {
		t.Errorf("another key's certificate: %v", err)
	}
	// One half dropped.
	var env proof.Envelope
	_ = json.Unmarshal(cert, &env)
	env.Signatures = env.Signatures[:1]
	half, _ := json.Marshal(env)
	if _, err := Check(half, k.PublicKey(), bound, tnow); Reason(err) != RefusedSignature {
		t.Errorf("half a signature: %v", err)
	}
	// The threshold edited after signing.
	_ = json.Unmarshal(cert, &env)
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	edited := strings.Replace(string(payload), `"threshold":0.71`, `"threshold":0.5`, 1)
	if edited == string(payload) {
		t.Fatal("the test edited nothing")
	}
	env.Payload = base64.StdEncoding.EncodeToString([]byte(edited))
	tampered, _ := json.Marshal(env)
	if _, err := Check(tampered, k.PublicKey(), bound, tnow); Reason(err) != RefusedSignature {
		t.Errorf("an edited threshold: %v", err)
	}
	if _, err := Check([]byte("{not json"), k.PublicKey(), bound, tnow); Reason(err) != RefusedUnreadable {
		t.Errorf("garbage: %v", err)
	}
}

func TestOnlyAProvenCalibrationCertificateGates(t *testing.T) {
	k, _ := pack.GenerateKey()
	thin := certify(t, clean(3))
	env, err := proof.Seal(thin, k)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env)
	if _, err := Check(b, k.PublicKey(), bound, tnow); Reason(err) != RefusedNotProven {
		t.Errorf("an inconclusive certificate: %v", err)
	}
}

// A certificate whose numbers do not hold together cannot be signed: the
// bound must follow from the counts, and a proven verdict must sit under
// its epsilon.
func TestACertificateCannotStateABoundItsCountsDoNotSupport(t *testing.T) {
	k, _ := pack.GenerateKey()
	for name, edit := range map[string]func(*proof.Statement){
		"a smaller bound":       func(st *proof.Statement) { st.Predicate.Calibration.Upper = 0.001 },
		"fewer false closures":  func(st *proof.Statement) { st.Predicate.Calibration.Closures = 300 },
		"a threshold off-grid":  func(st *proof.Statement) { st.Predicate.Calibration.Threshold = 0.715 },
		"a looser epsilon used": func(st *proof.Statement) { st.Predicate.Calibration.Epsilon = 0.001 },
		"another analyst":       func(st *proof.Statement) { st.Subject[0].Digest = proof.SHA256([]byte("x")) },
		"no expiry":             func(st *proof.Statement) { st.Predicate.Calibration.Expires = "" },
		"a long life": func(st *proof.Statement) {
			st.Predicate.Calibration.Expires = tnow.Add(200 * 24 * time.Hour).Format(time.RFC3339)
		},
		"detection evidence too": func(st *proof.Statement) {
			st.Predicate.Detection = &proof.DetectionEvidence{Rule: "x"}
		},
	} {
		st := certify(t, clean(200))
		edit(st)
		if _, err := proof.Seal(st, k); err == nil {
			t.Errorf("%s was signed", name)
		}
	}
}
