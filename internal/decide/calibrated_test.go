// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/calib"
	"github.com/aertun/aertun/internal/model"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

var verdict = Decider{Name: "triage", Title: "First pass", Questions: []Question{
	{Name: "verdict", Ask: "Real or not?", Kind: Choice,
		Options: []string{"real", "false-positive", "benign"}},
}}

var at = time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)

// replying is a model that answers with a Reply, spelling the verdict word
// in its own token with the probability given, or with no tokens at all
// when prob is zero.
type replying struct {
	word       string
	conf, prob float64
	asked      []model.Params
}

func (r *replying) Name() string { return "replying" }
func (r *replying) Complete(context.Context, string, string) (string, error) {
	return "", nil
}
func (r *replying) CompleteReply(_ context.Context, _, _ string, p model.Params) (model.Reply, error) {
	r.asked = append(r.asked, p)
	head := `{"answers":{"verdict":{"value":"`
	tail := `","confidence":` + strings.TrimRight(strings.TrimRight(
		jsonNumber(r.conf), "0"), ".") + `}}}`
	text := head + r.word + tail
	out := model.Reply{Text: text, Raw: text}
	if r.prob > 0 {
		out.Tokens = []model.Token{{Text: head, Logprob: 0}, {Text: r.word, Logprob: math.Log(r.prob)},
			{Text: tail, Logprob: 0}}
	}
	return out, nil
}

func jsonNumber(f float64) string { b, _ := json.Marshal(f); return string(b) }

// certificate signs a proven certificate for d on model name, at
// threshold 0.71 on the given channel: two hundred closing suggestions
// people ruled benign, scored 0.92, and forty that were real at 0.70.
func certificate(t *testing.T, k *pack.Key, name string, d Decider, channel string, edit func(*calib.Input)) []byte {
	t.Helper()
	var points []calib.Point
	p92, p70 := 0.92, 0.70
	for i := 0; i < 200; i++ {
		pt := calib.Point{Verdict: "benign", Confidence: 0.92, Label: "benign"}
		if channel == proof.ChannelLogprob {
			pt.Probability = &p92
		}
		points = append(points, pt)
	}
	for i := 0; i < 40; i++ {
		pt := calib.Point{Verdict: "false-positive", Confidence: 0.70, Label: calib.LabelReal}
		if channel == proof.ChannelLogprob {
			pt.Probability = &p70
		}
		points = append(points, pt)
	}
	in := calib.Input{Model: name, Template: TemplateDigest(d), Family: d.Name,
		Points: points, Epsilon: 0.05, Delta: 0.05, ValidFor: 30 * 24 * time.Hour,
		Program: "test", Now: at}
	if edit != nil {
		edit(&in)
	}
	st, err := calib.Certify(in)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Verdict != proof.Proven || st.Predicate.Calibration.Threshold != 0.71 {
		t.Fatalf("the fixture certificate is %s at %v", st.Predicate.Verdict,
			st.Predicate.Calibration.Threshold)
	}
	env, err := proof.Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env)
	return b
}

func answer(t *testing.T, m Model, d Decider, cal *Calibration) (Result, Answer) {
	t.Helper()
	res, err := DecideWith(context.Background(), d, m, map[string]string{"x": "y"}, cal)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := res.Get("verdict")
	return res, a
}

// With no certificate offered, nothing about the gate changes: the answer
// is held to the declared threshold and says nothing about certificates.
func TestWithoutACertificateTheDeclaredThresholdGates(t *testing.T) {
	m := &replying{word: "benign", conf: 0.75}
	res, a := answer(t, m, verdict, nil)
	if !a.Escalate || a.Certified || a.Threshold != 0 || res.Certificate != "" ||
		!strings.Contains(a.Why, "under the 0.80 threshold") {
		t.Fatalf("result %+v", res)
	}
}

// A valid certificate's threshold gates in place of the declared one, and
// the answer says so.
func TestAValidCertificateSetsTheGate(t *testing.T) {
	k, _ := pack.GenerateKey()
	m := &replying{word: "benign", conf: 0.75}
	cal := &Calibration{Certificate: certificate(t, k, m.Name(), verdict, proof.ChannelStated, nil),
		Key: k.PublicKey(), Now: at.Add(time.Hour)}
	res, a := answer(t, m, verdict, cal)
	if a.Escalate || !a.Certified || a.Threshold != 0.71 || res.Certificate != CertificateUsed ||
		a.Value != "benign" {
		t.Fatalf("result %+v", res)
	}
}

// Every way a certificate can fail to describe what it is gating refuses
// it, says why in one of a closed set of words, and sends every answer to a
// person — even one confident enough to clear the declared threshold, since
// falling back to the guess is what the certificate was offered to replace.
func TestACertificateThatDoesNotFitIsRefusedAndAPersonDecides(t *testing.T) {
	k, _ := pack.GenerateKey()
	other, _ := pack.GenerateKey()
	m := &replying{word: "benign", conf: 0.95}
	good := certificate(t, k, m.Name(), verdict, proof.ChannelStated, nil)
	reworded := verdict
	reworded.Context = "Answer carefully."
	adapter := strings.Repeat("ab", 32)
	cases := map[string]struct {
		cal *Calibration
		d   Decider
	}{
		calib.RefusedExpired:   {&Calibration{Certificate: good, Key: k.PublicKey(), Now: at.Add(31 * 24 * time.Hour)}, verdict},
		calib.RefusedNotYet:    {&Calibration{Certificate: good, Key: k.PublicKey(), Now: at.Add(-time.Hour)}, verdict},
		calib.RefusedSignature: {&Calibration{Certificate: good, Key: other.PublicKey(), Now: at}, verdict},
		calib.RefusedTemplate:  {&Calibration{Certificate: good, Key: k.PublicKey(), Now: at}, reworded},
		calib.RefusedAdapter:   {&Calibration{Certificate: good, Key: k.PublicKey(), Adapter: adapter, Now: at}, verdict},
		calib.RefusedModel: {&Calibration{Certificate: certificate(t, k, "another-model", verdict,
			proof.ChannelStated, nil), Key: k.PublicKey(), Now: at}, verdict},
		calib.RefusedUnreadable: {&Calibration{Certificate: []byte("not a certificate"),
			Key: k.PublicKey(), Now: at}, verdict},
	}
	for reason, c := range cases {
		res, a := answer(t, m, c.d, c.cal)
		if res.Certificate != "refused: "+reason {
			t.Errorf("%s: the result says %q", reason, res.Certificate)
		}
		if !a.Escalate || a.Certified || !res.Escalate ||
			a.Why != "the calibration certificate was refused: "+reason+", so a person decides" {
			t.Errorf("%s: a refused certificate let an answer through: %+v", reason, a)
		}
	}
}

// A certificate fitted on token probabilities gates answers on token
// probabilities, and only those: an answer that came without them goes to
// a person, however confident it says it is.
func TestATokenCertificateGatesOnlyAnswersWithTokenProbabilities(t *testing.T) {
	k, _ := pack.GenerateKey()
	probed := &replying{word: "benign", conf: 0.5, prob: 0.9}
	cert := certificate(t, k, probed.Name(), verdict, proof.ChannelLogprob, nil)
	cal := &Calibration{Certificate: cert, Key: k.PublicKey(), Now: at}
	res, a := answer(t, probed, verdict, cal)
	if a.Escalate || !a.Certified || a.Threshold != 0.71 || a.Probability == nil ||
		math.Abs(*a.Probability-0.9) > 1e-12 {
		t.Fatalf("result %+v", res)
	}
	// Every sample asked for the probabilities, with the draw it always had.
	for _, p := range probed.asked {
		if !p.Logprobs || p.Temperature == nil || p.Seed == nil {
			t.Errorf("a sample was asked %+v", p)
		}
	}

	bare := &replying{word: "benign", conf: 0.95}
	res, a = answer(t, bare, verdict, cal)
	if res.Certificate != CertificateUsed || a.Certified || !a.Escalate || a.Probability != nil ||
		!strings.Contains(a.Why, "without token probabilities") {
		t.Fatalf("an answer without token probabilities was gated by a token certificate: %+v", res)
	}
}

// flaky gives token probabilities on some samples and not on others.
type flaky struct{ n int }

func (f *flaky) Name() string { return "flaky" }
func (f *flaky) Complete(context.Context, string, string) (string, error) {
	return "", nil
}
func (f *flaky) CompleteReply(ctx context.Context, sys, user string, p model.Params) (model.Reply, error) {
	f.n++
	prob := 0.99
	if f.n%2 == 0 {
		prob = 0
	}
	return (&replying{word: "benign", conf: 0.9, prob: prob}).CompleteReply(ctx, sys, user, p)
}

// A probability averaged over only the samples that happened to carry one
// would be a score for a sample nobody chose; with any sample missing it,
// the answer has no token score at all.
func TestATokenScoreNeedsEverySample(t *testing.T) {
	_, a := answer(t, &flaky{}, verdict, nil)
	if a.Probability != nil {
		t.Errorf("an answer with a sample missing token probabilities scored %v", *a.Probability)
	}
	_, a = answer(t, &replying{word: "benign", conf: 0.9, prob: 0.99}, verdict, nil)
	if a.Probability == nil || math.Abs(*a.Probability-0.99) > 1e-12 {
		t.Errorf("every sample carried them, and the score is %v", a.Probability)
	}
}

// The probability is of the word chosen, found where the reply spells it.
func TestTheTokenProbabilityIsOfTheChosenWord(t *testing.T) {
	head := `{"answers":{"verdict":{"value":"`
	for name, c := range map[string]struct {
		raw  string
		word string
		ok   bool
	}{
		"plain":        {head + `benign","confidence":0.9}}}`, "benign", true},
		"fenced":       {"```json\n" + head + `benign","confidence":0.9}}}` + "\n```", "benign", true},
		"spaced":       {`{ "answers" : { "verdict" : { "confidence": 0.9, "value" : "benign" } } }`, "benign", true},
		"another word": {head + `real","confidence":0.9}}}`, "benign", false},
		// The i written as a JSON escape: the same word decoded, other bytes.
		"escaped":         {head + "ben" + string(rune(92)) + "u0069" + `gn","confidence":0.9}}}`, "benign", false},
		"another key":     {`{"answers":{"other":{"value":"benign"}}}`, "benign", false},
		"not an object":   {`["benign"]`, "benign", false},
		"value a boolean": {`{"answers":{"verdict":{"value":true}}}`, "true", false},
	} {
		start, end, ok := valueSpan(c.raw, "verdict", c.word)
		if ok != c.ok {
			t.Errorf("%s: found %v", name, ok)
			continue
		}
		if ok && c.raw[start:end] != c.word {
			t.Errorf("%s: the span is %q", name, c.raw[start:end])
		}
	}
}

// The template digest moves with anything about how the decider asks, and
// not with the threshold a certificate sets.
func TestTheTemplateDigestNamesHowTheQuestionIsAsked(t *testing.T) {
	base := TemplateDigest(verdict)
	gated := verdict
	gated.MinConfidence = 0.6
	if TemplateDigest(gated) != base {
		t.Error("the threshold moved the template digest")
	}
	for name, edit := range map[string]func(*Decider){
		"context": func(d *Decider) { d.Context = "Be brief." },
		"question": func(d *Decider) {
			d.Questions = []Question{{Name: "verdict", Ask: "Is it real?", Kind: Choice, Options: d.Questions[0].Options}}
		},
		"samples": func(d *Decider) { d.Samples = 5 },
	} {
		d := verdict
		edit(&d)
		if TemplateDigest(d) == base {
			t.Errorf("changing the %s left the template digest alone", name)
		}
	}
}
