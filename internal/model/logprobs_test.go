// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// verdictReply is a reply in the shape decide asks for, and the tokens a
// server that returns log-probabilities spells it with.
const verdictReply = `{"answers":{"verdict":{"value":"benign","confidence":0.9}}}`

var verdictTokens = []Token{
	{`{"answers":{"verdict":{"value":"`, -0.0001},
	{`ben`, math.Log(0.8)},
	{`ign`, math.Log(0.95)},
	{`","confidence":0.9}}}`, -0.0002},
}

// provider is a stub endpoint that records every request body and answers
// as its mode says: "returns" gives log-probabilities when asked, "ignores"
// answers without them, "refuses" answers 400 to any request carrying the
// field.
type provider struct {
	mu   sync.Mutex
	mode string
	seen []map[string]any
	srv  *httptest.Server
}

func newProvider(t *testing.T, mode string) *provider {
	t.Helper()
	p := &provider{mode: mode}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var got map[string]any
		_ = json.Unmarshal(b, &got)
		p.mu.Lock()
		p.seen = append(p.seen, got)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, asked := got["logprobs"]
		if p.mode == "refuses" && asked {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":{"message":"logprobs is not supported"}}`)
			return
		}
		choice := map[string]any{"message": map[string]any{"content": verdictReply}}
		if p.mode == "returns" && asked {
			var content []map[string]any
			for _, tk := range verdictTokens {
				content = append(content, map[string]any{"token": tk.Text,
					"logprob": tk.Logprob, "top_logprobs": []any{}})
			}
			choice["logprobs"] = map[string]any{"content": content}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{choice},
			"usage": map[string]any{"prompt_tokens": 50, "completion_tokens": 20}})
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *provider) model() *HTTPModel {
	return &HTTPModel{BaseURL: p.srv.URL, Model: "m", Client: p.srv.Client()}
}

// asked reports, for each request so far, whether it asked for
// log-probabilities.
func (p *provider) asked() []bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]bool, len(p.seen))
	for i, s := range p.seen {
		_, out[i] = s["logprobs"]
	}
	return out
}

// spanOf is where the verdict word sits in the reply.
func spanOf(word string) (int, int) {
	i := strings.Index(verdictReply, `"`+word+`"`) + 1
	return i, i + len(word)
}

// An endpoint that returns token probabilities has them asked for and
// handed back, and the probability of the chosen word is the product of
// the tokens that spell it.
func TestTokenProbabilitiesAreAskedForAndReturned(t *testing.T) {
	p := newProvider(t, "returns")
	h := p.model()
	for i := 0; i < 2; i++ {
		r, err := h.CompleteReply(context.Background(), "s", "u", Params{Logprobs: true})
		if err != nil {
			t.Fatal(err)
		}
		if r.Text != verdictReply || r.Raw != verdictReply || len(r.Tokens) != len(verdictTokens) {
			t.Fatalf("reply %+v", r)
		}
		start, end := spanOf("benign")
		got, ok := r.Probability(start, end)
		if !ok || math.Abs(got-0.8*0.95) > 1e-12 {
			t.Errorf("P(benign) = %v, %v; want %v", got, ok, 0.8*0.95)
		}
		if !r.Usage.Reported || r.Usage.In != 50 {
			t.Errorf("usage %+v", r.Usage)
		}
	}
	if a := p.asked(); len(a) != 2 || !a[0] || !a[1] {
		t.Errorf("requests asked for log-probabilities: %v", a)
	}
}

// An endpoint that answers without them keeps answering, and is not asked
// for them again: a field that comes back empty is a field the endpoint
// does not implement.
func TestAnEndpointThatIgnoresTheFieldIsNotAskedAgain(t *testing.T) {
	p := newProvider(t, "ignores")
	h := p.model()
	for i := 0; i < 3; i++ {
		r, err := h.CompleteReply(context.Background(), "s", "u", Params{Logprobs: true})
		if err != nil || r.Text != verdictReply {
			t.Fatalf("reply %+v, %v", r, err)
		}
		if _, ok := r.Probability(spanOf("benign")); ok || r.Tokens != nil {
			t.Errorf("a reply without log-probabilities gave a probability: %+v", r)
		}
	}
	if a := p.asked(); len(a) != 3 || !a[0] || a[1] || a[2] {
		t.Errorf("requests asked for log-probabilities: %v, want only the first", a)
	}
}

// An endpoint that refuses the field outright is asked once more without
// it, answers, and is never sent the field again.
func TestAnEndpointThatRefusesTheFieldStillAnswers(t *testing.T) {
	p := newProvider(t, "refuses")
	h := p.model()
	for i := 0; i < 2; i++ {
		r, err := h.CompleteReply(context.Background(), "s", "u", Params{Logprobs: true})
		if err != nil || r.Text != verdictReply || r.Tokens != nil {
			t.Fatalf("call %d: reply %+v, %v", i, r, err)
		}
	}
	if a := p.asked(); len(a) != 3 || !a[0] || a[1] || a[2] {
		t.Errorf("requests asked for log-probabilities: %v, want the first only", a)
	}
}

// A refusal of a request that never asked for the field is not mistaken for
// a refusal of the field, and is not retried.
func TestARefusalOnAnotherGroundIsNotRetried(t *testing.T) {
	h, _ := sent(t, http.StatusBadRequest)
	if _, err := h.CompleteReply(context.Background(), "s", "u", Params{}); err == nil {
		t.Fatal("a refused request came back as an answer")
	}
	if h.logprobs.Load() != logprobsUnknown {
		t.Errorf("a request that did not ask taught the model %d", h.logprobs.Load())
	}
}

// Once an endpoint has returned probabilities, a later refusal is a refusal
// of that request, not of the field: it is reported, not retried without
// the field, and the endpoint is still asked for them next time.
func TestALaterRefusalIsNotTakenForTheField(t *testing.T) {
	p := newProvider(t, "returns")
	h := p.model()
	if _, err := h.CompleteReply(context.Background(), "s", "u", Params{Logprobs: true}); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.mode = "refuses"
	p.mu.Unlock()
	if _, err := h.CompleteReply(context.Background(), "s", "u", Params{Logprobs: true}); err == nil {
		t.Fatal("a refused request came back as an answer")
	}
	if a := p.asked(); len(a) != 2 || !a[0] || !a[1] {
		t.Errorf("requests asked for log-probabilities: %v, want both and no retry", a)
	}
	if h.logprobs.Load() != logprobsReturned {
		t.Errorf("one refusal after a success taught the model %d", h.logprobs.Load())
	}
}

// Only the call that can hand probabilities back asks for them.
func TestTheTextOnlyCallsNeverAskForProbabilities(t *testing.T) {
	p := newProvider(t, "returns")
	h := p.model()
	temp := 0.7
	if _, err := h.CompleteTuned(context.Background(), "s", "u",
		Params{Temperature: &temp, Logprobs: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if a := p.asked(); len(a) != 2 || a[0] || a[1] {
		t.Errorf("requests asked for log-probabilities: %v", a)
	}
}

// A probability is reported only when the tokens spell the exact bytes it
// is about.
func TestAProbabilityIsTiedToTheExactBytes(t *testing.T) {
	start, end := spanOf("benign")
	good := Reply{Raw: verdictReply, Tokens: verdictTokens}
	if _, ok := good.Probability(start, end); !ok {
		t.Fatal("the aligned reply gave no probability")
	}
	misspelt := append([]Token(nil), verdictTokens...)
	misspelt[1] = Token{"rea", math.Log(0.8)}
	short := verdictTokens[:3]
	positive := append([]Token(nil), verdictTokens...)
	positive[2] = Token{"ign", 0.3}
	notANumber := append([]Token(nil), verdictTokens...)
	notANumber[2] = Token{"ign", math.NaN()}
	for name, r := range map[string]Reply{
		"tokens that spell other bytes": {Raw: verdictReply, Tokens: misspelt},
		"tokens that stop short":        {Raw: verdictReply, Tokens: short},
		"a positive log-probability":    {Raw: verdictReply, Tokens: positive},
		"a log-probability that is NaN": {Raw: verdictReply, Tokens: notANumber},
	} {
		if p, ok := r.Probability(start, end); ok {
			t.Errorf("%s gave probability %v", name, p)
		}
	}
	for _, span := range [][2]int{{-1, 3}, {start, len(verdictReply) + 1}, {end, start}} {
		if p, ok := good.Probability(span[0], span[1]); ok {
			t.Errorf("span %v gave probability %v", span, p)
		}
	}
}

// The guard passes the request for probabilities through and nothing else:
// sampling knobs stay behind, the masked values are put back into Text,
// and Raw is left as the model spelt it.
func TestTheGuardPassesTheRequestForProbabilitiesAndNoKnobs(t *testing.T) {
	p := newProvider(t, "returns")
	g := Guarded{Model: p.model()}
	temp, seed := 0.7, int64(9)
	r, err := g.CompleteReply(context.Background(), "s", "write to mira.k@mailhost.net",
		Params{Temperature: &temp, Seed: &seed, Logprobs: true})
	if err != nil || len(r.Tokens) == 0 || r.Raw != verdictReply {
		t.Fatalf("reply %+v, %v", r, err)
	}
	p.mu.Lock()
	sent := p.seen[0]
	p.mu.Unlock()
	if _, ok := sent["temperature"]; ok {
		t.Error("the guard forwarded a temperature")
	}
	if _, ok := sent["seed"]; ok {
		t.Error("the guard forwarded a seed")
	}
	if _, ok := sent["logprobs"]; !ok {
		t.Error("the guard dropped the request for probabilities")
	}
	if strings.Contains(sentText(sent), "mailhost") {
		t.Error("the guard let personal data through")
	}
	// A model that cannot return a Reply is asked the old way.
	h := &hearing{}
	r, err = Guarded{Model: h}.CompleteReply(context.Background(), "", "write to mira.k@mailhost.net",
		Params{Logprobs: true})
	if err != nil || r.Text != "Reply sent to mira.k@mailhost.net." || r.Tokens != nil {
		t.Fatalf("fallback reply %+v, %v", r, err)
	}
}

func sentText(body map[string]any) string {
	b, _ := json.Marshal(body["messages"])
	return string(b)
}
