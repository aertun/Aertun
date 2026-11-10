// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package model is the one way this program asks a language model
// anything: an OpenAI-compatible chat completions endpoint, reached through
// the SSRF-hardened client, behind a privacy guard (Guarded).
//
// What a model returns is untrusted input. Nothing here acts on it; the
// callers parse it strictly and treat it as a suggestion a person decides.
package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aertun/aertun/internal/fetch"
)

// RequestTimeout bounds one completion.
const RequestTimeout = 120 * time.Second

// maxResponse bounds what is read of a reply, on the way in that worked
// and the way in that did not. A reply is one JSON object whose content
// is a few words, and 256 KiB is an order of magnitude above anything a
// completion needs; an endpoint that answers with more — broken, or
// hosted by somebody who would rather this read until it could not — is
// cut off there rather than read to the end.
const maxResponse = 256 << 10

// Model is anything that can answer a prompt. An interface so the tests can
// drive hostile responses through the same path a real model uses.
type Model interface {
	Complete(ctx context.Context, system, user string) (string, error)
	Name() string
}

// HTTPModel talks to any OpenAI-compatible chat completions endpoint, which
// covers Ollama Cloud, Bedrock behind a gateway, and most self-hosted servers.
// One shape rather than a provider per vendor.
type HTTPModel struct {
	BaseURL string
	APIKey  string
	Model   string
	Client  *http.Client

	// OnUsage, when set, is told what each completion used: the tokens the
	// provider reported, or an estimate from the length of the text when
	// the provider said nothing. Usage is otherwise computed and thrown
	// away — a cost nobody can see is a cost nobody can question.
	OnUsage func(Usage)

	// logprobs is what this endpoint has shown about token probabilities:
	// not yet asked, returns them, or does not. Learned from the first
	// request that asks and kept, so an endpoint that refuses the field
	// is asked for it once rather than on every call.
	logprobs atomic.Int32
}

// What an endpoint has shown about token probabilities.
const (
	logprobsUnknown int32 = iota
	logprobsReturned
	logprobsRefused
)

// StatusError is what a provider answered when it did not answer 200,
// kept with its status so a caller can tell a route that is unavailable
// from a request every route would refuse.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("model returned %d: %s", e.Code, e.Body) }

func (h *HTTPModel) Name() string { return h.Model }

// isLocalEndpoint reports whether a model endpoint is on this machine or this
// network, and says why when it is not.
//
// Resolved rather than pattern-matched on the hostname. "localhost" is a name
// somebody can point anywhere, and a check that trusts the spelling is a check
// that trusts DNS — so the address is looked up and judged, which is the same
// reasoning internal/fetch applies in the other direction.
//
// Unresolvable is not local. An endpoint nobody can reach is a misconfiguration
// either way, and guessing in the permissive direction would let a typo become
// a keyless call to whatever the name eventually resolves to.
func isLocalEndpoint(raw string) (bool, string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false, "it is not a URL this can read"
	}
	host := u.Hostname()
	if host == "" {
		return false, "it names no host"
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false, "its address could not be resolved"
	}
	// Every address, not the first. A name that resolves to both a loopback
	// address and a public one is not a local endpoint, and taking the first
	// answer would make the decision depend on resolver ordering.
	//
	// This is the message rather than the boundary. The same rule runs again
	// in Control, on the address actually being dialled, because a resolver
	// that answers differently the second time is how a checked address stops
	// being the connected one — see fetch.Speaking.
	for _, ip := range ips {
		if why := fetch.OnThisNetwork(ip); why != "" {
			// The reason already names the address, so it is not prefixed
			// with one: "it resolves to 169.254.169.254 is link-local" is
			// what that produces, and a message nobody can read is a message
			// people route around.
			return false, why
		}
	}
	return true, ""
}

// NewHTTPModel reads configuration from the environment.
func NewHTTPModel() (*HTTPModel, error) {
	base := os.Getenv("AERTUN_MODEL_URL")
	if base == "" {
		base = "https://ollama.com/v1"
	}
	key := os.Getenv("AERTUN_MODEL_KEY")
	if key == "" {
		key = os.Getenv("OLLAMA_API_KEY")
	}
	model := os.Getenv("AERTUN_MODEL")
	if model == "" {
		model = "gpt-oss:20b"
	}
	return NewHTTPModelAt(base, key, model)
}

// NewHTTPModelAt is a model at a given endpoint, under the same rule as the
// configured one: a keyless endpoint must resolve to this network, because a
// public endpoint that answers without a key is one anybody's traffic can
// reach and nobody is accountable for.
func NewHTTPModelAt(base, key, model string) (*HTTPModel, error) {
	if key == "" {
		local, why := isLocalEndpoint(base)
		if !local {
			return nil, fmt.Errorf(
				"no model key, and %s is not a model on this machine (%s).\n"+
					"  Set AERTUN_MODEL_KEY for a hosted endpoint, or point "+
					"AERTUN_MODEL_URL at a local one — Ollama, llama.cpp, LM "+
					"Studio and vLLM all serve this protocol and need no key",
				base, why)
		}
	}
	// A key over plain http is a key anybody on the path can read: sent
	// only over https, or to a model on this machine.
	if key != "" && strings.HasPrefix(strings.ToLower(base), "http://") {
		if local, _ := isLocalEndpoint(base); !local {
			return nil, fmt.Errorf("%s is plain http and not on this machine, and a model's key is sent only over https", base)
		}
	}
	reach := fetch.Anywhere
	if key == "" {
		reach = fetch.OnThisNetwork
	}
	return &HTTPModel{
		BaseURL: strings.TrimSuffix(base, "/"),
		APIKey:  key,
		Model:   model,
		Client:  fetch.Speaking("model", reach, RequestTimeout),
	}, nil
}

// Params is what one completion may ask the endpoint beyond the prompt: a
// temperature, a seed, a cap on the reply. Every field is nil when the
// caller has no opinion, and a field with no opinion is not sent — a
// request that sets nothing is the request this always built.
//
// Nil and an explicit zero stay different on purpose. temperature 0 is a
// promise of determinism the caller is making to itself, and a sampling
// caller that sent 0 by accident would get three identical replies and
// read them as agreement; that promise is not made on anybody's behalf.
//
// Seed is whatever the provider means by it — for OpenAI-compatible
// endpoints, a number that makes a given temperature draw reproducible.
// MaxTokens bounds the reply before the wire does; it is the caller's to
// set, because a reasoning model spends tokens before its answer and only
// a caller that knows its model knows how many.
type Params struct {
	Temperature *float64
	Seed        *int64
	MaxTokens   *int
	// Logprobs asks for the reply's token probabilities. Sent only to an
	// endpoint not already known to refuse them, and only on the call that
	// can hand them back (CompleteReply): requesting what is then thrown
	// away would make every reply larger for nothing.
	Logprobs bool
}

// Tuned is a model that takes Params for one call. Satisfied by HTTPModel;
// a wrapper that cannot carry parameters (the privacy guard forwards
// prompts, not sampling knobs) simply does not implement it, and its
// callers fall back to Complete.
type Tuned interface {
	CompleteTuned(ctx context.Context, system, user string, p Params) (string, error)
}

// Usage is what one completion used, as the provider reported it.
type Usage struct {
	In, Out int
	// Reported is false when the provider said nothing, and the counts are
	// estimated from the length of the text.
	Reported bool
}

// Estimate is a usage worked out from text alone: about four characters to
// a token, rounded up, which is what providers' own guides give for
// English and an overstatement for most other text.
func Estimate(in, out string) Usage {
	return Usage{In: (len(in) + 3) / 4, Out: (len(out) + 3) / 4}
}

// Metered is a model that says what each completion used.
type Metered interface {
	CompleteMetered(ctx context.Context, system, user string) (string, Usage, error)
}

// Token is one token of a reply and the log-probability the endpoint gave
// it.
type Token struct {
	Text    string
	Logprob float64
}

// Reply is a completion with what the endpoint said about it beyond the
// text.
type Reply struct {
	// Text is the reply as the caller reads it.
	Text string
	// Raw is the reply exactly as the model produced it — what Tokens
	// spell. The same as Text unless a wrapper rewrote Text: the privacy
	// guard puts masked values back into Text and leaves Raw alone.
	Raw   string
	Usage Usage
	// Tokens are the reply's tokens with their log-probabilities when the
	// endpoint returned them, and nil when it did not or was not asked.
	Tokens []Token
}

// maxTokens bounds how many token probabilities a reply carries. A reply
// is a few words; one longer than this has its probabilities dropped
// rather than walked.
const maxTokens = 4096

// Probability is the probability the model gave the bytes Raw[start:end]:
// the product of the probabilities of the tokens that spell them, a token
// that straddles an edge counting whole. False when there are no tokens,
// when the tokens do not spell Raw exactly, when a log-probability is not
// one (positive, or not a number), or when the span is not inside Raw — a
// probability that cannot be tied to the exact bytes it is about is not
// reported at all, and the caller falls back to what it had without one.
func (r Reply) Probability(start, end int) (float64, bool) {
	if len(r.Tokens) == 0 || start < 0 || end > len(r.Raw) || start >= end {
		return 0, false
	}
	pos, sum, covered := 0, 0.0, false
	for _, t := range r.Tokens {
		next := pos + len(t.Text)
		if next > len(r.Raw) || r.Raw[pos:next] != t.Text {
			return 0, false
		}
		if math.IsNaN(t.Logprob) || math.IsInf(t.Logprob, 0) || t.Logprob > 0 {
			return 0, false
		}
		if pos < end && next > start {
			sum += t.Logprob
			covered = true
		}
		pos = next
	}
	if pos != len(r.Raw) || !covered {
		return 0, false
	}
	return math.Exp(sum), true
}

// Replier is a model that hands back the whole Reply, token probabilities
// included when Params asks for them and the endpoint gives them.
type Replier interface {
	CompleteReply(ctx context.Context, system, user string, p Params) (Reply, error)
}

func (h *HTTPModel) Complete(ctx context.Context, system, user string) (string, error) {
	out, _, err := h.CompleteMetered(ctx, system, user)
	return out, err
}

// CompleteMetered is Complete, with what the provider says it used: the
// usage block every OpenAI-compatible server returns, or an estimate when
// it returns none.
func (h *HTTPModel) CompleteMetered(ctx context.Context, system, user string) (string, Usage, error) {
	r, err := h.exchange(ctx, system, user, Params{})
	return r.Text, r.Usage, err
}

// CompleteTuned is Complete with Params the endpoint may honour: a
// temperature and a seed that make the call a draw the caller chose rather
// than the server's default, and a cap on the reply. Params left nil are
// not sent, so a caller that sets none sends exactly what Complete sends.
func (h *HTTPModel) CompleteTuned(ctx context.Context, system, user string, p Params) (string, error) {
	// The text alone goes back from here, so token probabilities would be
	// asked for and dropped.
	p.Logprobs = false
	r, err := h.exchange(ctx, system, user, p)
	return r.Text, err
}

// CompleteReply is CompleteTuned returning the whole Reply. With
// p.Logprobs it asks for token probabilities where the endpoint is not
// known to refuse them, and keeps working where it does: an endpoint that
// answers without them is not asked again, and one that refuses the
// request outright (400 or 422 on the first request that asked) is asked
// once more without the field and not asked for it again. Either way the
// reply comes back with no Tokens, and the caller has the text it always
// had.
func (h *HTTPModel) CompleteReply(ctx context.Context, system, user string, p Params) (Reply, error) {
	return h.exchange(ctx, system, user, p)
}

// exchange is one completion, with the endpoint's token probabilities
// asked for when Params wants them and the endpoint has not shown it
// refuses them.
func (h *HTTPModel) exchange(ctx context.Context, system, user string, p Params) (Reply, error) {
	state := h.logprobs.Load()
	ask := p.Logprobs && state != logprobsRefused
	r, code, err := h.post(ctx, system, user, p, ask)
	if ask && state == logprobsUnknown &&
		(code == http.StatusBadRequest || code == http.StatusUnprocessableEntity) {
		// Some servers refuse a field they do not implement rather than
		// ignore it. The first refusal is taken as that, once: asked again
		// without the field, and never asked for it again, so a model that
		// cannot give probabilities is still a model that answers.
		h.logprobs.Store(logprobsRefused)
		r, _, err = h.post(ctx, system, user, p, false)
		return r, err
	}
	if ask && err == nil {
		if len(r.Tokens) > 0 {
			h.logprobs.Store(logprobsReturned)
		} else {
			h.logprobs.Store(logprobsRefused)
		}
	}
	return r, err
}

// post sends one request and reads its reply, returning the HTTP status
// beside the error so exchange can tell a refused field from a refused
// request.
func (h *HTTPModel) post(ctx context.Context, system, user string,
	p Params, logprobs bool) (Reply, int, error) {

	payload := map[string]any{
		"model": h.Model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"stream": false,
	}
	if p.Temperature != nil {
		payload["temperature"] = *p.Temperature
	}
	if p.Seed != nil {
		payload["seed"] = *p.Seed
	}
	if p.MaxTokens != nil && *p.MaxTokens > 0 {
		payload["max_tokens"] = *p.MaxTokens
	}
	if logprobs {
		payload["logprobs"] = true
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Reply{}, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		h.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Reply{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Omitted rather than sent empty. "Bearer " with nothing after it is a
	// credential that is present and blank, which some servers reject and
	// others log as a failed authentication — neither of which is what a
	// keyless local model meant to happen.
	if h.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.APIKey)
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		return Reply{}, 0, fmt.Errorf("model request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(io.LimitReader(resp.Body, maxResponse))
		snippet := strings.TrimSpace(buf.String())
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return Reply{}, resp.StatusCode, &StatusError{Code: resp.StatusCode, Body: snippet}
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Logprobs *struct {
				Content []struct {
					Token   string  `json:"token"`
					Logprob float64 `json:"logprob"`
				} `json:"content"`
			} `json:"logprobs"`
		} `json:"choices"`
		Usage *struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&out); err != nil {
		return Reply{}, resp.StatusCode, fmt.Errorf("cannot read the model's reply: %w", err)
	}
	if len(out.Choices) == 0 {
		return Reply{}, resp.StatusCode, fmt.Errorf("the model returned no choices")
	}
	text := out.Choices[0].Message.Content
	r := Reply{Text: text, Raw: text}
	if lp := out.Choices[0].Logprobs; logprobs && lp != nil && len(lp.Content) <= maxTokens {
		for _, t := range lp.Content {
			r.Tokens = append(r.Tokens, Token{Text: t.Token, Logprob: t.Logprob})
		}
	}
	u := Estimate(system+user, text)
	if out.Usage != nil && out.Usage.Prompt >= 0 && out.Usage.Completion >= 0 &&
		(out.Usage.Prompt > 0 || out.Usage.Completion > 0) {
		u = Usage{In: out.Usage.Prompt, Out: out.Usage.Completion, Reported: true}
	}
	if h.OnUsage != nil {
		h.OnUsage(u)
	}
	r.Usage = u
	return r, resp.StatusCode, nil
}
