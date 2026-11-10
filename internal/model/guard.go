// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"

	"github.com/aertun/aertun/internal/pii"
	"github.com/aertun/aertun/internal/plaintext"
	"github.com/aertun/aertun/internal/secret"
)

// Guarded is a model behind a privacy guard: what may not leave is masked
// before the prompt does, and put back in the answer. What draws nothing is
// taken out first, so text nobody could read on a screen is not sent to a
// model either (internal/plaintext).
type Guarded struct {
	Model Model
	// Personal says it may receive personal data.
	Personal   bool
	OwnDomains []string
	OnMasked   func(counts map[string]int)
}

func (g Guarded) Name() string { return g.Model.Name() }

func (g Guarded) Complete(ctx context.Context, system, user string) (string, error) {
	out, _, err := g.CompleteMetered(ctx, system, user)
	return out, err
}

func (g Guarded) CompleteMetered(ctx context.Context, system, user string) (string, Usage, error) {
	r, err := g.guarded(system, user, func(sys, usr string) (Reply, error) {
		if mm, ok := g.Model.(Metered); ok {
			out, used, err := mm.CompleteMetered(ctx, sys, usr)
			return Reply{Text: out, Raw: out, Usage: used}, err
		}
		out, err := g.Model.Complete(ctx, sys, usr)
		return Reply{Text: out, Raw: out, Usage: Estimate(sys+usr, out)}, err
	})
	return r.Text, r.Usage, err
}

// CompleteReply is CompleteMetered with the reply's token probabilities,
// when the model behind the guard can return them. The request for them is
// the one thing that passes through beside the masked prompt: the guard
// has never carried sampling knobs, and asking for probabilities does not
// change that. Text has the masked values put back; Raw stays as the model
// produced it, because Raw is what the tokens spell.
func (g Guarded) CompleteReply(ctx context.Context, system, user string, p Params) (Reply, error) {
	rm, ok := g.Model.(Replier)
	if !ok {
		out, used, err := g.CompleteMetered(ctx, system, user)
		return Reply{Text: out, Raw: out, Usage: used}, err
	}
	return g.guarded(system, user, func(sys, usr string) (Reply, error) {
		return rm.CompleteReply(ctx, sys, usr, Params{Logprobs: p.Logprobs})
	})
}

// guarded masks the prompt, asks, counts what was masked, and puts the
// masked values back into the reply's text.
func (g Guarded) guarded(system, user string, ask func(sys, usr string) (Reply, error)) (Reply, error) {
	mask := &pii.Masker{Allowed: g.OwnDomains, Secrets: secret.Spans}
	sys, a := plaintext.Visible(system)
	usr, b := plaintext.Visible(user)
	sys, usr = mask.Mask(sys, g.Personal), mask.Mask(usr, g.Personal)
	r, err := ask(sys, usr)
	counts := mask.Masked()
	if a+b > 0 {
		counts["invisible"] = a + b
	}
	if len(counts) > 0 && g.OnMasked != nil {
		g.OnMasked(counts)
	}
	r.Text = mask.Restore(r.Text)
	return r, err
}
