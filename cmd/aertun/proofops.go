// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/ops"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

// keepMade keeps a proof a command of this store just made and signed, so
// the proving ground shows it without anybody handing it in. A failure is
// said, never fatal: the proof file is the command's output either way.
func keepMade(root string, env *proof.Envelope, pub []byte, by string) {
	body, err := json.Marshal(env)
	if err == nil {
		_, _, err = proofstore.Keep(root, body, pub, by, proofstore.OriginHere, time.Now())
	}
	if err != nil && !errors.Is(err, proofstore.ErrAlreadyKept) {
		w.Human("the proof was not kept in the store: %v\n", err)
	}
}

// -- the command line's face ------------------------------------------------

// cliCaller is the command line's caller, asked about through the same
// authorise every command uses.
type cliCaller struct {
	root string
	c    *Caller
}

func (k cliCaller) Allowed(a auth.Action, area string) error { return authorise(k.root, k.c, a, area) }
func (k cliCaller) Agent() bool                              { return k.c.Kind == audit.KindAI }
func (k cliCaller) Name() string                             { return k.c.Name }
func (k cliCaller) Record(action string, d map[string]string) error {
	return recordE(k.root, audit.Record{Action: action, Resource: "/proofs", Outcome: audit.Success,
		Principal: k.c.Name, Kind: k.c.Kind, Model: k.c.Model, Verified: k.c.Verified, Detail: d})
}

// runOpCommand runs an operation from the command line: its arguments as
// flags (its positional one, if any, after them), a document as the path of
// a file, the answer as labelled JSON with --json or as text for a person.
func runOpCommand(root string, reg *ops.Registry, name string, args []string,
	human func(*answer) string) error {
	op, ok := reg.Get(name)
	if !ok {
		return ops.ErrUnknown
	}
	fs := flag.NewFlagSet(op.CLI, flag.ContinueOnError)
	vals := map[string]*string{}
	var positional *ops.Arg
	for i, a := range op.Args {
		if a.Positional {
			positional = &op.Args[i]
			continue
		}
		about := a.About
		if a.Kind == ops.Document {
			about += " (a file)"
		}
		vals[a.Name] = fs.String(strings.ReplaceAll(a.Name, "_", "-"), "", about)
	}
	// Flags on either side of the positional argument, as a person types
	// them: the flag package stops at the first word that is not a flag, so
	// what follows it is parsed again.
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		rest = append(rest, fs.Arg(0))
		args = fs.Args()[1:]
	}
	raw := map[string]string{}
	for k, v := range vals {
		if *v != "" {
			raw[k] = *v
		}
	}
	switch {
	case positional != nil && len(rest) == 1:
		raw[positional.Name] = rest[0]
	case len(rest) > 0:
		return fmt.Errorf("%s takes %s", op.CLI, usageOf(op))
	}
	for _, a := range op.Args {
		if v, ok := raw[a.Name]; ok && a.Kind == ops.Document {
			body, err := proof.ReadBounded(v, int64(a.Max))
			if err != nil {
				return err
			}
			raw[a.Name] = string(body)
		}
	}
	ans, err := reg.Invoke(name, cliCaller{root, resolveCaller(root, flagToken)}, raw, time.Now().UTC())
	if err != nil {
		return err
	}
	text, err := ans.Labelled()
	if err != nil {
		return err
	}
	if w.JSON(json.RawMessage(text)) {
		return nil
	}
	w.Human("%s\n", human(ans))
	return nil
}

func usageOf(op ops.Op) string {
	var parts []string
	for _, a := range op.Args {
		switch {
		case a.Positional:
			parts = append(parts, strings.ToUpper(a.Name))
		case a.Required:
			parts = append(parts, "--"+strings.ReplaceAll(a.Name, "_", "-")+" VALUE")
		}
	}
	return strings.Join(parts, " ")
}

// humanProofs is a listing as a person reads it.
func humanProofs(a *answer) string {
	var b strings.Builder
	rows := a.Get("proofs").Items()
	fmt.Fprintf(&b, "%s%d proof(s) kept%s", bold, a.Get("kept").Value(), reset)
	if n, _ := a.Get("broken").Value().(int); n > 0 {
		fmt.Fprintf(&b, ", %d no longer verifying", n)
	}
	for _, r := range rows {
		if br := r.Get("broken"); br != nil {
			fmt.Fprintf(&b, "\n\n%s  BROKEN: %s", r.Get("id").Text(), br.Text())
			continue
		}
		fmt.Fprintf(&b, "\n\n%s%s%s  %s, %s  %s\n  %s\n  %s", bold, strings.ToUpper(r.Get("verdict").Text()), reset,
			r.Get("kind").Text(), r.Get("id").Text(), r.Get("kept_at").Text(), r.Get("claim").Text(), signedBy(r))
		if e := r.Get("expires"); e != nil {
			fmt.Fprintf(&b, "\n  expires %s", e.Text())
		}
	}
	return b.String()
}

// signedBy says whose key signed a proof: a signer this store trusts, by
// name, or a key it does not.
func signedBy(a *answer) string {
	if s := a.Get("signer"); s != nil && s.Text() != "" {
		return "signed by " + s.Text() + ", a trusted signer (key " + a.Get("key_id").Text() + ")"
	}
	return "signed by key " + a.Get("key_id").Text() + ", which this store does not trust"
}

// humanProof is one proof as a person reads it.
func humanProof(a *answer) string {
	var b strings.Builder
	if br := a.Get("broken"); br != nil {
		return a.Get("id").Text() + " no longer verifies: " + br.Text()
	}
	fmt.Fprintf(&b, "%s%s%s  %s  %s\n  %s\n  %s, kept %s by %s (%s)",
		bold, strings.ToUpper(a.Get("verdict").Text()), reset, a.Get("kind").Text(),
		a.Get("subject").Text(), a.Get("claim").Text(), signedBy(a),
		a.Get("kept_at").Text(), a.Get("kept_by").Text(), a.Get("origin").Text())
	for _, c := range a.Get("checks").Items() {
		mark := "pass"
		if c.Get("passed").Value() != true {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "\n  %s  %s: %s", mark, c.Get("name").Text(), c.Get("detail").Text())
		for _, f := range c.Get("failures").Items() {
			fmt.Fprintf(&b, "\n        - %s", f.Text())
		}
	}
	return b.String()
}
