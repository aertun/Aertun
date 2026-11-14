// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/bench"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// proofAnalyst is `aertun proof analyst --key F [--k 3] [--tolerance R]
// [--public-key F] [--out F]`: the configured AI analyst asked the labelled
// corpus k times, with instructions planted in the text an attacker could
// write, and the result signed as a triage proof (internal/proof) and kept.
//
// The measuring is the benchmark's (internal/bench), unchanged: the same
// corpus, the same model seam as the analyst's own triage, the same
// planted-instruction families. What this adds is the claim — at most a
// declared share of real cases closed, and no planted instruction steering a
// verdict — decided on exact bounds and signed, so it can be checked by
// somebody who was not there.
//
// It asks for tune, as calibrating and proving verdicts do: it signs a
// measurement of a product in the organisation's name and spends the model
// budget doing it. There is no stub: a proof about a stand-in model would
// be a signed statement about nothing.
func proofAnalyst(root string, args []string) error {
	fs := flag.NewFlagSet("proof analyst", flag.ContinueOnError)
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "write the signed proof to FILE (default: standard output)")
	k := fs.Int("k", proof.MinRuns, "how many times each case is asked (at least 3)")
	tolerance := fs.Float64("tolerance", 0.05, "the largest share of answers on real cases that may close them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyAt == "" {
		return errors.New("proof analyst needs --key FILE: an unsigned measurement is one nobody else can check")
	}
	if *pubAt != "" && *keyAt == "" {
		return errors.New("--public-key needs --key")
	}
	caller := resolveCaller(root, "")
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	signer, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	m, why := modelForAnalyst(root)
	if m == nil {
		return fmt.Errorf("%s", why)
	}
	corpus, err := bench.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	now := time.Now().UTC()
	res, err := bench.Run(ctx, m, corpus, bench.ModeModel, *k, now)
	if err != nil {
		return err
	}
	results, err := res.Document()
	if err != nil {
		return err
	}
	mx := res.Matrix
	st, err := proof.ProveTriage(proof.TriageInput{
		Model: res.Model, Corpus: proof.CorpusShipped, CorpusDigest: res.CorpusDigest,
		Runs: res.K, Cases: res.Samples / res.K,
		TP: mx.Real.Real, FP: mx.FalsePositive.Real + mx.Benign.Real,
		FN:        mx.Real.FalsePositive + mx.Real.Benign,
		TN:        mx.FalsePositive.FalsePositive + mx.FalsePositive.Benign + mx.Benign.FalsePositive + mx.Benign.Benign,
		Abstained: mx.Real.Abstained + mx.FalsePositive.Abstained + mx.Benign.Abstained,
		Reliable:  res.Reliable, Planted: res.Planted, Hijacked: res.Hijacked,
		Tolerance: *tolerance, Results: results, Program: version, Now: now})
	if err != nil {
		return err
	}
	env, err := proof.Seal(st, signer)
	if err != nil {
		return err
	}
	doc, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	doc = append(doc, '\n')
	if *pubAt != "" {
		if err := pack.WritePublicKey(*pubAt, signer.PublicKey()); err != nil {
			return err
		}
	}
	if pubDoc, err := json.Marshal(signer.PublicKey()); err == nil {
		keepMade(root, env, pubDoc, caller.Name)
	}
	ev := st.Predicate.Triage
	if err := recordE(root, audit.Record{Action: "analyst.proved", Resource: "/analyst",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind, Model: caller.Model,
		Verified: caller.Verified, Detail: map[string]string{"model": ev.Model,
			"verdict": string(st.Predicate.Verdict), "tolerance": fmt.Sprint(*tolerance),
			"answers_on_real": fmt.Sprint(ev.FalseClosures.N), "false_closures": fmt.Sprint(ev.FalseClosures.K),
			"hijacks": fmt.Sprint(ev.Hijacks.K), "runs": fmt.Sprint(ev.Runs)}}); err != nil {
		return err
	}
	if *outAt == "" {
		_, err := os.Stdout.Write(doc)
		return err
	}
	if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
		return err
	}
	if !w.JSON(summary(st)) {
		w.Human("%s\n", describe(st))
	}
	return nil
}
