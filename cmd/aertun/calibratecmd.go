// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/analyst"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/calib"
	"github.com/aertun/aertun/internal/decide"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// `analyst calibrate`: the analyst's threshold, fitted on what verified
// people ruled, and signed.
//
// Every finding people have ruled is put to the configured model the way
// triage puts it, as of the moment its verdict was recorded (verdictCases),
// and each answer's verdict and scores are paired with the person's ruling.
// internal/calib fits the lowest threshold whose false-closure rate it can
// bound under ε at confidence 1−δ and writes the certificate — proven,
// refuted or inconclusive, signed whichever it is. `analyst triage
// --calibration FILE --calibration-key PUB` then gates on the certified
// threshold, and internal/decide refuses a certificate that has expired, is
// for another model, adapter, template or task, or does not verify.
//
// The labels are the audit log's decisions, and only those a verified
// person recorded: a suggestion from a model is a different record and
// never a label, and a decision by a service, a model or an identity
// nobody proved is left out and counted. The chain must verify before
// anything is taken from it.

// adapterEnv names the adapter the configured model runs with.
const adapterEnv = "AERTUN_MODEL_ADAPTER_SHA256"

// modelAdapter is the sha256 of the adapter the configured model runs
// with, from AERTUN_MODEL_ADAPTER_SHA256, and empty for none. A certificate
// binds it, so a model measured with one adapter is not gated by a
// certificate fitted with another.
func modelAdapter() (string, error) {
	a := strings.ToLower(strings.TrimSpace(os.Getenv(adapterEnv)))
	if a == "" {
		return "", nil
	}
	if b, err := hex.DecodeString(a); err != nil || len(b) != 32 {
		return "", fmt.Errorf("%s is not a sha256 in hex; set it to the adapter's "+
			"digest, or unset it when the model runs without one", adapterEnv)
	}
	return a, nil
}

// peoplesVerdicts is the audit log with every decision that a verified
// person did not record taken out, and how many were. A decision by a
// service, by a model or by an identity nobody proved is not a label: a
// label is a verdict somebody accountable stands behind.
func peoplesVerdicts(events []audit.Event) ([]audit.Event, int) {
	decision := map[string]bool{}
	for _, s := range finding.States() {
		decision["finding."+string(s)] = true
	}
	out := make([]audit.Event, 0, len(events))
	left := 0
	for _, e := range events {
		if decision[e.Action] && (e.Kind != audit.KindHuman || !e.Verified) {
			left++
			continue
		}
		out = append(out, e)
	}
	return out, left
}

// verifiedCases is the ruled findings as cases labelled by verified
// people, from an audit chain that verifies, and how many decisions were
// left out.
func verifiedCases(root string, limit int, now time.Time) ([]analyst.Case, int, error) {
	reg, _, err := finding.Load(findingsPath(root))
	if err != nil {
		return nil, 0, err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, 0, err
	}
	if ok, problems := audit.Verify(events); !ok {
		p := problems[0]
		return nil, 0, fmt.Errorf("the audit log does not verify, so no "+
			"verdict can be taken from it: entry %d: %s", p.Seq, p.Reason)
	}
	kept, left := peoplesVerdicts(events)
	feeds, err := indicatorFeeds(root, reg.All(now))
	if err != nil {
		return nil, 0, err
	}
	return verdictCases(reg, kept, feeds, limit), left, nil
}

func analystCalibrate(root string, args []string) error {
	fs := flag.NewFlagSet("calibrate", flag.ContinueOnError)
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key triage and verify need")
	outAt := fs.String("out", "", "where to write the certificate (default: standard output)")
	eps := fs.Float64("epsilon", 0.05, "the false-closure rate the threshold must keep under")
	delta := fs.Float64("delta", 0.05, "the risk the bound is wrong: confidence is 1 minus this")
	validFor := fs.Duration("valid-for", 30*24*time.Hour, "how long the certificate holds, at most 2160h")
	limit := fs.Int("limit", 200, "how many ruled findings to fit on, spread across the three verdicts when there are more")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyAt == "" {
		return fmt.Errorf("calibrate needs --key FILE: an unsigned certificate is a " +
			"threshold anybody could have written")
	}
	if !(*eps > 0 && *eps < 1) || !(*delta > 0 && *delta < 1) {
		return fmt.Errorf("--epsilon and --delta are each between 0 and 1")
	}
	if *validFor <= 0 || *validFor > proof.MaxCalibrationValidity {
		return fmt.Errorf("--valid-for is between 1s and %v", proof.MaxCalibrationValidity)
	}
	if *limit < 1 || *limit > 2000 {
		return fmt.Errorf("--limit is between 1 and 2000")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	adapter, err := modelAdapter()
	if err != nil {
		return err
	}
	m, why := modelForAnalyst(root)
	if m == nil {
		return fmt.Errorf("%s", why)
	}
	now := time.Now().UTC()
	cases, left, err := verifiedCases(root, *limit, now)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	d := analyst.Decider()
	points := make([]calib.Point, 0, len(cases))
	for _, c := range cases {
		// The question exactly as triage asks it, gated at nothing in
		// particular: the fit needs the verdict and its scores whatever
		// the declared threshold would have made of them.
		res, err := decide.Decide(ctx, d, m, c.State)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		pt := calib.Point{Label: c.Expect}
		if a, ok := res.Get("verdict"); ok && a.Value != "" {
			pt.Verdict, pt.Confidence, pt.Probability = a.Value, a.Confidence, a.Probability
		}
		points = append(points, pt)
	}
	st, err := calib.Certify(calib.Input{Model: m.Name(), Adapter: adapter,
		Template: decide.TemplateDigest(d), Family: d.Name, Points: points,
		Epsilon: *eps, Delta: *delta, ValidFor: *validFor, LeftOut: left,
		Author: proof.Author{By: caller.Name}, Program: version, Now: now})
	if err != nil {
		return err
	}
	env, err := proof.Seal(st, k)
	if err != nil {
		return err
	}
	doc, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	doc = append(doc, '\n')
	if *pubAt != "" {
		if err := pack.WritePublicKey(*pubAt, k.PublicKey()); err != nil {
			return err
		}
	}
	if pubDoc, err := json.Marshal(k.PublicKey()); err == nil {
		// Kept in the store as well, so the proving ground shows it.
		keepMade(root, env, pubDoc, caller.Name)
	}
	ev := st.Predicate.Calibration
	if err := recordE(root, audit.Record{Action: "analyst.calibrated", Resource: "/agents",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind, Model: caller.Model,
		Verified: caller.Verified, Detail: map[string]string{
			"model": m.Name(), "verdict": string(st.Predicate.Verdict),
			"threshold": fmt.Sprintf("%.2f", ev.Threshold), "channel": ev.Channel,
			"cases": fmt.Sprint(ev.Cases), "closures": fmt.Sprint(ev.Closures),
			"false_closures": fmt.Sprint(ev.FalseClosures),
			"left_out":       fmt.Sprint(left)}}); err != nil {
		return err
	}
	if *outAt == "" {
		if _, err := os.Stdout.Write(doc); err != nil {
			return err
		}
	} else {
		if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
			return err
		}
		if !w.JSON(summary(st)) {
			w.Human("%s\n", describe(st))
		}
	}
	return notProven(st)
}
