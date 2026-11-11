// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// Proofs: a claim about security work, checked by a program, signed.
//
// `proof detection` checks a detection rule — usually one a model drafted —
// against its own fixtures and a labelled corpus its author did not write,
// and writes a DSSE envelope holding the verdict, whatever it is: a
// refutation is signed like a proof, because what did not work is what the
// next attempt most needs to know. `proof verify` checks a proof offline
// against a public key the verifier was handed, and is the CI gate.
//
// Like the wind tunnel, neither subcommand opens the store: the inputs are
// files the caller named, the key is a file the caller named, and the
// output is a file anybody can check without this deployment.
//
// `proof list`, `proof show` and `proof keep` are the proving ground's
// operations (proofops.go), the same ones the console and the agent
// interface run: they read and add to the proofs kept in the store.
func cmdProof(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("proof needs detection, verify, list, show or keep")
	}
	switch args[0] {
	case "detection":
		return proofDetection(args[1:])
	case "verify":
		return proofVerify(args[1:])
	case "list":
		return runOpCommand(root, provingRegistry(root), "list_proofs", args[1:], humanProofs)
	case "show":
		return runOpCommand(root, provingRegistry(root), "read_proof", args[1:], humanProof)
	case "keep":
		return runOpCommand(root, provingRegistry(root), "keep_proof", args[1:], func(a *answer) string {
			if a.Get("already_kept").Value() == true {
				return "already kept, as " + a.Get("id").Text()
			}
			return "kept, as " + a.Get("id").Text() + ": " + strings.ToUpper(a.Get("verdict").Text()) +
				" " + a.Get("kind").Text() + " proof"
		})
	default:
		return fmt.Errorf("unknown proof command %q; try detection, verify, list, show or keep", args[0])
	}
}

// MaxProofCorpus bounds a corpus read for a proof. The corpus is digested
// whole, so it is read whole, and a limit is what keeps that a decision.
const MaxProofCorpus = 256 << 20

func proofDetection(args []string) error {
	fs := flag.NewFlagSet("proof detection", flag.ContinueOnError)
	ruleAt := fs.String("rule", "", "the rule file under test")
	corpusAt := fs.String("corpus", "", "a labelled corpus (JSON lines) the rule's author did not write")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	by := fs.String("by", "", "who submitted the rule: a person or an agent")
	model := fs.String("model", "", "the model that wrote the rule, if one did")
	prompt := fs.String("prompt-sha256", "", "sha256 of the prompt that produced it (never the prompt)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ruleAt == "" || *keyAt == "" {
		return fmt.Errorf("proof detection needs --rule FILE and --key FILE: " +
			"an unsigned verdict is a claim about a claim")
	}
	if *pubAt != "" && *keyAt == "" {
		return fmt.Errorf("--public-key needs --key")
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	rule, err := proof.ReadBounded(*ruleAt, proof.MaxRuleFile)
	if err != nil {
		return err
	}
	in := proof.DetectionInput{RuleName: filepath.Base(*ruleAt), Rule: rule,
		Author:  proof.Author{By: *by, Model: *model, PromptSHA256: strings.ToLower(*prompt)},
		Program: version, Now: time.Now()}
	if *corpusAt != "" {
		corpus, err := proof.ReadBounded(*corpusAt, MaxProofCorpus)
		if err != nil {
			return err
		}
		entries, err := detect.ParseCorpus(bytes.NewReader(corpus))
		if err != nil {
			return fmt.Errorf("%s %w", *corpusAt, err)
		}
		in.CorpusName, in.Corpus, in.Entries = filepath.Base(*corpusAt), corpus, entries
	}
	st, err := proof.ProveDetection(in)
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
	if *outAt == "" {
		if _, err := os.Stdout.Write(doc); err != nil {
			return err
		}
	} else {
		// 0o600 like every operator-named document: a proof names corpus
		// entries, and entries are named after what happened to somebody.
		if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
			return err
		}
		if !w.JSON(summary(st)) {
			w.Human("%s\n", describe(st))
		}
	}
	return notProven(st)
}

func proofVerify(args []string) error {
	fs := flag.NewFlagSet("proof verify", flag.ContinueOnError)
	pubAt := fs.String("key", "", "the public key file the signer published")
	var subjects multiFlag
	fs.Var(&subjects, "subject", "an artefact the proof must be about (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("verify takes one FILE, the proof")
	}
	if *pubAt == "" {
		return fmt.Errorf("verify needs --key FILE: a signature is checked " +
			"against a key the verifier was handed, never one the document supplies")
	}
	pub, err := pack.LoadPublicKey(*pubAt)
	if err != nil {
		return err
	}
	env, err := proof.ReadEnvelope(fs.Arg(0))
	if err != nil {
		return err
	}
	st, err := proof.Open(env, pub)
	if err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	for _, path := range subjects {
		body, err := proof.ReadBounded(path, proof.MaxRuleFile)
		if err != nil {
			return err
		}
		want := proof.SHA256(body)["sha256"]
		found := false
		for _, s := range st.Subject {
			found = found || s.Digest["sha256"] == want
		}
		if !found {
			return fmt.Errorf("%s is not what this proof is about: its sha256 "+
				"%s… matches no subject", path, want[:12])
		}
	}
	if !w.JSON(summary(st)) {
		w.Human("both signatures hold, by key %s.\n%s\n", mustKeyID(pub), describe(st))
	}
	return notProven(st)
}

// notProven is the exit status: a gate passes on proven and on nothing
// else, and says which verdict it refused.
func notProven(st *proof.Statement) error {
	if st.Predicate.Verdict == proof.Proven {
		return nil
	}
	return fmt.Errorf("the verdict is %s, and only proven passes", st.Predicate.Verdict)
}

func summary(st *proof.Statement) map[string]any {
	out := map[string]any{"verdict": st.Predicate.Verdict, "subject": st.Subject,
		"claim": st.Predicate.Claim, "checks": st.Predicate.Checks,
		"verified_at": st.Predicate.VerifiedAt}
	switch {
	case st.Predicate.Detection != nil:
		out["detection"] = st.Predicate.Detection
	case st.Predicate.Calibration != nil:
		out["calibration"] = st.Predicate.Calibration
	case st.Predicate.Verdicts != nil:
		out["verdicts"] = st.Predicate.Verdicts
	case st.Predicate.Reconciliation != nil:
		out["reconciliation"] = st.Predicate.Reconciliation
	case st.Predicate.Adjudication != nil:
		out["adjudication"] = st.Predicate.Adjudication
	case st.Predicate.ClaimTest != nil:
		out["claim"] = st.Predicate.ClaimTest
	case st.Predicate.NotAffected != nil:
		out["not_affected"] = st.Predicate.NotAffected
	}
	return out
}

func describe(st *proof.Statement) string {
	var b strings.Builder
	p := st.Predicate
	fmt.Fprintf(&b, "%s: %s\n  %s\n", strings.ToUpper(string(p.Verdict)), st.Subject[0].Name, p.Claim)
	for _, c := range p.Checks {
		mark := "pass"
		if !c.Passed {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "  %s  %-8s %s\n", mark, c.Name, c.Detail)
		for _, f := range c.Failures {
			fmt.Fprintf(&b, "        - %s\n", f)
		}
	}
	if d := p.Detection; d != nil && d.Positives+d.Negatives > 0 {
		fmt.Fprintf(&b, "  evidence: recall ≥ %.2f over %d, specificity ≥ %.2f over %d (95%% Wilson lower bounds)",
			d.RecallLow, d.Positives, d.SpecificityLow, d.Negatives)
	} else if d != nil {
		b.WriteString("  evidence: none beyond the author's own fixtures")
	}
	if c := p.Calibration; c != nil {
		fmt.Fprintf(&b, "  evidence: at threshold %.2f on the %s channel, %d of %d closing "+
			"suggestion(s) were on findings ruled real, bounded at %.4f against %g "+
			"(Clopper-Pearson at confidence 1-%g/%d); %d verdict(s), %d real\n",
			c.Threshold, c.Channel, c.FalseClosures, c.Closures, c.Upper, c.Epsilon,
			c.Delta, c.Candidates, c.Cases, c.Real)
		fmt.Fprintf(&b, "  binds model %s, template %s…, family %s; expires %s",
			c.Model, c.Template[:12], c.Family, c.Expires)
	}
	if v := p.NotAffected; v != nil {
		fmt.Fprintf(&b, "  evidence: %d not_affected statement(s) of %d about %s: %d supported, %d contradicted, %d uncheckable",
			v.NotAffected, v.Statements, v.Asset, v.Supported, v.Contradicted, v.Uncheckable)
	}
	if v := p.ClaimTest; v != nil {
		fmt.Fprintf(&b, "  evidence: card %s, %s %s %g: %d of %d, between %.4f and %.4f at %g; window closed: %v",
			v.Name, v.Metric, v.Direction, v.Threshold, v.K, v.N, v.Low, v.High, v.Confidence, v.Closed)
	}
	if v := p.Adjudication; v != nil {
		fmt.Fprintf(&b, "  evidence: blind sample %s, committed at audit entry %d: the AI's closures %d of %d "+
			"judged real (%.4f to %.4f) against %g; people's %d of %d; %d reviewer(s)",
			v.Sample, v.Committed.Seq, v.AI.K, v.AI.N, v.AI.Lower, v.AI.Upper, v.Tolerance,
			v.Human.K, v.Human.N, v.Reviewers)
	}
	if v := p.Reconciliation; v != nil {
		fmt.Fprintf(&b, "  evidence: %d call(s) answered, %d in its account, %d unreported, %d claimed "+
			"and never received; %d connection(s) checked, %d unexplained; it reported %d tool call(s)",
			v.Calls, v.Matched, v.Unreported, v.Unreceived, v.Connects, v.Unexplained, v.Reported)
	}
	if v := p.Verdicts; v != nil {
		fmt.Fprintf(&b, "  evidence: %d of %d closure(s) false, between %.4f and %.4f, against %g; "+
			"agreement %d of %d; abstained on %d of %d alert(s); labels %s",
			v.FalseClosures.K, v.FalseClosures.N, v.FalseClosures.Lower, v.FalseClosures.Upper,
			v.Tolerance, v.Agreement.K, v.Agreement.N, v.Abstentions.K, v.Abstentions.N, v.Labels)
	}
	return strings.TrimRight(b.String(), "\n")
}

// loadSigningKey reads a dual key file, refusing one that anybody but its
// owner can read: whoever can read it can sign proofs in this key's name,
// so a readable key is a forgery waiting to be noticed.
func loadSigningKey(path string) (*pack.Key, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %04o); a signing "+
			"key must be 0600: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	return pack.LoadKey(path)
}

func mustKeyID(pub pack.KeyPublic) string {
	id, err := proof.KeyID(pub)
	if err != nil {
		return "unknown"
	}
	return id
}
