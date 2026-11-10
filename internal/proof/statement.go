// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package proof turns a claim about security work into a signed record of
// whether a program could confirm it.
//
// A model can now write a detection rule, triage an alert or draft a patch
// faster than anybody can check the work, and checking is the part that
// decides whether the work is worth anything. A proof is the check, made by
// a program rather than by the author, and written down so that somebody
// who was not there — a reviewer, an auditor, a customer, a training run —
// can rely on it without trusting whoever handed it over.
//
// # What a proof is
//
// An in-toto Statement (https://in-toto.io/Statement/v1): the subjects are
// the artefacts the claim is about, by digest; the predicate is what was
// checked, against what, by which verifier, and the verdict. It is carried
// in a DSSE envelope signed twice — Ed25519 and ML-DSA-65 — with the
// content plane's key in this package's own context. Both are open
// formats: a proof made here can be read, stored and checked by in-toto and
// Sigstore tooling, and nobody needs this program to keep their evidence.
//
// # The decisions this package is built on
//
// 1. THE AUTHOR NEVER GRADES ITS OWN WORK. A verifier is a program that
// runs the claim against evidence; nothing a model says about its own
// output reaches the verdict. A model's name and a digest of its prompt are
// recorded so the outcome can be attributed — the prompt itself never is.
//
// 2. THREE VERDICTS, NOT TWO. Proven means every check passed on evidence
// that could have failed it. Refuted means a check failed, and names what
// failed. Inconclusive means nothing failed but the evidence was too thin
// to fail anything — a rule tested only on its author's own examples is
// inconclusive, not proven. A refutation is signed like a proof: knowing
// what did not work is as useful to the next attempt as knowing what did.
//
// 3. WHAT RAN IS NAMED BEFORE HOW IT WENT. Every material the verifier read
// is listed by digest, with the verifier's identity and version, so the
// same inputs can be run again and must give the same verdict.
//
// 4. BOTH SIGNATURES, ALWAYS. pack.DualVerify has no single-signature
// mode, and neither does anything here.
//
// 5. BOUNDED AND STRICT. Every input is read under a size limit, a signed
// statement is decoded refusing fields this version does not know — so a
// statement cannot say something its verifier did not read — and the
// failure lists a proof carries are capped so a proof stays a document.
package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	// StatementType is the in-toto Statement version every proof is.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateDetection is the predicate of a proof about a detection
	// rule. Versioned in the URI, so a change to what it says is a new
	// type rather than a reinterpretation of the old one.
	PredicateDetection = "https://aertun.github.io/proof/detection/v1"
)

// Verdict is what the verifier concluded.
type Verdict string

const (
	Proven       Verdict = "proven"
	Refuted      Verdict = "refuted"
	Inconclusive Verdict = "inconclusive"
)

func (v Verdict) known() bool { return v == Proven || v == Refuted || v == Inconclusive }

// Digest maps an algorithm to a lower-case hex digest, as in-toto writes it.
type Digest map[string]string

// SHA256 is the digest of exact bytes.
func SHA256(b []byte) Digest {
	sum := sha256.Sum256(b)
	return Digest{"sha256": hex.EncodeToString(sum[:])}
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (d Digest) valid() bool { return hex64.MatchString(d["sha256"]) }

// Subject is an artefact the claim is about.
type Subject struct {
	Name   string `json:"name"`
	Digest Digest `json:"digest"`
}

// Statement is one proof, before it is signed.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Predicate is what was checked and what came of it.
type Predicate struct {
	Verdict Verdict `json:"verdict"`
	// Claim is the sentence that was checked, in words, so a reader knows
	// what "proven" is a proof of.
	Claim     string     `json:"claim"`
	Author    Author     `json:"author"`
	Verifier  VerifierID `json:"verifier"`
	Materials []Material `json:"materials"`
	Checks    []Check    `json:"checks"`
	// Detection is set on a detection proof, and holds how much evidence
	// the verdict rests on.
	Detection *DetectionEvidence `json:"detection,omitempty"`
	// Calibration is set on a calibration certificate, and holds the
	// binding, the counts and the bound.
	Calibration *CalibrationEvidence `json:"calibration,omitempty"`
	// VerifiedAt is when the verifier ran, in UTC, RFC 3339.
	VerifiedAt string `json:"verified_at"`
}

// Author is who produced the work under test. All optional, all
// attribution: none of it is evidence.
type Author struct {
	// By is the principal that submitted the work — a person or an agent.
	By string `json:"by,omitempty"`
	// Model names the model that wrote it, when a model did.
	Model string `json:"model,omitempty"`
	// PromptSHA256 is the digest of the prompt that produced it. The
	// prompt is never stored here: it may hold what the model was shown,
	// and a proof travels further than that should.
	PromptSHA256 string `json:"prompt_sha256,omitempty"`
}

// VerifierID names the program that checked the claim.
type VerifierID struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	// Program is the build of this binary the verifier ran in.
	Program string `json:"program,omitempty"`
}

// Material is an input the verifier read, other than the subjects.
type Material struct {
	Name    string `json:"name"`
	Digest  Digest `json:"digest"`
	Entries int    `json:"entries,omitempty"`
}

// Check is one test the claim had to pass.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
	// Failures names what failed, capped at MaxFailures with the remainder
	// counted in Detail.
	Failures []string `json:"failures,omitempty"`
}

// MaxFailures caps the names one check lists.
const MaxFailures = 50

// capped returns at most MaxFailures names and how many were left out.
func capped(names []string) ([]string, int) {
	if len(names) <= MaxFailures {
		return names, 0
	}
	return names[:MaxFailures], len(names) - MaxFailures
}

// Validate refuses a statement nobody could rely on. It is run before
// signing and again after opening, so neither side depends on the other
// having run it.
func (s *Statement) Validate() error {
	if s.Type != StatementType {
		return fmt.Errorf("this is a %q statement, and a proof is %s", s.Type, StatementType)
	}
	if len(s.Subject) == 0 {
		return fmt.Errorf("a proof names what it is about, and this names nothing")
	}
	for _, sub := range s.Subject {
		if strings.TrimSpace(sub.Name) == "" || !sub.Digest.valid() {
			return fmt.Errorf("every subject needs a name and a sha256 digest")
		}
	}
	p := s.Predicate
	if !p.Verdict.known() {
		return fmt.Errorf("%q is not a verdict; it is proven, refuted or inconclusive", p.Verdict)
	}
	if strings.TrimSpace(p.Claim) == "" {
		return fmt.Errorf("a proof says what it proves, and this says nothing")
	}
	if p.Verifier.ID == "" || p.Verifier.Version == "" {
		return fmt.Errorf("a proof names the verifier and version that made it")
	}
	if len(p.Checks) == 0 {
		return fmt.Errorf("a verdict with no checks behind it is an opinion")
	}
	for _, m := range p.Materials {
		if strings.TrimSpace(m.Name) == "" || !m.Digest.valid() {
			return fmt.Errorf("every material needs a name and a sha256 digest")
		}
	}
	failed := false
	for _, c := range p.Checks {
		if c.Name == "" {
			return fmt.Errorf("every check has a name")
		}
		if len(c.Failures) > MaxFailures {
			return fmt.Errorf("check %s lists more than %d failures", c.Name, MaxFailures)
		}
		failed = failed || !c.Passed
	}
	// The verdict has to agree with the checks it summarises: a refutation
	// with nothing failed, or a proof with something failed, is a document
	// contradicting itself.
	if failed != (p.Verdict == Refuted) {
		return fmt.Errorf("the verdict %s does not agree with the checks", p.Verdict)
	}
	if p.Author.PromptSHA256 != "" && !hex64.MatchString(p.Author.PromptSHA256) {
		return fmt.Errorf("the prompt digest is not a lower-case sha256")
	}
	if _, err := time.Parse(time.RFC3339, p.VerifiedAt); err != nil {
		return fmt.Errorf("verified_at is not RFC 3339: %w", err)
	}
	return s.validateEvidence()
}

// validateEvidence holds each predicate to its own evidence and to no
// other: a predicate this version does not know is refused, and so is a
// statement whose evidence belongs to another predicate, or carries a
// second kind beside its own — a reader of one kind of proof would not
// read the other's numbers, and a signed number nobody reads is one the
// signer could have put there for the wrong reader.
func (s *Statement) validateEvidence() error {
	p := s.Predicate
	kinds := 0
	for _, set := range []bool{p.Detection != nil, p.Calibration != nil} {
		if set {
			kinds++
		}
	}
	switch s.PredicateType {
	case PredicateDetection:
		if p.Detection == nil || kinds != 1 {
			return fmt.Errorf("a detection proof carries detection evidence and no other")
		}
		return nil
	case PredicateCalibration:
		if p.Calibration == nil || kinds != 1 {
			return fmt.Errorf("a calibration certificate carries calibration evidence and no other")
		}
		return p.Calibration.validate(s)
	default:
		return fmt.Errorf("the predicate %q is not one this version can read", s.PredicateType)
	}
}
