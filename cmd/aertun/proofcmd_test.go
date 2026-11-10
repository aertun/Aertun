// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

const proofCorpus = `{"name":"reset by helpdesk impostor","expect":["okta.mfa-reset"],"event":{"source":"okta/system","time":"2026-10-01T09:00:00Z","received":"2026-10-01T09:00:03Z","class":6003,"disposition":1,"actor":{"issuer":"okta","value":"00u9"},"message":"user.mfa.factor.reset_all","raw":{"eventType":"user.mfa.factor.reset_all"}}}
{"name":"self-service enrolment","event":{"source":"okta/system","time":"2026-10-01T09:05:00Z","received":"2026-10-01T09:05:03Z","class":6003,"disposition":1,"actor":{"issuer":"okta","value":"00u9"},"message":"user.mfa.factor.activate","raw":{"eventType":"user.mfa.factor.activate"}}}
`

// proofFiles lays out a signing key, the pack's okta rule and a corpus.
func proofFiles(t *testing.T) (dir, key, rule, corpus string) {
	t.Helper()
	dir = t.TempDir()
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key = filepath.Join(dir, "signing.key")
	if err := pack.SaveKey(key, k, 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("../../internal/detect/pack/okta.mfa-reset.json")
	if err != nil {
		t.Fatal(err)
	}
	rule = filepath.Join(dir, "okta.mfa-reset.json")
	corpus = filepath.Join(dir, "corpus.jsonl")
	for path, b := range map[string]string{rule: string(body), corpus: proofCorpus} {
		if err := os.WriteFile(path, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, key, rule, corpus
}

func TestProofDetectionSignsAndVerifyGates(t *testing.T) {
	buf := windtunnelOutput(t)
	dir, key, rule, corpus := proofFiles(t)
	out, pub := filepath.Join(dir, "rule.proof.json"), filepath.Join(dir, "pub.json")
	if err := cmdProof("", []string{"detection", "--rule", rule, "--corpus", corpus,
		"--key", key, "--public-key", pub, "--out", out, "--by", "agent:drafter"}); err != nil {
		t.Fatalf("a rule that holds: %v\n%s", err, buf)
	}
	if !strings.Contains(buf.String(), "PROVEN: okta.mfa-reset.json") {
		t.Errorf("the summary does not lead with the verdict:\n%s", buf)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the proof was not written 0600: %v %v", info, err)
	}
	buf.Reset()
	if err := cmdProof("", []string{"verify", "--key", pub, "--subject", rule, out}); err != nil {
		t.Fatalf("verify: %v\n%s", err, buf)
	}
	if !strings.Contains(buf.String(), "both signatures hold") {
		t.Errorf("verify did not say what it checked:\n%s", buf)
	}
	// A proof is about the bytes that were reviewed, and no others.
	other := filepath.Join(dir, "other.json")
	_ = os.WriteFile(other, []byte(`{"id":"something.else"}`), 0o600)
	if err := cmdProof("", []string{"verify", "--key", pub, "--subject", other, out}); err == nil ||
		!strings.Contains(err.Error(), "is not what this proof is about") {
		t.Errorf("a proof verified against a file it is not about: %v", err)
	}
	// An edited verdict does not verify.
	env, err := proof.ReadEnvelope(out)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	env.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(
		string(payload), `"caught":1`, `"caught":9`, 1)))
	tampered := filepath.Join(dir, "tampered.json")
	if err := writeJSON(tampered, env); err != nil {
		t.Fatal(err)
	}
	if err := cmdProof("", []string{"verify", "--key", pub, tampered}); err == nil {
		t.Error("an edited proof verified")
	}
}

// Without a corpus a proof is still written and signed, and the gate
// refuses it: the author's own fixtures cannot settle the claim.
func TestProofWithoutACorpusIsSignedAndRefusedByTheGate(t *testing.T) {
	windtunnelOutput(t)
	dir, key, rule, _ := proofFiles(t)
	out := filepath.Join(dir, "p.json")
	err := cmdProof("", []string{"detection", "--rule", rule, "--key", key, "--out", out})
	if err == nil || !strings.Contains(err.Error(), "inconclusive") {
		t.Errorf("an uncorroborated rule passed the gate: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("the inconclusive proof was not written: %v", statErr)
	}
}

func TestProofRefusesAKeyOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not express this on Windows")
	}
	windtunnelOutput(t)
	_, key, rule, _ := proofFiles(t)
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := cmdProof("", []string{"detection", "--rule", rule, "--key", key}); err == nil ||
		!strings.Contains(err.Error(), "readable by others") {
		t.Errorf("a group-readable signing key was used: %v", err)
	}
}

func TestProofVerifyNeedsAKeyItWasHanded(t *testing.T) {
	windtunnelOutput(t)
	if err := cmdProof("", []string{"verify", "some.proof.json"}); err == nil ||
		!strings.Contains(err.Error(), "never one the document supplies") {
		t.Errorf("verify without a key: %v", err)
	}
	if err := cmdProof("", nil); err == nil {
		t.Error("a bare proof command did something")
	}
}
