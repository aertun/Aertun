// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/proofstore"
)

// Trusting a key waits for a second administrator; once approved, the
// proofs it signs are shown as a trusted signer's on the command line;
// untrusting takes the label away at once. An agent cannot trust a key.
func TestTrustingAProofSignerTakesTwoAdministrators(t *testing.T) {
	root, export := verdictSite(t)
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"lee", "admin"})
	asOnly(t, root, "dana")
	if err := cmdVerdict(root, []string{"import", "--source", "charlotte", export}); err != nil {
		t.Fatal(err)
	}
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "proof.json")
	since := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	_ = cmdVerdict(root, []string{"prove", "--source", "charlotte", "--since", since,
		"--tolerance", "0.5", "--key", key, "--public-key", pub, "--out", at})
	kept, _ := proofstore.List(root)
	if len(kept) != 1 || kept[0].Signer != "" {
		t.Fatalf("before any signer is trusted: %+v", kept)
	}

	if err := cmdProof(root, []string{"trust", "verifier", "--key", pub, "--why", "our verifiers sign with it"}); err != nil {
		t.Fatal(err)
	}
	if s, _ := proofstore.Signers(root); len(s) != 0 {
		t.Fatal("a key was trusted on one administrator's word")
	}
	r := waiting(t, root)
	asOnly(t, root, "lee")
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Fatal(err)
	}
	if kept, _ = proofstore.List(root); kept[0].Signer != "verifier" {
		t.Fatalf("after approval the proof is labelled %q", kept[0].Signer)
	}
	buf := windtunnelOutput(t)
	if err := cmdProof(root, []string{"show", kept[0].ID}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "signed by verifier, a trusted signer") {
		t.Errorf("proof show does not name the trusted signer:\n%s", buf)
	}

	if err := cmdProof(root, []string{"untrust", "verifier", "--why", "key rotated"}); err != nil {
		t.Fatal(err)
	}
	if kept, _ = proofstore.List(root); kept[0].Signer != "" {
		t.Fatal("an untrusted signer still labels its proofs")
	}

	register(t, root, "helper", "aertun_read")
	_, agentSecret := agentToken(t, root, "helper", "dana", auth.RoleAdmin)
	t.Setenv("AERTUN_TOKEN", agentSecret)
	if err := cmdProof(root, []string{"trust", "agent-key", "--key", pub, "--why", "x"}); err == nil {
		t.Error("an agent asked to trust a key")
	}
	if _, err := os.Stat(at); err != nil {
		t.Fatal(err)
	}
}
