// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proofstore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/pack"
)

// A kept proof is labelled with the trusted signer whose key signed it, on
// every read, and loses the label the moment that signer is removed; a key
// nobody trusted is never labelled.
func TestAProofIsLabelledByItsTrustedSignerOnlyWhileTrusted(t *testing.T) {
	root := t.TempDir()
	k, _ := pack.GenerateKey()
	env, pub := sealed(t, k, 0)
	id, _, err := Keep(root, env, pub, "dana", OriginHandedIn, t0)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := Get(root, id); e.Signer != "" {
		t.Fatalf("a key nobody trusted is labelled %q", e.Signer)
	}
	if _, err := Trust(root, "verifier", pub, "lee", "the store's own verifiers sign with it", t0); err != nil {
		t.Fatal(err)
	}
	if e, _ := Get(root, id); e.Signer != "verifier" {
		t.Fatalf("a trusted signer's proof is labelled %q", e.Signer)
	}
	if l, _ := List(root); len(l) != 1 || l[0].Signer != "verifier" {
		t.Fatalf("the list labels it %+v", l)
	}
	if gone, err := Untrust(root, "verifier"); !gone || err != nil {
		t.Fatalf("untrust: %v %v", gone, err)
	}
	if e, _ := Get(root, id); e.Signer != "" {
		t.Fatalf("a removed signer still labels its proofs %q", e.Signer)
	}
}

// One name, one key: a name or a key already trusted is refused, as are a
// bad name, a missing reason and a document that is not a public key.
func TestTrustingRefusesWhatCannotBeOneSigner(t *testing.T) {
	root := t.TempDir()
	k, _ := pack.GenerateKey()
	pub, _ := json.Marshal(k.PublicKey())
	other, _ := pack.GenerateKey()
	otherPub, _ := json.Marshal(other.PublicKey())
	if _, err := Trust(root, "partner", pub, "lee", "partner's verifier", t0); err != nil {
		t.Fatal(err)
	}
	cases := map[string]error{}
	_, cases["same name"] = Trust(root, "partner", otherPub, "lee", "x", t0)
	_, cases["same key"] = Trust(root, "partner-2", pub, "lee", "x", t0)
	_, cases["bad name"] = Trust(root, "Partner Two", otherPub, "lee", "x", t0)
	_, cases["no reason"] = Trust(root, "partner-3", otherPub, "lee", "  ", t0)
	_, cases["not a key"] = Trust(root, "partner-4", []byte(`{"ed25519":"x"}`), "lee", "x", t0)
	_, cases["long reason"] = Trust(root, "partner-5", otherPub, "lee", strings.Repeat("x", 501), t0)
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s was trusted", name)
		}
	}
	if s, _ := Signers(root); len(s) != 1 {
		t.Errorf("signers: %+v", s)
	}
}

// Check verifies without keeping, and refuses a proof its key did not sign.
func TestCheckVerifiesWithoutKeeping(t *testing.T) {
	root := t.TempDir()
	k, _ := pack.GenerateKey()
	env, pub := sealed(t, k, 0)
	if _, kid, err := Check(env, pub); err != nil || kid == "" {
		t.Fatalf("check: %v", err)
	}
	other, _ := pack.GenerateKey()
	otherPub, _ := json.Marshal(other.PublicKey())
	if _, _, err := Check(env, otherPub); err == nil {
		t.Error("a proof checked out against a key that did not sign it")
	}
	if l, _ := List(root); len(l) != 0 {
		t.Error("checking kept something")
	}
}
