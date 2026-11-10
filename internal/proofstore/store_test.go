// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proofstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// sealed is a signed verdicts proof and the public key that checks it.
func sealed(t *testing.T, k *pack.Key, falseClosures int) (env, pub []byte) {
	t.Helper()
	n := 300
	st, err := proof.ProveVerdicts(proof.VerdictsInput{Source: "charlotte", Labels: proof.LabelsPeople,
		Since: t0, Until: t0.Add(7 * 24 * time.Hour), Tolerance: 0.01,
		Lines:      []byte(`{"source":"charlotte"}` + "\n"),
		Considered: n, Counted: n, Alerts: n,
		FalseClosures:  proof.Count{K: falseClosures, N: n},
		ReviewCoverage: proof.Count{K: n, N: n}, DeliveredFirst: proof.Count{K: n, N: n},
		Agreement: proof.Count{K: n - falseClosures, N: n}, Abstentions: proof.Count{K: 0, N: n},
		FalseClosed: closed(falseClosures), Program: "test", Now: t0.Add(8 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	e, err := proof.Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	env, _ = json.Marshal(e)
	pub, _ = json.Marshal(k.PublicKey())
	return env, pub
}

func closed(k int) []string {
	var out []string
	for i := range k {
		out = append(out, "ldt:"+string(rune('a'+i)))
	}
	return out
}

// A proof that verifies is kept with its key, read back verified, and kept
// once however many times it is handed in.
func TestAProofThatVerifiesIsKeptOnce(t *testing.T) {
	root := t.TempDir()
	k, _ := pack.GenerateKey()
	env, pub := sealed(t, k, 0)
	id, st, err := Keep(root, env, pub, "dana", OriginHandedIn, t0)
	if err != nil || st.Predicate.Verdict != proof.Proven {
		t.Fatalf("keep: %v", err)
	}
	if _, _, err := Keep(root, env, pub, "lee", OriginHandedIn, t0); !errors.Is(err, ErrAlreadyKept) {
		t.Errorf("a second keep: %v", err)
	}
	all, err := List(root)
	if err != nil || len(all) != 1 || all[0].ID != id || all[0].Broken != "" ||
		all[0].KeptBy != "dana" || all[0].Statement == nil {
		t.Fatalf("listed %+v, %v", all, err)
	}
	info, _ := os.Stat(filepath.Join(Dir(root), id+".json"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("kept at %v", info.Mode().Perm())
	}
}

// What does not verify against the key handed in with it is not kept.
func TestAProofThatDoesNotVerifyIsNotKept(t *testing.T) {
	root := t.TempDir()
	k, _ := pack.GenerateKey()
	other, _ := pack.GenerateKey()
	env, _ := sealed(t, k, 0)
	otherPub, _ := json.Marshal(other.PublicKey())
	if _, _, err := Keep(root, env, otherPub, "dana", OriginHandedIn, t0); err == nil {
		t.Error("a proof was kept against a key that did not sign it")
	}
	if _, _, err := Keep(root, []byte(`{"payload":"x"}`), otherPub, "dana", OriginHandedIn, t0); err == nil {
		t.Error("something that is not a proof was kept")
	}
	if all, _ := List(root); len(all) != 0 {
		t.Errorf("kept %d", len(all))
	}
}

// A kept file edited afterwards is listed as broken, never as what it now
// says, and never left out.
func TestAKeptProofEditedAfterwardsShowsAsBroken(t *testing.T) {
	k, _ := pack.GenerateKey()
	attacker, _ := pack.GenerateKey()
	cases := map[string]func(t *testing.T, path string){
		"the statement": func(t *testing.T, path string) {
			// A refutation signed by somebody else, put in place of the proof.
			env, pub := sealed(t, attacker, 20)
			var kept Kept
			body, _ := os.ReadFile(path)
			_ = json.Unmarshal(body, &kept)
			_ = json.Unmarshal(env, &kept.Envelope)
			_ = json.Unmarshal(pub, &kept.Key)
			b, _ := json.Marshal(kept)
			_ = os.WriteFile(path, b, 0o600)
		},
		"the key": func(t *testing.T, path string) {
			var kept Kept
			body, _ := os.ReadFile(path)
			_ = json.Unmarshal(body, &kept)
			kept.Key = attacker.PublicKey()
			b, _ := json.Marshal(kept)
			_ = os.WriteFile(path, b, 0o600)
		},
		// The same statement and key, with a signature that is not the
		// key's: only checking the signature again can tell.
		"the signature": func(t *testing.T, path string) {
			var kept Kept
			body, _ := os.ReadFile(path)
			_ = json.Unmarshal(body, &kept)
			other, _ := sealed(t, attacker, 0)
			var forged proof.Envelope
			_ = json.Unmarshal(other, &forged)
			kept.Envelope.Signatures = forged.Signatures
			b, _ := json.Marshal(kept)
			_ = os.WriteFile(path, b, 0o600)
		},
		"the bytes": func(t *testing.T, path string) {
			body, _ := os.ReadFile(path)
			_ = os.WriteFile(path, []byte(strings.Replace(string(body), `"kept_by": "dana"`, `"kept_by": "dana", "extra": 1`, 1)), 0o600)
		},
	}
	for name, edit := range cases {
		root := t.TempDir()
		env, pub := sealed(t, k, 0)
		id, _, err := Keep(root, env, pub, "dana", OriginHandedIn, t0)
		if err != nil {
			t.Fatal(err)
		}
		edit(t, filepath.Join(Dir(root), id+".json"))
		all, _ := List(root)
		if len(all) != 1 || all[0].Broken == "" || all[0].Statement != nil {
			t.Errorf("%s edited: listed %+v", name, all)
		}
		if e, err := Get(root, id); err != nil || e.Broken == "" {
			t.Errorf("%s edited: read %+v, %v", name, e, err)
		}
	}
}

// An id is a shape before it is a file name.
func TestAnIdIsOnlyAnId(t *testing.T) {
	for _, bad := range []string{"../../etc/passwd", "", strings.Repeat("a", 23), strings.Repeat("A", 24)} {
		if _, err := Get(t.TempDir(), bad); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}
