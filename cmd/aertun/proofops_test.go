// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/ops"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/proving"
)

// The proving ground's operations, through the command line and the agent
// interface: the same declarations the console runs (internal/admin's
// proving_test.go covers that face).

// A proof made here by verdict prove is kept in the store as it is made;
// the command line lists and shows it; a proof made elsewhere is kept with
// proof keep only against the key that signed it.
func TestTheCommandLineKeepsListsAndShowsProofs(t *testing.T) {
	root, export := verdictSite(t)
	if err := cmdVerdict(root, []string{"import", "--source", "charlotte", export}); err != nil {
		t.Fatal(err)
	}
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "proof.json")
	since := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	_ = cmdVerdict(root, []string{"prove", "--source", "charlotte", "--since", since,
		"--tolerance", "0.5", "--key", key, "--public-key", pub, "--out", at})
	kept, err := proofstore.List(root)
	if err != nil || len(kept) != 1 || kept[0].Origin != proofstore.OriginHere || kept[0].Broken != "" {
		t.Fatalf("after verdict prove, kept %+v, %v", kept, err)
	}
	if err := cmdProof(root, []string{"list"}); err != nil {
		t.Errorf("proof list: %v", err)
	}
	if err := cmdProof(root, []string{"show", kept[0].ID}); err != nil {
		t.Errorf("proof show: %v", err)
	}
	// The same proof handed in again is already kept.
	if err := cmdProof(root, []string{"keep", at, "--public-key", pub}); err != nil {
		t.Errorf("keeping it again: %v", err)
	}
	// Against a key that did not sign it, it is refused.
	if err := cmdProof(root, []string{"keep", at, "--public-key", otherPubFile(t)}); err == nil {
		t.Error("a proof was kept against a key that did not sign it")
	}
	if err := cmdProof(root, []string{"show", "not-an-id"}); err == nil || !ops.IsRefusal(err) {
		t.Errorf("an id that is not one: %v", err)
	}
}

// otherPubFile is a public key file for a key that signed nothing here.
func otherPubFile(t *testing.T) string {
	t.Helper()
	key, pub := signingFiles(t)
	k, err := loadSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(k.PublicKey())
	if err := os.WriteFile(pub, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return pub
}

// An agent on the command line may read the proofs and may not keep one,
// whatever its grants: the core's rule, on this face.
func TestAnAgentOnTheCommandLineCannotKeepAProof(t *testing.T) {
	root, _ := verdictSite(t)
	agent := cliCaller{root, &Caller{Name: "triage-bot", Kind: audit.KindAI, Model: "local/qwen"}}
	reg := proving.Ops(root)
	_, err := reg.Invoke("keep_proof", agent, map[string]string{"envelope": "{}", "public_key": "{}"}, time.Now())
	if !ops.IsRefusal(err) || !strings.Contains(err.Error(), "never make one") {
		t.Errorf("an agent keeping a proof: %v", err)
	}
	if !agent.Agent() || (cliCaller{root, human("dana")}).Agent() {
		t.Error("the command line's caller misreads who is an agent")
	}
}

// The agent interface offers the proving ground's reads, answers them with
// every value labelled, and does not offer keeping a proof at all.
func TestTheAgentInterfaceReadsProofsLabelledAndCannotKeepOne(t *testing.T) {
	root, export := verdictSite(t)
	if err := cmdVerdict(root, []string{"import", "--source", "charlotte", export}); err != nil {
		t.Fatal(err)
	}
	key, pub := signingFiles(t)
	_ = cmdVerdict(root, []string{"prove", "--source", "charlotte", "--since",
		time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339), "--tolerance", "0.001",
		"--key", key, "--public-key", pub, "--out", filepath.Join(t.TempDir(), "p.json")})
	srv := buildMCP(root, &Caller{Name: "dana", Kind: audit.KindHuman, Verified: true})
	text, rerr := callTool(t, srv, "aertun_read", "list_proofs", nil)
	if rerr != nil {
		t.Fatalf("list_proofs: %s", rerr.Message)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatalf("not JSON: %s", text)
	}
	var values []labelledValue
	walkLabelled(t, "list_proofs", doc, &values)
	if len(values) < 5 {
		t.Fatalf("%d labelled values in %s", len(values), text)
	}
	if !strings.Contains(text, `"verdict":{"value":"refuted","attacker_writable":false}`) {
		t.Errorf("the refuted proof is not listed as one: %s", text)
	}
	if strings.Contains(text, verdictMarker) {
		t.Errorf("text planted in the store reached an answer: %s", text)
	}
	id := doc["proofs"].([]any)[0].(map[string]any)["id"].(map[string]any)["value"].(string)
	one, rerr := callTool(t, srv, "aertun_read", "read_proof", map[string]any{"id": id})
	if rerr != nil || !strings.Contains(one, "false closure: ldt:0") {
		t.Errorf("read_proof: %v %s", rerr, one)
	}
	if _, rerr := callTool(t, srv, "aertun_write", "keep_proof",
		map[string]any{"envelope": "{}", "public_key": "{}"}); rerr == nil {
		t.Error("the agent interface offered keep_proof")
	}
	// verify_proof checks a proof without keeping it, and says whether this
	// store trusts the key; a key that did not sign it is refused.
	pubBody, _ := os.ReadFile(pub)
	rawEnv, _ := os.ReadFile(keptEnvelopeFile(t, root, id))
	checked, rerr := callTool(t, srv, "aertun_read", "verify_proof",
		map[string]any{"envelope": string(rawEnv), "public_key": string(pubBody)})
	if rerr != nil || !strings.Contains(checked, `"trusted":{"value":false`) ||
		!strings.Contains(checked, `"verdict":{"value":"refuted"`) {
		t.Errorf("verify_proof: %v %s", rerr, checked)
	}
	otherBody, _ := os.ReadFile(otherPubFile(t))
	if _, rerr := callTool(t, srv, "aertun_read", "verify_proof",
		map[string]any{"envelope": string(rawEnv), "public_key": string(otherBody)}); rerr == nil {
		t.Error("verify_proof accepted a key that did not sign the proof")
	}
	// Once anything is granted, a read is authorised as every other read
	// is, and somebody with no grant is refused.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "dana", Role: auth.RoleViewer, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	if _, rerr := callTool(t, srv, "aertun_read", "list_proofs", nil); rerr != nil {
		t.Errorf("a viewer was refused: %s", rerr.Message)
	}
	stranger := buildMCP(root, &Caller{Name: "nobody", Kind: audit.KindHuman, Verified: true})
	if _, rerr := callTool(t, stranger, "aertun_read", "list_proofs", nil); rerr == nil {
		t.Error("a caller with no grant read the proofs")
	}
}

// The twin answers the proving ground's reads from the proofs it recorded,
// by the same operations: the same answer twice, and not a proof kept after
// the recording.
func TestTheTwinAnswersProofsFromItsRecording(t *testing.T) {
	root, export := verdictSite(t)
	if err := cmdVerdict(root, []string{"import", "--source", "charlotte", export}); err != nil {
		t.Fatal(err)
	}
	key, pub := signingFiles(t)
	since := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	prove := func(tolerance string) {
		_ = cmdVerdict(root, []string{"prove", "--source", "charlotte", "--since", since,
			"--tolerance", tolerance, "--key", key, "--public-key", pub,
			"--out", filepath.Join(t.TempDir(), "p.json")})
	}
	prove("0.001")
	path := recordCase(t, root)
	prove("0.5") // kept after the recording
	srv, err := openTwin(path)
	if err != nil {
		t.Fatal(err)
	}
	first, rerr := callTool(t, srv, "aertun_read", "list_proofs", nil)
	if rerr != nil {
		t.Fatalf("list_proofs: %s", rerr.Message)
	}
	second, _ := callTool(t, srv, "aertun_read", "list_proofs", nil)
	if first != second {
		t.Errorf("two replays differ:\n%s\n%s", first, second)
	}
	if !strings.Contains(first, `"value":"refuted"`) || strings.Contains(first, `"value":"proven"`) {
		t.Errorf("the replay is not the recording: %s", first)
	}
	if live, _ := proofstore.List(root); len(live) != 2 {
		t.Fatalf("the store holds %d proofs, want 2", len(live))
	}
}

// keptEnvelopeFile writes a kept proof's envelope to a file, as it would
// be handed to somebody.
func keptEnvelopeFile(t *testing.T, root, id string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(proofstore.Dir(root), id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var k proofstore.Kept
	if err := json.Unmarshal(body, &k); err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(k.Envelope)
	at := filepath.Join(t.TempDir(), "envelope.json")
	if err := os.WriteFile(at, env, 0o600); err != nil {
		t.Fatal(err)
	}
	return at
}
