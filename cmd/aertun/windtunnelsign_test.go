// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/windtunnel"
)

// Signing is refused unless the environment says it is CI, before the key
// file is even opened, and the refusal says why and what to do instead.
// With the signal present, the CI job's path — sign, publish the public
// half, verify offline with those two files and nothing else — holds, and
// the verifier states the document's schema and standing.
func TestWindtunnelSignsOnlyInCIAndVerifiesOffline(t *testing.T) {
	buf := windtunnelOutput(t)
	root := t.TempDir()
	work := t.TempDir()
	missingKey := filepath.Join(work, "no-such-key.json")
	for _, ci := range []string{"", "false", "1", "TRUE "} {
		t.Setenv("CI", ci)
		err := cmdWindtunnel(root, []string{"run", "--scenario",
			"agent.trifecta-mailroom-exfil", "--key", missingKey})
		if err == nil || !strings.Contains(err.Error(), "signed only in CI") ||
			!strings.Contains(err.Error(), "without --key") {
			t.Fatalf("CI=%q: signing gave %v; outside CI it is refused, "+
				"with the reason and the unsigned alternative", ci, err)
		}
	}

	keyPath := filepath.Join(work, "ci-key.json")
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pack.SaveKey(keyPath, k, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CI", "true")
	doc := filepath.Join(work, "scorecard.json")
	pub := filepath.Join(work, "public-key.json")
	if err := cmdWindtunnel(root, []string{"run", "--score", "reference",
		"--seed", "7", "--key", keyPath, "--public-key", pub, "--out",
		doc}); err != nil {
		t.Fatalf("the CI job's run failed: %v", err)
	}
	// The run's own screen labels the self-graded result.
	screen := strings.Join(strings.Fields(buf.String()), " ")
	for _, want := range []string{"the secondary mode, and self-graded",
		"[self-graded: secondary mode]", "dual-signed"} {
		if !strings.Contains(screen, want) {
			t.Errorf("the run's screen never says %q: %s", want, screen)
		}
	}

	// Offline: a fresh process would hold only these two files.
	buf.Reset()
	if err := cmdWindtunnel(root, []string{"verify", "--key", pub, doc}); err != nil {
		t.Fatalf("offline verification of the CI-signed card failed: %v", err)
	}
	for _, want := range []string{"both signatures hold",
		windtunnel.DocSchema, "self-graded"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("verify never says %q: %s", want, buf.String())
		}
	}
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	var card windtunnel.Scorecard
	if err := json.Unmarshal(b, &card); err != nil {
		t.Fatal(err)
	}
	if card.Signature == nil || card.Standing != windtunnel.StandingSelfGraded {
		t.Fatalf("the CI card carries signature %v and standing %q",
			card.Signature, card.Standing)
	}
}

// --mutate through the command: their naive rule's misses under mutation
// are on the screen as k of n and sealed on the document, and the request
// is bounded.
func TestWindtunnelMutateFlagReportsTheRateUnderMutation(t *testing.T) {
	buf := windtunnelOutput(t)
	root := t.TempDir()
	doc := filepath.Join(t.TempDir(), "scorecard.json")
	if err := cmdWindtunnel(root, []string{"run", "--sigma",
		theirSigmaDir("their-sigma-naive"), "--scenario",
		"agent.trifecta-mailroom-exfil", "--mutate", "4", "--out",
		doc}); err != nil {
		t.Fatalf("a run under mutation failed: %v", err)
	}
	screen := buf.String()
	for _, want := range []string{"the primary mode",
		"missed 4 of 4 variant(s) of must-alert scenarios",
		"4 of 4 evaded"} {
		if !strings.Contains(strings.Join(strings.Fields(screen), " "), want) {
			t.Errorf("the screen never says %q:\n%s", want, screen)
		}
	}
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	var card windtunnel.Scorecard
	if err := json.Unmarshal(b, &card); err != nil {
		t.Fatal(err)
	}
	if err := card.Verify(); err != nil {
		t.Fatal(err)
	}
	if m := card.Mutation; m == nil || m.MissUnderMutation == nil ||
		m.MissUnderMutation.K != 4 || m.MissUnderMutation.N != 4 {
		t.Fatalf("the sealed mutation section is %+v", card.Mutation)
	}
	err = cmdWindtunnel(root, []string{"run", "--mutate", "65"})
	if err == nil || !strings.Contains(err.Error(), "between 0 and 64") {
		t.Fatalf("--mutate 65 gave %v", err)
	}
}
