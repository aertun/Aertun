// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/jcs"
	"github.com/aertun/aertun/internal/pack"
)

// A version 2 digest is the RFC 8785 form, and a third party can recompute
// it from the file alone, knowing nothing of this program's structs: read
// the document as generic JSON, empty the digest, drop the signature,
// canonicalise, hash.
func TestScorecardDigestIsRecomputableFromTheFileByAnyCanonicaliser(t *testing.T) {
	card, err := Run(RunOptions{Seed: 7, Mutate: 2,
		Now:       time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC),
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}})
	if err != nil {
		t.Fatal(err)
	}
	if card.Schema != DocSchema || DocSchema != "aertun/windtunnel-scorecard/v2" {
		t.Fatalf("a run wrote schema %q", card.Schema)
	}
	doc, err := card.Document()
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(doc, &generic); err != nil {
		t.Fatal(err)
	}
	generic["sha256"] = ""
	delete(generic, "signature")
	raw, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canon)
	if got := hex.EncodeToString(sum[:]); got != card.SHA256 {
		t.Fatalf("the canonical form of the file hashes to %s and the "+
			"document says %s; a verifier outside this program could not "+
			"check it", got, card.SHA256)
	}
	// And the signed message is the context, a NUL, and those bytes.
	msg, err := scorecardMessage(card)
	if err != nil {
		t.Fatal(err)
	}
	if want := append(append([]byte(ScorecardContext), 0), canon...); string(msg) != string(want) {
		t.Fatal("the signed message is not context, NUL, canonical bytes")
	}
}

// RFC 8785 reads every number as a double, so a seed wider than 53 bits
// would be signed as its neighbour, and two documents rendering different
// seeds would share one digest. The round trip refuses to seal one.
func TestScorecardRefusesANumberTheCanonicalFormCannotHold(t *testing.T) {
	card, err := Run(RunOptions{Seed: 7,
		Now:       time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC),
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}})
	if err != nil {
		t.Fatal(err)
	}
	card.Seed = 1<<53 + 1
	if err := card.seal(); err == nil ||
		!strings.Contains(err.Error(), "cannot hold exactly") {
		t.Fatalf("a seed of 2^53+1 sealed (%v); it would be signed as 2^53, "+
			"and a document claiming either seed would verify", err)
	}
	// Through Run as well: the operator's seed is what reaches the seal.
	_, err = Run(RunOptions{Seed: -(1<<53 + 1),
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}})
	if err == nil || !strings.Contains(err.Error(), "cannot hold exactly") {
		t.Fatalf("a run with a seed beyond the double sealed (%v)", err)
	}
	// 2^53 - 1 is the widest an integer can be and stay exact.
	card.Seed = 1<<53 - 1
	if err := card.seal(); err != nil {
		t.Fatalf("a seed of 2^53-1 refused: %v", err)
	}
}

// The standing is sealed and held to the mode: a reference document says
// it is self-graded, a their-Sigma document says it is primary, and a
// reference document relabelled primary — even re-sealed, so its digest is
// consistent — is refused.
func TestScorecardStandingIsSealedAndHeldToTheMode(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	ref, err := Run(RunOptions{Seed: 7, Now: now,
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}})
	if err != nil {
		t.Fatal(err)
	}
	if ref.Standing != StandingSelfGraded {
		t.Fatalf("a reference document calls itself %q", ref.Standing)
	}
	s := ref.Summarize()
	for _, want := range []string{"the secondary mode, and self-graded",
		"regression test of the pack", "--sigma DIR, the primary mode",
		"[self-graded: secondary mode]"} {
		if !strings.Contains(strings.Join(strings.Fields(s), " "), want) {
			t.Errorf("the reference summary never says %q:\n%s", want, s)
		}
	}
	ref.Standing = StandingPrimary
	if err := ref.seal(); err != nil {
		t.Fatal(err)
	}
	if err := ref.Verify(); err == nil ||
		!strings.Contains(err.Error(), "calls itself") {
		t.Fatalf("a self-graded document relabelled primary verified (%v)",
			err)
	}

	theirs := theirRun(t, theirFixtures, "agent.trifecta-mailroom-exfil")
	if theirs.Standing != StandingPrimary {
		t.Fatalf("a their-Sigma document calls itself %q", theirs.Standing)
	}
	ts := theirs.Summarize()
	if !strings.Contains(ts, "the primary mode") ||
		strings.Contains(ts, "self-graded") {
		t.Errorf("the their-Sigma summary mislabels its standing:\n%s", ts)
	}
}

// Version 1 documents still verify, by the form version 1 builds digested
// — the committed seed card, signed by the CI key, is one — and a version
// 1 document cannot carry the fields version 2 added.
func TestScorecardVersionOneStillVerifiesAndCannotGrowFields(t *testing.T) {
	root := filepath.Join("..", "..", "scorecards")
	body, err := os.ReadFile(filepath.Join(root, "scorecard-2026-11-04.json"))
	if err != nil {
		t.Fatal(err)
	}
	var card Scorecard
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&card); err != nil {
		t.Fatal(err)
	}
	if card.Schema != DocSchemaV1 {
		t.Fatalf("the seed card is %q; this test is about version 1",
			card.Schema)
	}
	if err := card.Verify(); err != nil {
		t.Fatalf("the version 1 seed card no longer verifies: %v", err)
	}
	pub, err := pack.LoadPublicKey(filepath.Join(root, "public-key.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyScorecard(&card, *card.Signature, pub); err != nil {
		t.Fatalf("the seed card's signatures no longer verify: %v", err)
	}
	if card.ModeStanding() != StandingSelfGraded {
		t.Errorf("the reference-mode seed card's standing reads %q",
			card.ModeStanding())
	}
	// The legacy form is not the canonical one: had the digest moved to
	// RFC 8785 under the version 1 name, every published card would fail.
	legacy, err := legacyBytes(&card)
	if err != nil {
		t.Fatal(err)
	}
	card.Schema = DocSchema
	canon, err := card.digestBytes()
	card.Schema = DocSchemaV1
	if err == nil && string(canon) == string(legacy) {
		t.Fatal("the legacy and canonical forms coincide; the test cannot " +
			"tell the two schemas apart")
	}

	grown := card
	grown.Standing = StandingSelfGraded
	if err := grown.Verify(); err == nil ||
		!strings.Contains(err.Error(), "fields that schema never had") {
		t.Fatalf("a version 1 document carrying a standing verified (%v)", err)
	}
	grown = card
	grown.Mutation = &MutationReport{}
	if err := grown.Verify(); err == nil ||
		!strings.Contains(err.Error(), "fields that schema never had") {
		t.Fatalf("a version 1 document carrying a mutation section "+
			"verified (%v)", err)
	}
}
