// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package proofstore keeps signed proofs in the store, so the console, the
// command line and the agent interface can show what has been proven,
// refuted and left inconclusive, and by whom.
//
// A proof is a file anybody can check without this program (internal/proof),
// and most are made somewhere else: in CI, on an analyst's machine, by
// another deployment. Keeping one here means three things. It verifies, both
// signatures over a statement this version can read, against the public key
// handed over with it, or it is not kept. The key it verified with is kept
// beside it, by fingerprint, so a reader can see whose signature it is and
// decide whether they trust that key — verifying says the bytes are what the
// key signed, never that the key is one to believe. And it is checked again
// every time it is read, so a file edited after it was kept shows as one that
// no longer verifies rather than as what it now says.
package proofstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// Format names a kept proof's file and its version.
const Format = "aertun/kept-proof/v1"

// MaxKept bounds how many proofs the store holds. Listing reads and verifies
// every one, so a bound is what keeps a page of them a page.
const MaxKept = 2000

// maxFile bounds one kept file: the envelope's own bound and a public key.
const maxFile = proof.MaxEnvelope + pack.MaxPublicKeyFile + 4096

// Kept is one kept proof as it is written.
type Kept struct {
	Format   string         `json:"format"`
	Envelope proof.Envelope `json:"envelope"`
	Key      pack.KeyPublic `json:"public_key"`
	KeyID    string         `json:"key_id"`
	KeptAt   time.Time      `json:"kept_at"`
	KeptBy   string         `json:"kept_by"`
	Origin   string         `json:"origin"`
}

// The closed set of where a kept proof came from.
const (
	// OriginHere is a proof a command of this store made and kept itself.
	OriginHere = "made-here"
	// OriginHandedIn is a proof somebody handed in with its public key.
	OriginHandedIn = "handed-in"
)

// Entry is a kept proof as it is read: the statement when it still verifies,
// and why not when it does not.
type Entry struct {
	ID        string           `json:"id"`
	KeyID     string           `json:"key_id,omitempty"`
	KeptAt    time.Time        `json:"kept_at,omitzero"`
	KeptBy    string           `json:"kept_by,omitempty"`
	Origin    string           `json:"origin,omitempty"`
	Statement *proof.Statement `json:"statement,omitempty"`
	// Broken is why the kept file no longer verifies, or no longer reads as
	// one; empty when it does.
	Broken string `json:"broken,omitempty"`
	// Signer is the name of the trusted signer whose key signed it, worked
	// out when it is read; empty when this store does not trust that key.
	Signer string `json:"signer,omitempty"`
}

var idShape = regexp.MustCompile(`^[0-9a-f]{24}$`)

// ValidID reports whether s has the shape of a kept proof's id.
func ValidID(s string) bool { return idShape.MatchString(s) }

// Dir is where a store keeps its proofs.
func Dir(root string) string { return filepath.Join(root, "proofs") }

// idOf names a proof by the statement it signs, so the same statement handed
// in twice, or signed again, is one proof kept once.
func idOf(env *proof.Envelope) (string, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return "", fmt.Errorf("the envelope's payload is not base64")
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:12]), nil
}

// ErrAlreadyKept is a proof the store already holds.
var ErrAlreadyKept = errors.New("that proof is already kept")

// Keep verifies the envelope in body against the public key in pub and, when
// it verifies, keeps both. It returns the proof's id and statement.
func Keep(root string, body, pub []byte, by, origin string, now time.Time) (string, *proof.Statement, error) {
	if origin != OriginHere && origin != OriginHandedIn {
		return "", nil, fmt.Errorf("a kept proof comes from here or was handed in")
	}
	env, err := proof.ParseEnvelope(body)
	if err != nil {
		return "", nil, fmt.Errorf("the proof %w", err)
	}
	key, err := pack.ParsePublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("the public key %w", err)
	}
	st, err := proof.Open(env, key)
	if err != nil {
		return "", nil, fmt.Errorf("the proof does not verify against that key, so it was not kept: %w", err)
	}
	kid, err := proof.KeyID(key)
	if err != nil {
		return "", nil, err
	}
	id, err := idOf(env)
	if err != nil {
		return "", nil, err
	}
	dir := Dir(root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	unlock, err := atomicfile.Lock(filepath.Join(dir, ".lock"))
	if err != nil {
		return "", nil, err
	}
	defer unlock()
	path := filepath.Join(dir, id+".json")
	if _, err := os.Stat(path); err == nil {
		return id, st, ErrAlreadyKept
	}
	names, err := keptNames(dir)
	if err != nil {
		return "", nil, err
	}
	if len(names) >= MaxKept {
		return "", nil, fmt.Errorf("the store keeps at most %d proofs and holds %d", MaxKept, len(names))
	}
	doc, err := json.MarshalIndent(Kept{Format: Format, Envelope: *env, Key: key, KeyID: kid,
		KeptAt: now.UTC(), KeptBy: by, Origin: origin}, "", "  ")
	if err != nil {
		return "", nil, err
	}
	// 0600, like every proof file this program writes: a proof names what it
	// read, and what it read is named after what happened to somebody.
	if err := atomicfile.Write(path, append(doc, '\n'), 0o600); err != nil {
		return "", nil, err
	}
	return id, st, nil
}

func keptNames(dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range des {
		id, ok := strings.CutSuffix(d.Name(), ".json")
		if ok && ValidID(id) && d.Type().IsRegular() {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Get reads one kept proof and checks it again.
func Get(root, id string) (Entry, error) {
	if !ValidID(id) {
		return Entry{}, fmt.Errorf("a proof's id is 24 hexadecimal characters")
	}
	path := filepath.Join(Dir(root), id+".json")
	body, err := proof.ReadBounded(path, maxFile)
	if errors.Is(err, os.ErrNotExist) {
		return Entry{}, fmt.Errorf("no proof is kept with that id")
	}
	if err != nil {
		return Entry{}, err
	}
	signers, err := Signers(root)
	if err != nil {
		return Entry{}, err
	}
	e := read(id, body)
	e.Signer = SignerOf(signers, e.KeyID)
	return e, nil
}

// read turns a kept file into an entry, checking it as Keep did. A file that
// fails is still an entry, marked broken: one that vanished from the list
// would hide that somebody edited it.
func read(id string, body []byte) Entry {
	e := Entry{ID: id}
	var k Kept
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&k); err != nil || k.Format != Format {
		e.Broken = "the file does not read as a kept proof"
		return e
	}
	e.KeyID, e.KeptAt, e.KeptBy, e.Origin = k.KeyID, k.KeptAt, k.KeptBy, k.Origin
	if want, err := idOf(&k.Envelope); err != nil || want != id {
		e.Broken = "the file holds a different proof from the one its name says"
		return e
	}
	kid, err := proof.KeyID(k.Key)
	if err != nil || kid != k.KeyID {
		e.Broken = "the key kept with it is not the key its fingerprint names"
		return e
	}
	st, err := proof.Open(&k.Envelope, k.Key)
	if err != nil {
		e.Broken = "it no longer verifies against the key it was kept with"
		return e
	}
	e.Statement = st
	return e
}

// List reads every kept proof, newest first.
func List(root string) ([]Entry, error) {
	dir := Dir(root)
	names, err := keptNames(dir)
	if err != nil {
		return nil, err
	}
	signers, err := Signers(root)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(names))
	for _, id := range names {
		body, err := proof.ReadBounded(filepath.Join(dir, id+".json"), maxFile)
		if err != nil {
			out = append(out, Entry{ID: id, Broken: "the file could not be read"})
			continue
		}
		e := read(id, body)
		e.Signer = SignerOf(signers, e.KeyID)
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].KeptAt.After(out[j].KeptAt) })
	return out, nil
}
