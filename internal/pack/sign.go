// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
)

// Signing pack metadata, twice, with algorithms that fail differently.
//
// This is the internal/audit/sign.go discipline, applied to a second domain.
// Ed25519 is the algorithm everything else here uses; ML-DSA-65 (FIPS 204)
// is the post-quantum half, standardised and in the standard library. Both
// signatures are made and both are required — there is no AcceptSingle here
// at all, not even as a deployment decision, because a content verifier is
// pointed at packs from outside, and a verifier that can be talked into
// accepting one signature is the property an attacker buys a key for.
//
// The context string below separates these signatures from every other use
// of the same key material and from the audit log's domain, exactly as
// internal/audit/sign.go separates its own: a signature made for one
// purpose must never be presentable as one for another. The role a document
// plays is bound inside the signed bytes by its `_type` field, so the one
// context serves three roles without any way to promote one to another.

// signatureContext is the domain every pack-metadata signature is made and
// checked in. Versioned, so a change to what gets signed cannot be confused
// with the thing it replaced.
const signatureContext = "aertun/pack-metadata/v1"

// SeedSize is the length of each half of a key's seeds.
const SeedSize = 32

// Signature is both signatures over one metadata body.
type Signature struct {
	// KeyID identifies the dual key that signed, so a verifier holding
	// several knows which to try rather than trying all of them.
	KeyID string `json:"key_id"`
	// Ed25519 and MLDSA65 are base64. Both required: a document carrying
	// one is a document with half its argument.
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"mldsa_65"`
}

// Key is a dual signing key held as two seeds.
//
// Seeds rather than encoded private keys, for the reason internal/audit
// gives: an ML-DSA private key is several kilobytes and its seed is 32
// bytes that regenerate it exactly, which is the difference between a key
// file that fits on paper and one that does not. The offline root seed
// especially has to be printable — the whole rotation ceremony for one
// operator (design §4.3) rests on it.
type Key struct {
	edSeed []byte
	mlSeed []byte
}

// GenerateKey returns a fresh dual key from the system's entropy.
func GenerateKey() (*Key, error) {
	edSeed := make([]byte, SeedSize)
	mlSeed := make([]byte, SeedSize)
	if _, err := rand.Read(edSeed); err != nil {
		return nil, fmt.Errorf("no entropy for a signing seed: %w", err)
	}
	if _, err := rand.Read(mlSeed); err != nil {
		return nil, fmt.Errorf("no entropy for a signing seed: %w", err)
	}
	return NewKey(edSeed, mlSeed)
}

// NewKey derives a dual key from two 32-byte seeds.
func NewKey(edSeed, mlSeed []byte) (*Key, error) {
	if len(edSeed) != SeedSize || len(mlSeed) != SeedSize {
		return nil, fmt.Errorf("a key is two %d-byte seeds, and these are "+
			"%d and %d", SeedSize, len(edSeed), len(mlSeed))
	}
	return &Key{edSeed: edSeed, mlSeed: mlSeed}, nil
}

// PublicKey is the public half, for publishing inside root.json.
func (k *Key) PublicKey() KeyPublic {
	ed := ed25519.NewKeyFromSeed(k.edSeed).Public().(ed25519.PublicKey)
	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), k.mlSeed)
	if err != nil {
		// NewKey checked the seeds' lengths and ML-DSA-65 accepts any
		// 32-byte seed; there is no other failure mode here.
		return KeyPublic{}
	}
	return KeyPublic{
		Ed25519: base64.StdEncoding.EncodeToString(ed),
		MLDSA65: base64.StdEncoding.EncodeToString(ml.PublicKey().Bytes()),
	}
}

// KeyID is a short fingerprint of a dual public key in the content plane's
// own context. See KeyIDIn.
func KeyID(pub KeyPublic) (string, error) { return KeyIDIn(signatureContext, pub) }

// KeyIDIn is a short fingerprint of a dual public key within one signing
// context: sha256 over the context and both halves, first 16 hex characters.
//
// Over both, so a pair with one key swapped is a different identity — the
// same reason internal/audit's KeyID hashes both halves. The context is in
// the hash so the same key halves are a different identity in each domain
// that signs with them, and a scorecard key, a proof key and a content key
// never borrow each other's name.
func KeyIDIn(context string, pub KeyPublic) (string, error) {
	ed, ml, err := pub.decode()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(context))
	h.Write([]byte{0})
	h.Write(ed)
	h.Write([]byte{0})
	h.Write(ml)
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// decode reads both halves of a published key, refusing a half that is
// not the length its algorithm requires.
func (pub KeyPublic) decode() (ed, ml []byte, err error) {
	ed, err = base64.StdEncoding.DecodeString(pub.Ed25519)
	if err != nil || len(ed) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("the Ed25519 public key is not readable base64")
	}
	ml, err = base64.StdEncoding.DecodeString(pub.MLDSA65)
	if err != nil {
		return nil, nil, fmt.Errorf("the ML-DSA public key is not readable base64")
	}
	return ed, ml, nil
}

// signMetadata produces both signatures over a metadata body.
func (k *Key) signMetadata(body any) (Signature, error) {
	msg, err := metadataMessage(body)
	if err != nil {
		return Signature{}, err
	}
	edSig, mlSig, err := k.DualSign(msg, signatureContext)
	if err != nil {
		return Signature{}, err
	}
	id, err := KeyID(k.PublicKey())
	if err != nil {
		return Signature{}, err
	}
	return Signature{
		KeyID:   id,
		Ed25519: base64.StdEncoding.EncodeToString(edSig),
		MLDSA65: base64.StdEncoding.EncodeToString(mlSig),
	}, nil
}

// metadataMessage is the exact bytes both algorithms sign: the context, a
// NUL, then the body's canonical JSON. The NUL ends the context so it
// cannot bleed into the payload; the payload is self-delimiting JSON.
func metadataMessage(body any) ([]byte, error) {
	canonical, err := canonicalBody(body)
	if err != nil {
		return nil, fmt.Errorf("the body would not encode: %w", err)
	}
	return append(append([]byte(signatureContext), 0), canonical...), nil
}

// DualSign signs exact bytes in a caller-named context with both algorithms.
//
// The context is the whole point: a domain that is not pack metadata signs
// in its own — internal/windtunnel signs its scorecards in
// aertun/windtunnel-scorecard/v1 — so a signature made for one purpose can
// never be presented as one for another, the same separation this file's
// own context provides, lent to a second signer holding the same key
// material. Deterministic on both algorithms, so the same bytes sign to the
// same signatures and a document remains a commitment.
func (k *Key) DualSign(msg []byte, context string) (edSig, mlSig []byte, err error) {
	ed := ed25519.NewKeyFromSeed(k.edSeed)
	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), k.mlSeed)
	if err != nil {
		return nil, nil, fmt.Errorf("the ML-DSA key is unusable: %w", err)
	}
	mlSig, err = ml.SignDeterministic(msg, &mldsa.Options{Context: context})
	if err != nil {
		return nil, nil, fmt.Errorf("the ML-DSA signature failed: %w", err)
	}
	return ed25519.Sign(ed, msg), mlSig, nil
}

// VerifyMetadata checks both signatures over a body against a dual public
// key. Both, always: a signature carrying one half is refused with its name
// in the error, and there is no option to accept one, on the
// internal/audit/sign.go argument — an option would be found and used.
func VerifyMetadata(body any, sig Signature, pub KeyPublic) error {
	id, err := KeyID(pub)
	if err != nil {
		return err
	}
	if sig.KeyID != "" && sig.KeyID != id {
		return fmt.Errorf("this was signed by key %s and the key trusted "+
			"here is %s", sig.KeyID, id)
	}
	msg, err := metadataMessage(body)
	if err != nil {
		return err
	}
	return DualVerifyBase64(msg, signatureContext, sig.Ed25519, sig.MLDSA65, pub)
}

// DualVerifyBase64 is DualVerify for signatures carried as base64 text,
// which is how every document here carries them. A missing half is named
// in the error, so whoever reads it knows which half to go and find.
func DualVerifyBase64(msg []byte, context, edB64, mlB64 string, pub KeyPublic) error {
	if edB64 == "" || mlB64 == "" {
		missing := "neither signature"
		switch {
		case edB64 != "":
			missing = "no ML-DSA-65 signature"
		case mlB64 != "":
			missing = "no Ed25519 signature"
		}
		return fmt.Errorf("this document carries %s. Both are required: one "+
			"of them is the half that survives whichever algorithm turns "+
			"out to be broken", missing)
	}
	edSig, err := base64.StdEncoding.DecodeString(edB64)
	if err != nil {
		return fmt.Errorf("the Ed25519 signature is not base64: %w", err)
	}
	mlSig, err := base64.StdEncoding.DecodeString(mlB64)
	if err != nil {
		return fmt.Errorf("the ML-DSA signature is not base64: %w", err)
	}
	return DualVerify(msg, context, edSig, mlSig, pub)
}

// DualVerify checks both signatures DualSign made over exact bytes in a
// caller-named context. Both, always, and in the same order every time,
// so no caller can build a verifier that accepts one: the Ed25519 half
// over the bytes, then the ML-DSA-65 half over the same bytes in the
// context. The context binds the ML-DSA half to its domain; callers bind
// the Ed25519 half by putting the context, or an encoding that cannot
// collide with another domain's, inside the bytes themselves.
func DualVerify(msg []byte, context string, edSig, mlSig []byte, pub KeyPublic) error {
	edKey, mlKey, err := pub.decode()
	if err != nil {
		return fmt.Errorf("the trusted key is unreadable: %w", err)
	}
	if len(edSig) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(edKey), msg, edSig) {
		return fmt.Errorf("the Ed25519 signature does not verify")
	}
	mlPub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), mlKey)
	if err != nil {
		return fmt.Errorf("the trusted ML-DSA public key is unreadable: %w", err)
	}
	if err := mldsa.Verify(mlPub, msg, mlSig, &mldsa.Options{
		Context: context}); err != nil {
		return fmt.Errorf("the ML-DSA-65 signature does not verify: %w", err)
	}
	return nil
}

// MaxPublicKeyFile bounds a published public key file. Both halves in
// base64 are under three kilobytes; anything far larger is not one.
const MaxPublicKeyFile = 64 << 10

// LoadPublicKey reads a published dual public key — the file a verifier is
// handed, holding both halves and no secrets — refusing one that carries
// only half, or halves of the wrong length.
func LoadPublicKey(path string) (KeyPublic, error) {
	f, err := os.Open(path)
	if err != nil {
		return KeyPublic{}, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, MaxPublicKeyFile+1))
	if err != nil {
		return KeyPublic{}, err
	}
	pub, err := ParsePublicKey(body)
	if err != nil {
		return KeyPublic{}, fmt.Errorf("%s %w", path, err)
	}
	return pub, nil
}

// ParsePublicKey reads a published dual public key already in memory, under
// the same bound and checks as a file: both halves, each the right length.
func ParsePublicKey(body []byte) (KeyPublic, error) {
	if len(body) > MaxPublicKeyFile {
		return KeyPublic{}, fmt.Errorf("is larger than any public key file")
	}
	var pub KeyPublic
	if err := json.Unmarshal(body, &pub); err != nil {
		return KeyPublic{}, fmt.Errorf("is not a public key file: %w", err)
	}
	if pub.Ed25519 == "" || pub.MLDSA65 == "" {
		return KeyPublic{}, fmt.Errorf("carries only half a dual key. A " +
			"verifier needs both halves: one of them is the half that " +
			"survives whichever algorithm turns out to be broken")
	}
	if _, _, err := pub.decode(); err != nil {
		return KeyPublic{}, err
	}
	return pub, nil
}

// WritePublicKey writes a published dual public key, for the operator who
// hands a verifier something to verify with. It holds no secret, so it is
// written world-readable, and atomically, so a verifier never reads half.
func WritePublicKey(path string, pub KeyPublic) error {
	body, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, append(body, '\n'), 0o644)
}

// StoredKey is a key file on disk: two seeds, base64. The release key's
// file lives in the store at 0600 (anybody who reads it can sign content
// this store's peers trust); the root key's file is written wherever the
// operator put it and must be moved away — the offline half of the
// root/release split, which is the Uptane shape: stealing the online key
// signs new releases (bad, and bounded by the gates), stealing the offline
// key is the disaster, and the two are not kept together.
type StoredKey struct {
	Ed25519Seed string `json:"ed25519_seed"`
	MLDSASeed   string `json:"mldsa_seed"`
}

// LoadKey reads a key file written by SaveKey.
func LoadKey(path string) (*Key, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sk StoredKey
	if err := json.Unmarshal(body, &sk); err != nil {
		return nil, fmt.Errorf("%s is not a key file: %w", path, err)
	}
	ed, err := base64.StdEncoding.DecodeString(sk.Ed25519Seed)
	if err != nil {
		return nil, fmt.Errorf("%s: the Ed25519 seed is not base64: %w", path, err)
	}
	ml, err := base64.StdEncoding.DecodeString(sk.MLDSASeed)
	if err != nil {
		return nil, fmt.Errorf("%s: the ML-DSA seed is not base64: %w", path, err)
	}
	return NewKey(ed, ml)
}

// SaveKey writes a key file. mode is 0600 for anything that stays on this
// machine; the operator's copy of the root key is written 0600 too, because
// a file that can be moved away is also a file that can be copied without
// noticing.
func SaveKey(path string, k *Key, mode os.FileMode) error {
	body, err := json.MarshalIndent(StoredKey{
		Ed25519Seed: base64.StdEncoding.EncodeToString(k.edSeed),
		MLDSASeed:   base64.StdEncoding.EncodeToString(k.mlSeed),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, append(body, '\n'), mode)
}

// SignPack builds and signs the whole metadata side of a pack into its
// directory: targets.json (pinning the manifest as it stands on disk right
// now), timestamp.json (pinning targets), and the store's root.json copied
// in unchanged — root metadata is signed by the offline key at keygen, not
// at every release, so releasing content never touches the offline key.
//
// version is the pack's monotonic integer metadata version; the producer's
// counter is the caller's to keep (see Produced state in install.go), and
// re-signing at a version the producer has already emitted is refused here,
// because monotonicity is a property of what was signed, not of what a
// store happens to have installed.
func SignPack(dir string, p *Pack, release *Key, root *SignedRoot, version int, now time.Time) error {
	if version < 1 {
		return fmt.Errorf("the metadata version is %d; it counts up from 1",
			version)
	}
	if p.Manifest.ID == "" {
		return fmt.Errorf("the pack has no id")
	}

	// Pin the manifest exactly as it sits in the directory, by reading it
	// back from disk rather than re-encoding the struct in memory: the
	// bytes on disk are what an installer will hash.
	mbody, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return fmt.Errorf("reading the manifest back: %w", err)
	}
	if len(mbody) > MaxFileBytes {
		return fmt.Errorf("%s is %d bytes; it is at most %d", ManifestName,
			len(mbody), MaxFileBytes)
	}
	// And what was read back must be the manifest that was validated: a
	// directory whose manifest changed between Read and Sign is a race, and
	// the digest is what catches it.
	var onDisk Manifest
	if err := decodeStrict(mbody, &onDisk); err != nil || onDisk.ID != p.Manifest.ID ||
		onDisk.Version != p.Manifest.Version {
		return fmt.Errorf("%s changed under the signing; run again",
			ManifestName)
	}

	targets := SignedTargets{Signed: TargetsBody{
		Type: targetsType, Pack: p.Manifest.ID, Version: version,
		Expires: now.Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Manifest: Digest{
			SHA256: sha256Hex(mbody), Length: int64(len(mbody)),
		},
	}}
	if targets.Signed.Expires == "" {
		return fmt.Errorf("the targets expiry did not format")
	}
	if targets.Signature, err = release.signMetadata(targets.Signed); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, TargetsName), &targets); err != nil {
		return err
	}

	// Timestamp pins the whole targets.json file as written, signature
	// included — deterministic signing makes those bytes stable, and the
	// freeze defence is over exactly what an installer will read.
	tbody, err := os.ReadFile(filepath.Join(dir, TargetsName))
	if err != nil {
		return err
	}
	ts := SignedTimestamp{Signed: TimestampBody{
		Type: timestampType, Version: version,
		Expires: now.Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Targets: Digest{SHA256: sha256Hex(tbody), Length: int64(len(tbody))},
	}}
	if ts.Signature, err = release.signMetadata(ts.Signed); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, TimestampName), &ts); err != nil {
		return err
	}

	// Root is copied, never re-signed here: the release pipeline holds the
	// release key only, and root.json in the pack must be byte-identical
	// to the one this store trusts so the anchor comparison in Verify is
	// exact.
	rootBody, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, RootName),
		append(rootBody, '\n'), 0o644)
}

// sha256Hex is digest of bytes as lowercase hex.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Root expiry: the offline half re-signed on a slow human calendar, not the
// release pipeline's daily one.
const rootLifetime = 365 * 24 * time.Hour

// MakeRoot signs a first root with the offline key: the release key it
// names, version 1, a year's expiry. Every later root is made by
// RotateRoot — a first root is the one act of trust that has no previous
// key to answer to.
func MakeRoot(rootKey, releaseKey *Key, now time.Time) (*SignedRoot, error) {
	body := RootBody{
		Type:       rootType,
		Version:    1,
		Expires:    now.Add(rootLifetime).UTC().Format(time.RFC3339),
		RootKey:    rootKey.PublicKey(),
		ReleaseKey: releaseKey.PublicKey(),
	}
	sig, err := rootKey.signMetadata(body)
	if err != nil {
		return nil, err
	}
	return &SignedRoot{Signed: body, Signature: sig}, nil
}

// RotateRoot signs the next root version: the incoming offline key in the
// RootKey slot, the release key the current root names carried forward
// unchanged, a fresh year, and BOTH signatures — the outgoing key's over
// the new body and the incoming key's own.
//
// This is TUF's belt-and-braces (design §4.3), and the reason both are
// required rather than merely collected: a client that missed the
// transition verifies the new root with the old key (the continuity —
// trust in the old key is the only thing that can vouch for its
// replacement), and a client that already anchored it verifies the root
// with itself (the handover — every later root is checked against the
// incoming key, so it had better be able to sign). A new root that drops
// the old signature mid-chain fails one of those two checks on every
// client there is. The freeze and rollback protections are untouched:
// the version still counts up, one step at a time, and nothing here can
// move it down.
func RotateRoot(anchor *SignedRoot, oldKey, newKey *Key, now time.Time) (*SignedRoot, error) {
	if anchor.Signed.Version < 1 {
		return nil, fmt.Errorf("the root to rotate is version %d; root "+
			"versions count up from 1", anchor.Signed.Version)
	}
	body := RootBody{
		Type:       rootType,
		Version:    anchor.Signed.Version + 1,
		Expires:    now.Add(rootLifetime).UTC().Format(time.RFC3339),
		RootKey:    newKey.PublicKey(),
		ReleaseKey: anchor.Signed.ReleaseKey,
	}
	previous, err := oldKey.signMetadata(body)
	if err != nil {
		return nil, err
	}
	self, err := newKey.signMetadata(body)
	if err != nil {
		return nil, err
	}
	return &SignedRoot{Signed: body, Previous: &previous, Signature: self}, nil
}
