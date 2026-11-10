// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"encoding/base64"
	"fmt"

	"github.com/aertun/aertun/internal/pack"
)

// Signing a scorecard, twice, with algorithms that fail differently.
//
// This is internal/pack's signing discipline (internal/pack/sign.go), which
// is internal/audit's, applied to a third domain. Ed25519 because it is the
// algorithm everything else here uses; ML-DSA-65 (FIPS 204) because it is
// the post-quantum half, standardised and in the standard library. Both
// signatures are made and both are required — no AcceptSingle shape exists
// anywhere in this codebase, and a verifier that could be talked into one
// signature is the property an attacker buys a key for.
//
// The key material is the content plane's, reused: the same dual key a
// store's keygen made, the same seeds-on-disk format, the same release key
// the operator already holds. The context below is new and versioned, so a
// scorecard signature can never be re-presented as a pack signature or an
// audit head — a signature made for one purpose must never be presentable
// as one for another, and the separation lives in the signed bytes
// themselves.

// ScorecardContext is the domain every windtunnel-scorecard signature is
// made and checked in. Versioned, so a change to what gets signed cannot be
// confused with the thing it replaced.
//
// It names the signing domain and the message's construction (context,
// NUL, canonical bytes), which version 2 of the document did not change:
// the canonical bytes themselves carry the document's schema, so a version
// 1 body and a version 2 body can never be the same signed message, and
// each is verified only by the form its own schema names.
const ScorecardContext = "aertun/windtunnel-scorecard/v1"

// ScorecardSignature is both signatures over one sealed scorecard — the
// same shape as the content plane's Signature, in this domain.
type ScorecardSignature struct {
	// KeyID identifies the dual key that signed, so a verifier holding
	// several knows which to try rather than trying all of them.
	KeyID string `json:"key_id"`
	// Ed25519 and MLDSA65 are base64. Both required: a document carrying
	// one is a document with half its argument.
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"mldsa_65"`
}

// ScorecardKeyID is a short fingerprint of a dual public key in this
// domain — pack.KeyIDIn over the scorecard context, so the same key halves
// are a different identity here than they are in the content plane, and
// neither borrows the other's name.
func ScorecardKeyID(pub pack.KeyPublic) (string, error) {
	return pack.KeyIDIn(ScorecardContext, pub)
}

// scorecardMessage is the exact bytes both algorithms sign: the context, a
// NUL, then the sealed document's canonical bytes — the digest included, so
// the signature covers both the numbers and the check on the numbers. The
// NUL ends the context so it cannot bleed into the payload.
func scorecardMessage(card *Scorecard) ([]byte, error) {
	body, err := card.digestBytes()
	if err != nil {
		return nil, err
	}
	return append(append([]byte(ScorecardContext), 0), body...), nil
}

// SignScorecard produces both signatures over a sealed scorecard, using the
// content plane's dual key. Deterministic on both algorithms, so signing
// the same document twice produces the same bytes — a scorecard is a
// commitment, and two different signatures over one body invite the
// question of which is real.
func SignScorecard(card *Scorecard, k *pack.Key) (ScorecardSignature, error) {
	if card.SHA256 == "" {
		return ScorecardSignature{}, fmt.Errorf("the scorecard is not " +
			"sealed: an unsealed document has no digest to sign, and a " +
			"signature over nothing verifies nothing")
	}
	msg, err := scorecardMessage(card)
	if err != nil {
		return ScorecardSignature{}, err
	}
	edSig, mlSig, err := k.DualSign(msg, ScorecardContext)
	if err != nil {
		return ScorecardSignature{}, err
	}
	id, err := ScorecardKeyID(k.PublicKey())
	if err != nil {
		return ScorecardSignature{}, err
	}
	return ScorecardSignature{
		KeyID:   id,
		Ed25519: base64.StdEncoding.EncodeToString(edSig),
		MLDSA65: base64.StdEncoding.EncodeToString(mlSig),
	}, nil
}

// VerifyScorecard checks both signatures over a sealed document against a
// dual public key. Both, always: pack.DualVerifyBase64 refuses a signature
// carrying one half with its name in the error, and there is no option to
// accept one.
func VerifyScorecard(card *Scorecard, sig ScorecardSignature,
	pub pack.KeyPublic) error {

	id, err := ScorecardKeyID(pub)
	if err != nil {
		return err
	}
	if sig.KeyID != "" && sig.KeyID != id {
		return fmt.Errorf("this was signed by key %s and the key trusted "+
			"here is %s", sig.KeyID, id)
	}
	if card.SHA256 == "" {
		return fmt.Errorf("the scorecard is not sealed, so what a signature " +
			"would verify against is undefined")
	}
	msg, err := scorecardMessage(card)
	if err != nil {
		return err
	}
	return pack.DualVerifyBase64(msg, ScorecardContext, sig.Ed25519, sig.MLDSA65, pub)
}
