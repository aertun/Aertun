// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/aertun/aertun/internal/pack"
)

// Signing a proof: a DSSE envelope (https://github.com/secure-systems-lab/dsse)
// carrying the statement, with one signature from each half of the dual key.
//
// DSSE signs PAE(payloadType, payload) — a length-prefixed encoding that
// begins "DSSEv1 " — so the Ed25519 half cannot be confused with a pack
// metadata signature or a scorecard signature made by the same key: those
// sign messages that begin with their own context strings, and no PAE
// begins with one. The ML-DSA half is additionally bound to Context. An
// in-toto or Sigstore verifier given the Ed25519 public key checks the
// first half with no help from this program; the second half is checked
// here, and both are required here.

const (
	// PayloadType is DSSE's media type for an in-toto statement.
	PayloadType = "application/vnd.in-toto+json"
	// Context is the domain every proof's ML-DSA signature is made in, and
	// the context of the key fingerprint proofs name.
	Context = "aertun/proof/v1"
	// MaxEnvelope bounds a proof file. A proof caps the failures it lists,
	// so a real one is a few kilobytes; this is generous and finite.
	MaxEnvelope = 4 << 20
)

// Envelope is a signed proof.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature. The key ID is the dual key's
// fingerprint in Context with the algorithm appended, so each half names
// itself and a verifier never has to guess which is which.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

const (
	suffixEd = ":ed25519"
	suffixML = ":mldsa65"
)

// pae is DSSE's pre-authentication encoding: what both halves sign.
func pae(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// KeyID is the fingerprint proofs name a dual key by.
func KeyID(pub pack.KeyPublic) (string, error) { return pack.KeyIDIn(Context, pub) }

// Seal validates a statement and signs it with both halves of k.
func Seal(st *Statement, k *pack.Key) (*Envelope, error) {
	if err := st.Validate(); err != nil {
		return nil, fmt.Errorf("refusing to sign: %w", err)
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	edSig, mlSig, err := k.DualSign(pae(PayloadType, payload), Context)
	if err != nil {
		return nil, err
	}
	id, err := KeyID(k.PublicKey())
	if err != nil {
		return nil, err
	}
	return &Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{
			{KeyID: id + suffixEd, Sig: base64.StdEncoding.EncodeToString(edSig)},
			{KeyID: id + suffixML, Sig: base64.StdEncoding.EncodeToString(mlSig)},
		},
	}, nil
}

// Open checks both signatures against a trusted key and returns the
// statement only if both verify and it is one this version can read.
//
// Signatures by other keys are ignored rather than refused — DSSE allows
// an envelope to carry countersignatures — but the trusted key's two must
// both be present, exactly once each.
func Open(env *Envelope, pub pack.KeyPublic) (*Statement, error) {
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("the envelope carries %q, and a proof is %s",
			env.PayloadType, PayloadType)
	}
	id, err := KeyID(pub)
	if err != nil {
		return nil, err
	}
	var edB64, mlB64 string
	for _, s := range env.Signatures {
		var slot *string
		switch s.KeyID {
		case id + suffixEd:
			slot = &edB64
		case id + suffixML:
			slot = &mlB64
		default:
			continue
		}
		if *slot != "" {
			return nil, fmt.Errorf("the envelope carries %s twice", s.KeyID)
		}
		*slot = s.Sig
	}
	if edB64 == "" && mlB64 == "" {
		return nil, fmt.Errorf("nothing in this envelope was signed by the "+
			"trusted key %s", id)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("the payload is not base64: %w", err)
	}
	if err := pack.DualVerifyBase64(pae(env.PayloadType, payload), Context,
		edB64, mlB64, pub); err != nil {
		return nil, err
	}
	// Only now is the payload trusted enough to parse, and it is parsed
	// strictly: a field this version does not know is something the
	// signer said that this verifier would silently not have read.
	var st Statement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("the signed statement is not one this version reads: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("the signed payload carries more than one statement")
	}
	if err := st.Validate(); err != nil {
		return nil, fmt.Errorf("the signed statement is invalid: %w", err)
	}
	return &st, nil
}

// ReadEnvelope reads a proof file under MaxEnvelope.
func ReadEnvelope(path string) (*Envelope, error) {
	body, err := ReadBounded(path, MaxEnvelope)
	if err != nil {
		return nil, err
	}
	env, err := ParseEnvelope(body)
	if err != nil {
		return nil, fmt.Errorf("%s %w", path, err)
	}
	return env, nil
}

// ParseEnvelope reads an envelope already in memory, under the same bound
// and the same strictness as a file.
func ParseEnvelope(body []byte) (*Envelope, error) {
	if len(body) > MaxEnvelope {
		return nil, fmt.Errorf("is larger than the %d bytes a proof may be", MaxEnvelope)
	}
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("is not a proof envelope: %w", err)
	}
	return &env, nil
}

// ReadBounded reads a whole file, refusing one larger than limit rather
// than truncating it: a truncated input digests to something nobody
// meant to submit.
func ReadBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s is larger than the %d bytes allowed here", path, limit)
	}
	return body, nil
}
