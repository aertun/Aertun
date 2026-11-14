// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proofstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// Signers: the keys this store trusts to speak for it.
//
// A proof says which key signed it, and nothing about whether that key
// belongs to anybody the organisation relies on: a key anybody can make
// signs a proof that verifies. So the store keeps a short list of the keys
// it trusts — the one its own verifiers sign with, a partner's, an
// auditor's — each with a name, and every face shows a kept proof as
// signed by a trusted signer or by a key this store does not trust. The
// label is worked out each time a proof is read, never written beside it,
// so removing a signer takes the word "trusted" off every proof it signed
// at once.
//
// Adding a signer is the one change here that grants authority, and it is
// made through a request a second administrator approves (internal/dual);
// removing one only takes authority away, and an administrator does it
// alone.

// Signer is one trusted key.
type Signer struct {
	Name    string         `json:"name"`
	KeyID   string         `json:"key_id"`
	Key     pack.KeyPublic `json:"public_key"`
	AddedBy string         `json:"added_by"`
	AddedAt time.Time      `json:"added_at"`
	Why     string         `json:"why"`
}

// signersFile is the list of trusted signers.
type signersFile struct {
	Signers []Signer `json:"signers"`
}

// MaxSigners bounds the list: a handful of keys a person can review.
const MaxSigners = 64

// maxWhy bounds the reason kept with a signer.
const maxWhy = 500

var signerName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidSignerName reports whether s can name a signer: lower case letters,
// digits, dots, dashes and underscores, starting with a letter or digit.
func ValidSignerName(s string) bool { return signerName.MatchString(s) }

func signersPath(root string) string { return filepath.Join(Dir(root), "signers.json") }

// Signers is every trusted signer, in the order they were added.
func Signers(root string) ([]Signer, error) {
	var f signersFile
	if err := loadSigners(root, &f); err != nil {
		return nil, err
	}
	return f.Signers, nil
}

func loadSigners(root string, f *signersFile) error {
	body, err := proof.ReadBounded(signersPath(root), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := strictJSON(body, f); err != nil {
		return fmt.Errorf("%s does not read as a list of signers: %w", signersPath(root), err)
	}
	return nil
}

// CheckSigner says what is wrong with a signer about to be trusted, before
// anybody is asked to approve it: its name, its key, its reason.
func CheckSigner(name string, pub []byte, why string) (pack.KeyPublic, string, error) {
	if !ValidSignerName(name) {
		return pack.KeyPublic{}, "", fmt.Errorf("%q cannot name a signer: lower case letters, digits, dots, dashes and underscores", name)
	}
	why = strings.TrimSpace(why)
	if why == "" {
		return pack.KeyPublic{}, "", errors.New("trusting a key takes a reason, kept with it")
	}
	if utf8.RuneCountInString(why) > maxWhy || strings.ContainsFunc(why, unicode.IsControl) {
		return pack.KeyPublic{}, "", fmt.Errorf("the reason is one line of at most %d characters", maxWhy)
	}
	key, err := pack.ParsePublicKey(pub)
	if err != nil {
		return pack.KeyPublic{}, "", fmt.Errorf("the public key %w", err)
	}
	kid, err := proof.KeyID(key)
	if err != nil {
		return pack.KeyPublic{}, "", err
	}
	return key, kid, nil
}

// Trust adds a signer. It is called once a second administrator has
// approved the request, so it checks everything again: the list may have
// changed while the request waited.
func Trust(root, name string, pub []byte, by, why string, now time.Time) (Signer, error) {
	key, kid, err := CheckSigner(name, pub, why)
	if err != nil {
		return Signer{}, err
	}
	s := Signer{Name: name, KeyID: kid, Key: key, AddedBy: by, AddedAt: now.UTC(), Why: strings.TrimSpace(why)}
	err = atomicfile.Update(signersPath(root), func(f *signersFile) error {
		for _, have := range f.Signers {
			switch {
			case have.Name == name:
				return fmt.Errorf("a signer called %s is already trusted", name)
			case have.KeyID == kid:
				return fmt.Errorf("that key is already trusted, as %s", have.Name)
			}
		}
		if len(f.Signers) >= MaxSigners {
			return fmt.Errorf("the store trusts at most %d signers", MaxSigners)
		}
		f.Signers = append(f.Signers, s)
		return nil
	})
	return s, err
}

// Untrust removes a signer by name, and reports whether there was one.
func Untrust(root, name string) (bool, error) {
	found := false
	err := atomicfile.Update(signersPath(root), func(f *signersFile) error {
		kept := f.Signers[:0]
		for _, s := range f.Signers {
			if s.Name == name {
				found = true
				continue
			}
			kept = append(kept, s)
		}
		if !found {
			return atomicfile.ErrUnchanged
		}
		f.Signers = kept
		return nil
	})
	return found, err
}

// SignerOf is the name of the trusted signer whose key has that
// fingerprint, or empty when no trusted signer has it.
func SignerOf(signers []Signer, keyID string) string {
	for _, s := range signers {
		if s.KeyID == keyID {
			return s.Name
		}
	}
	return ""
}

// strictJSON decodes one document, refusing fields it does not know.
func strictJSON(body []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Check verifies a proof against a public key without keeping it, and
// returns its statement and the key's fingerprint.
func Check(body, pub []byte) (*proof.Statement, string, error) {
	env, err := proof.ParseEnvelope(body)
	if err != nil {
		return nil, "", fmt.Errorf("the proof %w", err)
	}
	key, err := pack.ParsePublicKey(pub)
	if err != nil {
		return nil, "", fmt.Errorf("the public key %w", err)
	}
	st, err := proof.Open(env, key)
	if err != nil {
		return nil, "", fmt.Errorf("the proof does not verify against that key: %w", err)
	}
	kid, err := proof.KeyID(key)
	if err != nil {
		return nil, "", err
	}
	return st, kid, nil
}
