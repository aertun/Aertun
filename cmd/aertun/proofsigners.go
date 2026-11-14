// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/dual"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proofstore"
)

// The keys this store trusts to sign proofs in its name
// (internal/proofstore): `aertun proof signers`, `aertun proof trust NAME
// --key PUB --why "..."` and `aertun proof untrust NAME`.
//
// Trusting a key grants authority — every proof it signs is shown on every
// face as signed by a trusted signer — so it waits for a second
// administrator, as making somebody an administrator does, and the only
// administrator's own request waits out its delay. Untrusting only takes
// authority away, and an administrator does it alone, on the record.

func proofSigners(root string, args []string) error {
	caller := resolveCaller(root, "")
	if err := authorise(root, caller, auth.ActView, auth.AreaSecurity); err != nil {
		return err
	}
	signers, err := proofstore.Signers(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"signers": signers}) {
		return nil
	}
	if len(signers) == 0 {
		w.Human("no key is trusted to sign proofs here yet, so every proof is shown as signed by a key this store does not trust\n")
		w.Human("  %saertun proof trust NAME --key PUBLIC-KEY --why \"...\"%s\n", dim, reset)
		return nil
	}
	for _, s := range signers {
		w.Human("%s%s%s  key %s\n  added %s by %s: %s\n", bold, s.Name, reset, s.KeyID,
			s.AddedAt.Format("2 Jan 2006"), s.AddedBy, s.Why)
	}
	return nil
}

func proofTrust(root string, args []string) error {
	fs := flag.NewFlagSet("proof trust", flag.ContinueOnError)
	keyAt := fs.String("key", "", "the signer's public key file")
	why := fs.String("why", "", "why this key may speak for the store, kept with it")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || *keyAt == "" {
		return errors.New(`usage: aertun proof trust NAME --key PUBLIC-KEY --why "..."`)
	}
	caller := resolveCaller(root, "")
	if err := authorise(root, caller, auth.ActGrant, auth.AreaSecurity); err != nil {
		return err
	}
	if caller.Kind == audit.KindAI {
		return errors.New("which keys speak for the store is decided by people, never by an agent")
	}
	pub, err := os.ReadFile(*keyAt)
	if err != nil {
		return err
	}
	if len(pub) > pack.MaxPublicKeyFile {
		return fmt.Errorf("%s is larger than a public key file", *keyAt)
	}
	_, kid, err := proofstore.CheckSigner(pos[0], pub, *why)
	if err != nil {
		return err
	}
	_, err = proposeSecond(root, caller, dual.Signer,
		fmt.Sprintf("trust key %s to sign proofs as %s", kid, pos[0]),
		dual.SignerChange{Name: pos[0], Key: json.RawMessage(pub), Why: *why}, *why, "--why")
	return err
}

func proofUntrust(root string, args []string) error {
	fs := flag.NewFlagSet("proof untrust", flag.ContinueOnError)
	why := fs.String("why", "", "why the key no longer speaks for the store")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(`usage: aertun proof untrust NAME [--why "..."]`)
	}
	caller := resolveCaller(root, "")
	if err := authorise(root, caller, auth.ActGrant, auth.AreaSecurity); err != nil {
		return err
	}
	gone, err := proofstore.Untrust(root, pos[0])
	if err != nil {
		return err
	}
	if !gone {
		return fmt.Errorf("no signer called %s is trusted", pos[0])
	}
	if err := recordE(root, caller.auditRecord("proof.untrusted", "/proofs", audit.Success,
		map[string]string{"signer": pos[0], "why": *why})); err != nil {
		return err
	}
	w.Human("%s no longer signs for this store; the proofs it signed stay kept, shown as signed by a key it does not trust\n", pos[0])
	return nil
}

// applySigner trusts a key once its request is approved.
func applySigner(root string, r dual.Request) error {
	var ch dual.SignerChange
	if err := json.Unmarshal(r.Payload, &ch); err != nil {
		return err
	}
	s, err := proofstore.Trust(root, ch.Name, ch.Key, r.By, ch.Why, time.Now())
	if err != nil {
		return err
	}
	return recordE(root, resolveCaller(root, "").auditRecord("proof.trusted", "/proofs", audit.Success,
		map[string]string{"signer": s.Name, "fingerprint": s.KeyID, "request": r.ID, "asked_by": r.By}))
}
