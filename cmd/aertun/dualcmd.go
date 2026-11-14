// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/dual"
)

// Privileged changes that wait for a second administrator (internal/dual):
// where they are proposed from the command line, and `aertun pending`,
// where they are decided.

func dualStore(root string) *dual.Store {
	return &dual.Store{Path: filepath.Join(root, "dual.json")}
}

// proposeSecond records a privileged change for a second administrator.
// It reports whether the caller should apply it now, which it never does:
// a request waits for another administrator, or, made by the only one, for
// its delay (dual.SoloDelay), and the person is told which and how it is
// approved. The boolean stays so a caller's shape does not depend on who
// else administers the store.
//
// flag is the command's own option for the reason, named in the refusal a
// request made alone with none gets: the next reader of the log has only
// the reason to go on, with nobody else's approval beside it.
func proposeSecond(root string, c *Caller, kind, what string, payload any, why, flag string) (bool, error) {
	alone := onlyAdministrator(root, c.Name)
	if alone && strings.TrimSpace(why) == "" {
		return false, fmt.Errorf("you are the only administrator, so a "+
			"change you make alone needs a reason: give one with %s", flag)
	}
	r, err := dualStore(root).Propose(kind, what, payload, why, c.Name, alone, time.Now())
	if err != nil {
		return false, err
	}
	detail := map[string]string{"request": r.ID, "kind": kind, "what": what}
	if why != "" {
		detail["why"] = why
	}
	if alone {
		detail["alone"] = "true"
		detail["not_before"] = r.NotBefore.UTC().Format(time.RFC3339)
	}
	if err := recordE(root, c.auditRecord("dual.proposed", "/", audit.Success, detail)); err != nil {
		return false, err
	}
	if w.JSON(r) {
		return false, nil
	}
	if alone {
		w.Human("%syou are the only administrator%s, so %s waits until %s (request %s)\n",
			yellow, reset, what, r.NotBefore.UTC().Format("15:04 MST on 2 Jan"), r.ID)
		w.Human("  %sthen approve it yourself on the People screen of the console, which asks for your passkey; until then any administrator's session can decline it%s\n",
			dim, reset)
		return false, nil
	}
	w.Human("%swaiting for a second administrator%s: %s (request %s)\n", yellow, reset, what, r.ID)
	w.Human("  %sanother administrator approves it with aertun pending approve %s%s\n", dim, r.ID, reset)
	return false, nil
}

// applyDual makes an approved change, as by. A token is not made here: the
// person who asked for it receives it (aertun pending redeem).
func applyDual(root string, r dual.Request, by string) error {
	switch r.Kind {
	case dual.Grant:
		var ch dual.GrantChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		_, err := updatePolicy(root, func(p *auth.Policy) error {
			for _, b := range ch.Bindings {
				if err := p.Grant(b); err != nil {
					return err
				}
			}
			return nil
		})
		return err
	case dual.Setting:
		var ch dual.SettingChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		c, err := loadConfig(root)
		if err != nil {
			return err
		}
		if err := c.Set(ch.Key, ch.Value, ch.Reason, r.By); err != nil {
			return err
		}
		return saveConfig(root, c)
	case dual.AuditLog:
		var ch dual.AuditLogChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		// Written to the old log before the pointer moves, so the change is
		// in the record that was being kept at the time.
		record(root, resolveCaller(root, "").auditRecord("auditlog.dir", "/", audit.Success,
			map[string]string{"from": auditDir(root), "to": ch.Dir, "request": r.ID, "approved_by": by}))
		return setAuditDir(root, ch.Dir)
	case dual.Owner:
		var ch dual.OwnerChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		return applyOwner(root, r, ch)
	case dual.Token:
		return nil
	case dual.Signer:
		return applySigner(root, r)
	}
	return fmt.Errorf("request %s is a %q, which this version does not know how to apply", r.ID, r.Kind)
}

// cmdPending is `aertun pending [list] | approve ID | decline ID |
// withdraw ID | redeem ID`.
func cmdPending(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	store := dualStore(root)
	c := resolveCaller(root, "")
	now := time.Now()
	if args[0] == "list" {
		pend, err := store.Pending(now)
		if err != nil {
			return err
		}
		if w.JSON(pend) {
			return nil
		}
		if len(pend) == 0 {
			w.Human("nothing is waiting for a second administrator\n")
			return nil
		}
		for _, r := range pend {
			w.Human("%s%s%s  %s\n  %sby %s at %s; %s%s\n", bold, r.ID, reset, r.What, dim, r.By,
				r.At.UTC().Format("15:04 2 Jan"), dual.StateWords(r, now), reset)
			if r.Why != "" {
				w.Human("  %swhy: %s%s\n", dim, r.Why, reset)
			}
		}
		return nil
	}
	if len(args) != 2 {
		return errors.New("usage: aertun pending [list] | approve ID | decline ID | withdraw ID | redeem ID")
	}
	id := args[1]
	switch args[0] {
	case "approve", "decline":
		approve := args[0] == "approve"
		if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
			return err
		}
		// An agent may ask for a privileged change; a person approves one.
		// Acting for the only administrator, an agent would otherwise wait
		// out the delay and approve its own request in their name.
		// Declining stays open to it: stopping a change is never the risk.
		if approve && c.Kind == audit.KindAI {
			return errors.New("a privileged change is approved by a person, never by an agent")
		}
		// A request approved by whoever made it has nobody else's
		// approval beside it, so it needs the person: a passkey sign-in
		// within dual.OwnProof. A command-line token is not one; the
		// console asks for the passkey.
		if approve {
			if mine, gerr := store.Get(id); gerr == nil && strings.EqualFold(mine.By, c.Name) &&
				!c.Proof.ProvedWithin(auth.MethodPasskey, now, dual.OwnProof) {
				return fmt.Errorf("request %s is your own, so approving it needs a passkey "+
					"sign-in from the last %d minutes, and a command-line token is not "+
					"one: approve it on the People screen of the console (aertun serve), "+
					"which asks for your passkey", id, int(dual.OwnProof/time.Minute))
			}
		}
		r, err := store.Decide(id, c.Name, approve, onlyAdministrator(root, c.Name), now)
		if err != nil {
			return err
		}
		if approve {
			if err := applyDual(root, r, c.Name); err != nil {
				return fmt.Errorf("approved, and applying it failed: %w", err)
			}
		}
		detail := map[string]string{"request": r.ID, "kind": r.Kind, "what": r.What, "proposed_by": r.By}
		if r.Alone {
			detail["alone"] = "true"
		}
		if err := recordE(root, c.auditRecord(map[bool]string{true: "dual.approved", false: "dual.declined"}[approve],
			"/", audit.Success, detail)); err != nil {
			return err
		}
		if w.JSON(r) {
			return nil
		}
		w.Human("%s: %s\n", dual.StateWords(r, now), r.What)
		if approve && r.Kind == dual.Token {
			w.Human("  %s%s receives it with aertun pending redeem %s, within a day%s\n", dim, r.By, r.ID, reset)
		}
		return nil
	case "withdraw":
		r, err := store.Withdraw(id, c.Name, now)
		if err != nil {
			return err
		}
		w.Human("withdrawn: %s\n", r.What)
		return recordE(root, c.auditRecord("dual.withdrawn", "/", audit.Success,
			map[string]string{"request": r.ID, "kind": r.Kind}))
	case "redeem":
		r, err := store.Get(id)
		if err != nil {
			return err
		}
		if r.Kind != dual.Token {
			return fmt.Errorf("request %s is not a token: an approved %s is already done", r.ID, r.Kind)
		}
		var ch dual.TokenChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		if _, err := store.Redeem(id, c.Name, now); err != nil {
			return err
		}
		if err := recordE(root, c.auditRecord("dual.redeemed", "/", audit.Success,
			map[string]string{"request": r.ID, "approved_by": r.DecidedBy})); err != nil {
			return err
		}
		return tokenIssueAs(root, ch.Args, true)
	}
	return errors.New("usage: aertun pending [list] | approve ID | decline ID | withdraw ID | redeem ID")
}
