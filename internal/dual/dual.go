// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package dual keeps the privileged changes that wait for a second
// administrator (NIST SP 800-53 AC-5, CM-5(4) and AU-9(5): dual
// authorisation).
//
// Making somebody an administrator, issuing an administrator's token,
// weakening a setting, lowering how many approvals a change needs and
// moving the audit log are each something one person, or whoever has their
// session, could do to take a store over or to hide that they had. So one
// administrator proposes and another approves, and the request records
// both.
//
// A store with one administrator is not left unable to change anything,
// and is not left open to whoever holds that administrator's session
// either. Their own request waits — an hour, a day to move the audit log —
// announced in the audit log, where the self-watch rules raise it at once;
// anybody with a session may decline it while it waits, and declining
// always wins. Only after the delay may they approve it themselves, and
// the record says it was approved alone. A stolen session can start a
// takeover; it cannot finish one before somebody has had the chance to
// notice. This is the solo half of NIST SP 800-53 AC-5: separation of
// duties held in time when it cannot be held between people.
//
// The store keeps the request, not the change: what applying a request
// does is its caller's, by kind, because the changes live in different
// parts of the program.
package dual

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/config"
)

// The kinds of change that wait.
const (
	// Grant is a binding that makes somebody an administrator of
	// something.
	Grant = "grant"
	// Token is an administrator's token, issued to whoever asked once
	// another administrator agrees.
	Token = "token"
	// Setting is a setting weakened.
	Setting = "setting"
	// AuditLog is the audit log moved to another directory.
	AuditLog = "auditlog"
	// Owner is the store's ownership passed to somebody (auth.Policy's
	// Owner). Only whoever asked approves it, and only a day after asking:
	// it is the one change that cannot be undone by the person it is
	// taken from.
	Owner = "owner"
	// Signer is a key trusted to sign proofs in this store's name
	// (internal/proofstore): every proof it signs is shown as trusted.
	Signer = "signer"
)

// SignerChange is a Signer request: the name, the public key document and
// why it is to be trusted.
type SignerChange struct {
	Name string          `json:"name"`
	Key  json.RawMessage `json:"public_key"`
	Why  string          `json:"why"`
}

// OwnerChange names who is to be the Owner.
type OwnerChange struct {
	To string `json:"to"`
}

// GrantChange is a Grant request: bindings granted together.
type GrantChange struct {
	Bindings []auth.Binding `json:"bindings"`
}

// TokenChange is a Token request: the command that issues it, run again
// for whoever asked once it is approved.
type TokenChange struct {
	Args []string `json:"args"`
}

// SettingChange is a Setting request.
type SettingChange struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Reason string `json:"reason,omitempty"`
}

// AuditLogChange is an AuditLog request: the directory the log moves to.
type AuditLogChange struct {
	Dir string `json:"dir"`
}

// Privileged reports whether bindings make somebody an administrator of
// anything, which is what a Grant request is for.
func Privileged(bindings []auth.Binding) bool {
	for _, b := range bindings {
		if !b.Deny && b.Role == auth.RoleAdmin {
			return true
		}
	}
	return false
}

// SettingNeedsSecond says why a setting's new value waits for a second
// administrator: weaker than the default (c is the configuration as it
// stands).
func SettingNeedsSecond(c *config.Config, key, value string) (bool, string) {
	if s, ok := config.Lookup(key); ok {
		if weaker, why := s.IsWeaker(value); weaker {
			return true, why
		}
	}
	return false, ""
}

// Wait is how long a request waits for a decision, and Redeem how long an
// approved token may wait to be issued to whoever asked for it.
const (
	Wait   = 7 * 24 * time.Hour
	Redeem = 24 * time.Hour
)

// SoloDelay is how long a request must wait before the administrator who
// made it may approve it alone. An hour is long enough for an alert to
// reach somebody and short enough not to stop an owner working; moving the
// audit log — the change that hides every other change — waits a day.
func SoloDelay(kind string) time.Duration {
	if kind == AuditLog || kind == Owner {
		return 24 * time.Hour
	}
	return time.Hour
}

// OwnProof is how recently a person approving their own request must have
// signed in with their passkey. Their own approval is the only one such a
// request gets — the only administrator's after its delay, the Owner's
// confirming a transfer — so it must come from the person, not from a
// session somebody may have taken an hour ago.
const OwnProof = 5 * time.Minute

// The states a request is in.
const (
	Waiting   = "waiting"
	Approved  = "approved"
	Declined  = "declined"
	Withdrawn = "withdrawn"
	Done      = "done"
)

// Request is one privileged change and who decided it.
type Request struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// What is the change in words, for the person deciding.
	What string `json:"what"`
	// Payload is the change itself, as its kind's caller reads it.
	Payload json.RawMessage `json:"payload"`
	Why     string          `json:"why,omitempty"`
	By      string          `json:"by"`
	At      time.Time       `json:"at"`
	State   string          `json:"state"`
	// DecidedBy decided it and Alone says they were the only
	// administrator, deciding their own request.
	DecidedBy string    `json:"decided_by,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
	Alone     bool      `json:"alone,omitempty"`
	// NotBefore is set on a request made by the only administrator: the
	// moment from which they may approve it themselves.
	NotBefore time.Time `json:"not_before,omitzero"`
}

// AloneFrom is when the proposer may approve this request without a
// second administrator: NotBefore when it was made alone, and otherwise
// the same delay counted from when it was made, for a request whose other
// administrators have since gone.
func (r Request) AloneFrom() time.Time {
	if !r.NotBefore.IsZero() {
		return r.NotBefore
	}
	return r.At.Add(SoloDelay(r.Kind))
}

// Open reports whether a request still waits for a decision at now.
func (r Request) Open(now time.Time) bool {
	return r.State == Waiting && now.Before(r.At.Add(Wait))
}

// Redeemable reports whether an approved token may still be issued.
func (r Request) Redeemable(now time.Time) bool {
	return r.State == Approved && now.Before(r.DecidedAt.Add(Redeem))
}

type file struct {
	Requests []Request `json:"requests"`
}

// Store is the requests, in one file.
type Store struct {
	Path string
}

// ErrNoRequest is an id that names no request.
var ErrNoRequest = errors.New("there is no such request")

// MaxWhy is the longest reason a request carries, in characters: a
// sentence or three for whoever approves it and whoever reads the log.
const MaxWhy = 500

// Propose records a request. alone says the proposer is the only
// administrator, so the request carries the moment from which they may
// approve it themselves (SoloDelay).
func (s Store) Propose(kind, what string, payload any, why, by string, alone bool, now time.Time) (Request, error) {
	if strings.TrimSpace(by) == "" {
		return Request{}, errors.New("a request is somebody's: nobody was named")
	}
	if n := utf8.RuneCountInString(why); n > MaxWhy {
		return Request{}, fmt.Errorf("the reason is %d characters; a request carries at most %d", n, MaxWhy)
	}
	if strings.ContainsFunc(why, unicode.IsControl) {
		return Request{}, errors.New("the reason is one line of text, with no control characters")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Request{}, err
	}
	id := make([]byte, 4)
	if _, err := rand.Read(id); err != nil {
		return Request{}, err
	}
	r := Request{ID: hex.EncodeToString(id), Kind: kind, What: what, Payload: raw,
		Why: strings.TrimSpace(why), By: by, At: now.UTC(), State: Waiting}
	if alone || kind == Owner {
		r.NotBefore = now.UTC().Add(SoloDelay(kind))
	}
	err = atomicfile.Update(s.Path, func(f *file) error {
		f.Requests = append(prune(f.Requests, now), r)
		return nil
	})
	return r, err
}

// Decide approves or declines a waiting request. Anybody may decline one.
// Nobody approves their own, unless alone says they are the only
// administrator and the request's delay has passed (AloneFrom). An
// approved token waits for whoever asked to redeem it; anything else
// approved is done, for the approver to apply.
func (s Store) Decide(id, by string, approve, alone bool, now time.Time) (Request, error) {
	var out Request
	err := atomicfile.Update(s.Path, func(f *file) error {
		r := find(f.Requests, id)
		if r == nil {
			return ErrNoRequest
		}
		if !r.Open(now) {
			return fmt.Errorf("request %s is %s, not waiting", r.ID, stateWords(*r, now))
		}
		if approve && r.Kind == Owner {
			// Ownership is confirmed by whoever asked for it to move — the
			// Owner, or on a store with none the administrator claiming
			// it — after the day's wait. Nobody else can make it happen;
			// anybody can stop it.
			if !strings.EqualFold(r.By, by) {
				return fmt.Errorf("request %s moves the store's ownership: %s, "+
					"who asked, confirms it; anybody may decline it", r.ID, r.By)
			}
			if from := r.AloneFrom(); now.Before(from) {
				return fmt.Errorf("request %s moves the store's ownership and may be "+
					"confirmed from %s; until then it can only be declined",
					r.ID, from.UTC().Format("15:04 MST on 2 Jan"))
			}
		} else if approve && strings.EqualFold(r.By, by) {
			if !alone {
				return fmt.Errorf("request %s is yours: another administrator approves it", r.ID)
			}
			if from := r.AloneFrom(); now.Before(from) {
				return fmt.Errorf("request %s is yours and you are the only administrator: "+
					"you may approve it from %s, and until then it can only be declined",
					r.ID, from.UTC().Format("15:04 MST on 2 Jan"))
			}
		}
		r.DecidedBy, r.DecidedAt = by, now.UTC()
		r.Alone = alone && strings.EqualFold(r.By, by)
		switch {
		case !approve:
			r.State = Declined
		case r.Kind == Token:
			r.State = Approved
		default:
			r.State = Done
		}
		out = *r
		return nil
	})
	return out, err
}

// Withdraw takes back a request its proposer no longer wants.
func (s Store) Withdraw(id, by string, now time.Time) (Request, error) {
	var out Request
	err := atomicfile.Update(s.Path, func(f *file) error {
		r := find(f.Requests, id)
		if r == nil {
			return ErrNoRequest
		}
		if !strings.EqualFold(r.By, by) {
			return fmt.Errorf("request %s is %s's to withdraw", r.ID, r.By)
		}
		if !r.Open(now) && !r.Redeemable(now) {
			return fmt.Errorf("request %s is %s", r.ID, stateWords(*r, now))
		}
		r.State = Withdrawn
		out = *r
		return nil
	})
	return out, err
}

// Redeem uses an approved token request, once, for whoever made it.
func (s Store) Redeem(id, by string, now time.Time) (Request, error) {
	var out Request
	err := atomicfile.Update(s.Path, func(f *file) error {
		r := find(f.Requests, id)
		if r == nil || r.Kind != Token {
			return ErrNoRequest
		}
		if !strings.EqualFold(r.By, by) {
			return fmt.Errorf("request %s was %s's: only they receive the token", r.ID, r.By)
		}
		if !r.Redeemable(now) {
			return fmt.Errorf("request %s is %s", r.ID, stateWords(*r, now))
		}
		r.State = Done
		out = *r
		return nil
	})
	return out, err
}

// Get is one request.
func (s Store) Get(id string) (Request, error) {
	var out Request
	err := atomicfile.Update(s.Path, func(f *file) error {
		r := find(f.Requests, id)
		if r == nil {
			return ErrNoRequest
		}
		out = *r
		return atomicfile.ErrUnchanged
	})
	return out, err
}

// Pending are the requests still waiting, and the approved tokens still
// waiting to be issued, oldest first.
func (s Store) Pending(now time.Time) ([]Request, error) {
	var out []Request
	err := atomicfile.Update(s.Path, func(f *file) error {
		for _, r := range f.Requests {
			if r.Open(now) || r.Redeemable(now) {
				out = append(out, r)
			}
		}
		return atomicfile.ErrUnchanged
	})
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, err
}

// StateWords is a request's state as a person reads it.
func StateWords(r Request, now time.Time) string { return stateWords(r, now) }

func stateWords(r Request, now time.Time) string {
	switch {
	case r.State == Waiting && !r.Open(now):
		return "expired"
	case r.State == Waiting && !r.NotBefore.IsZero() && now.Before(r.NotBefore):
		return "waiting until " + r.NotBefore.UTC().Format("15:04 MST on 2 Jan") +
			", when " + r.By + " may approve it alone; it can be declined before then"
	case r.State == Approved && !r.Redeemable(now):
		return "approved and never used"
	case r.State == Approved:
		return "approved, waiting for " + r.By + " to receive it"
	case r.State == Done && r.Alone:
		return "approved alone by " + r.DecidedBy
	case r.State == Done:
		return "approved by " + r.DecidedBy
	}
	return r.State
}

func find(rs []Request, id string) *Request {
	id = strings.TrimSpace(id)
	for i := range rs {
		if rs[i].ID == id {
			return &rs[i]
		}
	}
	return nil
}

// prune keeps the record of decisions for a year, so the file does not
// grow without end; the audit log keeps them for ever.
func prune(rs []Request, now time.Time) []Request {
	kept := rs[:0]
	for _, r := range rs {
		if now.Sub(r.At) < 365*24*time.Hour {
			kept = append(kept, r)
		}
	}
	return kept
}
