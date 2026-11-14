// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
)

// Two factors for every person (SP 800-63B-4 AAL2): from when.
//
// An installation running before two factors became the rule is given a
// grace, so nobody already signing in with a token is locked out the day
// they upgrade: the first time this version starts, it writes down the end
// of the grace, and from then on that date is the one every part of the
// program reads. During it, a token alone still reaches the admin, with a
// notice on every page and a posture finding naming who has no passkey;
// after it, a token is a first factor only.

// mfaGrace is how long an installation has to give everyone a passkey.
const mfaGrace = 14 * 24 * time.Hour

type mfaState struct {
	// EnforcedFrom is when two factors became compulsory here.
	EnforcedFrom time.Time `json:"enforced_from"`
}

func mfaPath(root string) string { return filepath.Join(root, "mfa.json") }

// mfaFrom is when two factors are compulsory from, written down the first
// time it is asked for. A state file that cannot be read or written is
// answered with now: the grace is a courtesy, and losing it never opens
// anything.
func mfaFrom(root string, now time.Time) time.Time {
	var from time.Time
	err := atomicfile.Update(mfaPath(root), func(st *mfaState) error {
		if !st.EnforcedFrom.IsZero() {
			from = st.EnforcedFrom
			return atomicfile.ErrUnchanged
		}
		st.EnforcedFrom = now.UTC().Add(mfaGrace)
		from = st.EnforcedFrom
		return nil
	})
	if err != nil {
		return now
	}
	return from
}

// mfaFromIfSet is the date without writing one, for the commands that
// report it.
func mfaFromIfSet(root string) (time.Time, bool) {
	var st mfaState
	if err := loadJSON(mfaPath(root), &st); err != nil {
		return time.Time{}, false
	}
	return st.EnforcedFrom, !st.EnforcedFrom.IsZero()
}
