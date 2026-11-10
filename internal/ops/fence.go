// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ops

import (
	"strings"

	"github.com/aertun/aertun/internal/untrusted"
)

// Fence keeps untrusted text on one line and unable to close its fence.
//
// Clean runs before the fence tokens are replaced, in that order because
// Clean folds the imitators — ＜＜＜, «««, ‹‹‹ — to the ASCII they imitate,
// so a folded lookalike becomes a literal "<<<" and is then replaced like
// any other. The other order would leave a ‹‹‹ that had been cleaned into
// a fence the replacement never looked for. The invisible characters go
// first for the same reason: "<<" + a zero-width space + "<" is three
// runes to the eye and four to the bytes, and only the bytes were being
// checked.
func Fence(s string) string {
	s = untrusted.Clean(s)
	s = strings.ReplaceAll(s, "<<<", "‹‹‹")
	s = strings.ReplaceAll(s, ">>>", "›››")
	s = strings.Join(strings.Fields(s), " ")
	return untrusted.Truncate(s, 2000)
}
