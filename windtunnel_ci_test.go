// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// The CI job that signs the wind tunnel's scorecard keeps its promises.
//
// The command refuses to sign outside CI (cmd/aertun's tests hold that);
// this holds the workflow side, which no Go test executes: the signing key
// reaches only the one step, only on a push to main — never a pull
// request's unmerged code — and its absence is a skip the log states, not
// a failure, while its presence ends in an offline verification against
// the public key committed on main. A workflow edit that widened the
// secret or dropped the verification would otherwise read as a one-line
// diff and pass.
func TestTheWindtunnelJobSignsOnlyOnMainAndVerifiesOffline(t *testing.T) {
	ci := read(t, ".github/workflows/ci.yml")
	start := strings.Index(ci, "\n  windtunnel:\n")
	if start < 0 {
		t.Fatal("ci.yml has no windtunnel job; the scorecard is signed " +
			"nowhere")
	}
	job := ci[start:]
	if n := strings.Count(ci, "secrets.SCORECARD_SIGNING_KEY"); n != 1 {
		t.Fatalf("ci.yml names the signing secret %d times; one step, in "+
			"one job, is the only place it belongs", n)
	}
	for _, want := range []string{
		// The gate: the secret is empty unless this is a push to main.
		"github.event_name == 'push' && github.ref == 'refs/heads/main' && " +
			"secrets.SCORECARD_SIGNING_KEY || ''",
		// Absent key: skipped, and said so, and the run still happens.
		`if [ -z "$KEY" ]; then`,
		"signing skipped:",
		"exit 0",
		// Present key: written private, used, removed.
		"umask 077",
		`--key "$RUNNER_TEMP/windtunnel/signing.key"`,
		`rm -f "$RUNNER_TEMP/windtunnel/signing.key"`,
		// And verified the way a stranger verifies: the committed key.
		"windtunnel verify --key scorecards/public-key.json",
	} {
		if !strings.Contains(job, want) {
			t.Errorf("the windtunnel job never says %q", want)
		}
	}
}
