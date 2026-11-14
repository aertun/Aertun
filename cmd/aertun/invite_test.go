// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
)

// enrolLink is the one-time link a command printed.
var enrolLink = regexp.MustCompile(`https?://\S+/enrol/(\S+)`)

// Inviting a viewer grants the role and prints a link that works: the
// enrolment store takes the secret it carries, for that person.
func TestInvitingAViewerGrantsAndGivesAWorkingLink(t *testing.T) {
	root := ownedStore(t)
	buf := windtunnelOutput(t)
	asOnly(t, root, "dana")
	if err := cmdAuth(root, []string{"invite", "pat@acme.example", "viewer"}); err != nil {
		t.Fatal(err)
	}
	if p, _ := loadPolicy(root); !p.Evaluate("pat@acme.example", auth.ActView, "/").Allowed {
		t.Fatal("the invitation did not grant the role")
	}
	m := enrolLink.FindStringSubmatch(buf.String())
	if m == nil {
		t.Fatalf("no link was printed:\n%s", buf)
	}
	l, err := enrolStore(root).Peek(m[1], time.Now())
	if err != nil || l.Principal != "pat@acme.example" {
		t.Fatalf("the printed link does not open for pat: %+v %v", l, err)
	}
}

// Inviting an administrator: the grant waits for a second administrator,
// as any grant of administration does, and the link is still printed —
// with the plain statement that it reaches nothing until the grant is
// approved. Before, the waiting grant made the link refuse, and the
// invitation printed nothing a person could use.
func TestInvitingAnAdministratorWaitsAndStillGivesTheLink(t *testing.T) {
	root := ownedStore(t)
	buf := windtunnelOutput(t)
	asOnly(t, root, "dana")
	if err := cmdAuth(root, []string{"invite", "sam@acme.example", "admin",
		"--note", "sam takes over on-call"}); err != nil {
		t.Fatal(err)
	}
	if p, _ := loadPolicy(root); p.Evaluate("sam@acme.example", auth.ActGrant, "/").Allowed {
		t.Fatal("an administrator was made on one administrator's word")
	}
	if r := waiting(t, root); !strings.Contains(r.What, "sam@acme.example") {
		t.Fatalf("the waiting request: %+v", r)
	}
	out := buf.String()
	if !strings.Contains(out, "holds nothing until that request is approved") {
		t.Errorf("the invitation does not say the link reaches nothing yet:\n%s", out)
	}
	m := enrolLink.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no link was printed for a waiting administrator:\n%s", out)
	}
	if l, err := enrolStore(root).Peek(m[1], time.Now()); err != nil || l.Principal != "sam@acme.example" {
		t.Fatalf("the printed link does not open for sam: %+v %v", l, err)
	}
}

// A grant the invitation cannot make gives no link; a deny is not an
// invitation; and somebody who may not grant cannot invite.
func TestAnInvitationThatCannotGrantGivesNoLink(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"vic", "viewer"})
	asOnly(t, root, "dana")
	// The only administrator, with no reason: refused at the grant.
	if err := cmdAuth(root, []string{"invite", "sam@acme.example", "admin"}); err == nil {
		t.Fatal("an administrator's invitation without a reason was made alone")
	}
	if err := cmdAuth(root, []string{"invite", "sam@acme.example", "viewer", "--deny"}); err == nil {
		t.Fatal("a deny was taken for an invitation")
	}
	ts, _ := loadTokens(root)
	secret, _, _ := ts.Issue("vic", "vic", auth.RoleViewer, "/", time.Hour, auth.RoleAdmin)
	_ = saveJSON(tokensPath(root), ts)
	t.Setenv("AERTUN_TOKEN", secret)
	if err := cmdAuth(root, []string{"invite", "sam@acme.example", "viewer"}); err == nil {
		t.Fatal("a viewer invited somebody")
	}
	if links, _ := enrolStore(root).Waiting(time.Now()); len(links) != 0 {
		t.Fatalf("a refused invitation left a link: %+v", links)
	}
}

// stdoutOf runs fn and returns what it wrote to standard output: some
// commands print with fmt rather than through the writer a test swaps.
func stdoutOf(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wr
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stdout = old
	_ = wr.Close()
	return <-done
}

// A grant says what the person can do once it is made, read from the policy
// with the grant in it. It used to read the policy loaded before the grant,
// and told an operator that somebody just made an analyst "can now: nothing".
func TestAGrantSaysWhatThePersonCanNowDo(t *testing.T) {
	root := ownedStore(t)
	asOnly(t, root, "dana")
	out := stdoutOf(t, func() {
		if err := cmdAuth(root, []string{"grant", "ana@acme.example", "analyst"}); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "can now: view, triage on /") {
		t.Errorf("the grant's summary:\n%s", out)
	}
	out = stdoutOf(t, func() {
		if err := cmdAuth(root, []string{"deny", "ana@acme.example", "analyst"}); err != nil {
			t.Error(err)
		}
	})
	// The deny takes triage away and leaves what the grant's lower rungs
	// still give: the summary follows the policy, not the last word typed.
	if !strings.Contains(out, "can now: view on /") {
		t.Errorf("after a deny, the summary:\n%s", out)
	}
}
