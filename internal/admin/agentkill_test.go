// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/agentreg"
	"github.com/aertun/aertun/internal/auth"
)

// The console's kill switch: a viewer cannot pull it, a reason is required,
// and the switch the command line pulls is pulled, as the person signed in.
func TestTheConsoleKillSwitchTakesAResponderAndAReason(t *testing.T) {
	srv, editor := setup(t)
	var got struct{ name, why, by string }
	srv.KillAgent = func(name, why, by string) (int, error) {
		got.name, got.why, got.by = name, why, by
		return 2, nil
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "vic", Role: auth.RoleViewer, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	viewer, _, err := srv.Tokens.IssueSession("v", "vic", auth.RoleViewer, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"name": {"watcher"}, "why": {"it began deleting findings"}}.Encode()
	if w := postForm(t, srv, "/security/agents/kill", viewer, form); w.Code != http.StatusForbidden {
		t.Fatalf("a viewer pulled the kill switch: %d", w.Code)
	}
	if got.name != "" {
		t.Fatal("the switch was pulled for a viewer")
	}
	w := postForm(t, srv, "/security/agents/kill", editor, url.Values{"name": {"watcher"}}.Encode())
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "takes a reason") || got.name != "" {
		t.Fatalf("no reason: %s, pulled for %q", loc, got.name)
	}
	w = postForm(t, srv, "/security/agents/kill", editor, form)
	loc, _ := url.QueryUnescape(w.Header().Get("Location"))
	if got.name != "watcher" || got.why != "it began deleting findings" || got.by != "editor" {
		t.Fatalf("the switch was pulled as %+v", got)
	}
	if !strings.Contains(loc, "watcher is disabled, and 2 of its token(s) revoked") {
		t.Errorf("the answer: %s", loc)
	}
}

// The registry page lists an agent no event has named — the board, by
// design, gives it no row — with its kill switch for a responder; an
// analyst reads the registry and is offered no switch; the registry's free
// text is escaped.
func TestTheRegistryPageListsASilentAgentWithItsSwitch(t *testing.T) {
	withRegistry(t, func(st agentreg.Store) {
		addAgent(t, st, agentreg.Agent{Name: "night-watcher", Owner: "Ana",
			Note: `reads the queue <b>overnight</b>`, Allow: []string{"aertun_read"}, CreatedBy: "dana"})
	})
	srv, editor := setup(t)
	srv.KillAgent = func(string, string, string) (int, error) { return 0, nil }
	page := get(t, srv, "/security/agents/registry", editor).Body.String()
	for _, want := range []string{"<code>night-watcher</code>", `action="/security/agents/kill"`,
		"Disable and revoke its tokens", "active"} {
		if !strings.Contains(page, want) {
			t.Errorf("the registry page does not show %q", want)
		}
	}
	if strings.Contains(page, "<b>overnight</b>") {
		t.Error("the registry's note reached the page unescaped")
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "ana", Role: auth.RoleAnalyst, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	analyst, _, err := srv.Tokens.IssueSession("a", "ana", auth.RoleAnalyst, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	page = get(t, srv, "/security/agents/registry", analyst).Body.String()
	if !strings.Contains(page, "<code>night-watcher</code>") || strings.Contains(page, `action="/security/agents/kill"`) {
		t.Error("an analyst was not shown the registry, or was offered the kill switch")
	}
}
