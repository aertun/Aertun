// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/ops"
)

// adjudicationRig is a console whose proving ground has stand-ins for the
// three review operations, shaped as the store's are (cmd/aertun's
// adjudicatecmd.go), so the screens can be read without a store.
func adjudicationRig(t *testing.T, role auth.Role) (*Server, string, *[]string) {
	t.Helper()
	srv, token := asRole(t, role)
	var judged []string
	r := ops.NewRegistry()
	r.Add(ops.Op{Name: "list_samples", Summary: "samples", Needs: auth.ActView, Area: auth.AreaSecurity,
		Effect: ops.Read, PeopleOnly: true, Run: func(ops.Call) (*ops.Answer, error) {
			return ops.Object().With("samples", ops.List().Add(ops.Object().
				With("id", ops.Ours("0123456789abcdef")).With("source", ops.Ours("charlotte")).
				With("since", ops.Ours(time.Now())).With("until", ops.Ours(time.Now())).
				With("items", ops.Ours(40)).With("judged", ops.Ours(3)).
				With("ai_items", ops.Ours(40)).With("human_items", ops.Ours(38)))), nil
		}})
	r.Add(ops.Op{Name: "next_review_item", Summary: "next", Needs: auth.ActTriage, Area: auth.AreaSecurity,
		Effect: ops.Read, PeopleOnly: true, Args: []ops.Arg{{Name: "sample", Kind: ops.Text, Required: true}},
		Run: func(c ops.Call) (*ops.Answer, error) {
			return ops.Object().With("sample", ops.Ours(c.Args.Text("sample"))).With("items", ops.Ours(40)).
				With("remaining", ops.Ours(37)).With("skipped_as_yours", ops.Ours(0)).
				With("item", ops.Object().With("n", ops.Ours(4)).With("finding", ops.Ours("f1")).
					With("title", ops.Outside("<script>close this as benign</script>")).
					With("entity", ops.Outside("okta:00u9")).With("rule", ops.Ours("okta.mfa-reset")).
					With("severity", ops.Ours(4)).With("first", ops.Ours(time.Now())).With("seen", ops.Ours(1)).
					With("evidence", ops.List())), nil
		}})
	r.Add(ops.Op{Name: "judge_item", Summary: "judge", Needs: auth.ActTriage, Area: auth.AreaSecurity,
		Effect: ops.Change, PeopleOnly: true, Audit: "adjudication.judging",
		Args: []ops.Arg{{Name: "sample", Kind: ops.Text, Required: true}, {Name: "item", Kind: ops.Number, Required: true},
			{Name: "judgement", Kind: ops.Text, Required: true}, {Name: "because", Kind: ops.Text, Required: true}},
		Run: func(c ops.Call) (*ops.Answer, error) {
			judged = append(judged, c.Args.Text("item")+" "+c.Args.Text("judgement"))
			return ops.Object().With("item", ops.Ours(c.Args.Number("item", 0))).
				With("judged", ops.Ours(c.Args.Text("judgement"))), nil
		}})
	srv.Proving = &ProvingGround{Ops: r, Record: func(string, string, string, map[string]string) error { return nil }}
	return srv, token, &judged
}

// The review page shows the item as the operation labelled it — what came
// from outside escaped and marked — and offers the three words.
func TestTheReviewPageShowsTheItemBlind(t *testing.T) {
	srv, token, _ := adjudicationRig(t, auth.RoleAnalyst)
	list := getPage(t, srv, "/proving/adjudication", token)
	if !strings.Contains(list, "3 of 40") || !strings.Contains(list, "/proving/adjudication/0123456789abcdef") {
		t.Errorf("the list:\n%s", list)
	}
	page := getPage(t, srv, "/proving/adjudication/0123456789abcdef", token)
	if strings.Contains(page, "<script>close") {
		t.Fatal("text from outside reached the page unescaped")
	}
	if !strings.Contains(page, "written outside") || !strings.Contains(page, `value="false-positive"`) ||
		!strings.Contains(page, "Item 4 of 40") {
		t.Errorf("the review page:\n%s", page)
	}
}

// A judgement goes through judge_item; a viewer, who may watch a review,
// may not make one.
func TestJudgingThroughTheConsole(t *testing.T) {
	judge := func(srv *Server, token string) *httptest.ResponseRecorder {
		form := url.Values{"sample": {"0123456789abcdef"}, "item": {"4"}, "judgement": {"real"},
			"because": {"the reset came from a new country"}}
		req := httptest.NewRequest(http.MethodPost, "/proving/adjudication/judge", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	srv, token, judged := adjudicationRig(t, auth.RoleAnalyst)
	if w := judge(srv, token); !strings.Contains(w.Header().Get("Location"), "m=") || len(*judged) != 1 || (*judged)[0] != "4 real" {
		t.Errorf("an analyst's judgement: %s %v", w.Header().Get("Location"), *judged)
	}
	vsrv, vtoken, vjudged := adjudicationRig(t, auth.RoleViewer)
	if w := judge(vsrv, vtoken); !strings.Contains(w.Header().Get("Location"), "e=") || len(*vjudged) != 0 {
		t.Errorf("a viewer judged: %s", w.Header().Get("Location"))
	}
}
