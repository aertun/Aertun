// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Adjudication: closures judged again, blind, by a person.
//
// The screen lists the samples drawn (`aertun adjudicate draw`) and how far
// each review has got, and shows one item at a time to whoever reviews it:
// the finding as it was raised and its evidence, and nothing that says who
// closed it, how, what the product's AI said, or which of the two strata it
// came from — the operation (next_review_item) leaves all of that out, so
// there is nothing here to hide. A judgement is judge_item, which refuses an
// item already judged and an item its reviewer closed, and records the
// judgement in the audit log without touching the finding.

type sampleRow struct {
	ID, Source, Since, Until, Broken string
	Items, Judged, AI, Human         string
	Done                             bool
}

func (s *Server) handleAdjudication(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.invokeOp(w, r, p, "list_samples", nil)
	if !ok {
		return
	}
	var rows []sampleRow
	for _, it := range a.Get("samples").Items() {
		row := sampleRow{ID: it.Get("id").Text()}
		if b := it.Get("broken"); b != nil {
			row.Broken = b.Text()
			rows = append(rows, row)
			continue
		}
		row.Source, row.Items, row.Judged = it.Get("source").Text(), it.Get("items").Text(), it.Get("judged").Text()
		row.AI, row.Human = it.Get("ai_items").Text(), it.Get("human_items").Text()
		if t, ok := it.Get("since").Value().(time.Time); ok {
			row.Since = t.Format("2 Jan 2006")
		}
		if t, ok := it.Get("until").Value().(time.Time); ok {
			row.Until = t.Format("2 Jan 2006")
		}
		row.Done = row.Items == row.Judged
		rows = append(rows, row)
	}
	s.render(w, r, "adjudication.html", map[string]any{"Nav": "adjudication", "Title": "Adjudication",
		"Principal": p, "Rows": rows, "Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")})
}

func (s *Server) handleAdjudicationItem(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	id := strings.TrimPrefix(r.URL.Path, "/proving/adjudication/")
	a, ok := s.invokeOp(w, r, p, "next_review_item", map[string]string{"sample": id})
	if !ok {
		return
	}
	type evidence struct {
		At, From string
		What     fact
	}
	data := map[string]any{"Nav": "adjudication", "Title": "Review", "Principal": p,
		"Sample": a.Get("sample").Text(), "Items": a.Get("items").Text(),
		"Remaining": a.Get("remaining").Text(), "Skipped": a.Get("skipped_as_yours").Text(),
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if it := a.Get("item"); it != nil {
		var evs []evidence
		for _, e := range it.Get("evidence").Items() {
			ev := evidence{From: e.Get("from").Text(), What: factOf(e.Get("what"))}
			if t, ok := e.Get("at").Value().(time.Time); ok {
				ev.At = t.Format("2 Jan 2006 15:04:05 MST")
			}
			evs = append(evs, ev)
		}
		data["Item"] = map[string]any{"N": it.Get("n").Text(), "Title": factOf(it.Get("title")),
			"Entity": factOf(it.Get("entity")), "Rule": it.Get("rule").Text(),
			"Severity": it.Get("severity").Text(), "Seen": it.Get("seen").Text(), "Evidence": evs}
	}
	s.render(w, r, "review.html", data)
}

func (s *Server) handleAdjudicationJudge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	sample := r.FormValue("sample")
	back := "/proving/adjudication/" + url.PathEscape(sample)
	if s.Proving == nil || s.Proving.Ops == nil {
		http.Redirect(w, r, back+"?e="+url.QueryEscape("This build was started without the proving ground's operations."), http.StatusSeeOther)
		return
	}
	a, err := s.Proving.Ops.Invoke("judge_item", consoleCaller{s, p}, map[string]string{
		"sample": sample, "item": r.FormValue("item"), "judgement": r.FormValue("judgement"),
		"because": r.FormValue("because")}, time.Now().UTC())
	if err != nil {
		http.Redirect(w, r, back+"?e="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"?m="+url.QueryEscape("Item "+a.Get("item").Text()+" judged "+
		a.Get("judged").Text()+"."), http.StatusSeeOther)
}
