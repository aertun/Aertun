// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"time"
)

// Claim cards: each vendor claim written down as a test before its data
// existed (`aertun claim register`), when it was registered, and when its
// window closes and it can be decided. The cards themselves are list_claims;
// the proofs testing them are on the Proofs screen.

type claimRow struct {
	Name, Source, Metric, Side, Threshold, Confidence, Ends, Broken, Entry string
	Closed                                                                 bool
}

func (s *Server) handleClaims(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.invokeOp(w, r, p, "list_claims", nil)
	if !ok {
		return
	}
	var rows []claimRow
	for _, it := range a.Get("claims").Items() {
		row := claimRow{Name: it.Get("name").Text()}
		if b := it.Get("broken"); b != nil {
			row.Broken = b.Text()
		}
		if it.Get("source") != nil {
			row.Source, row.Metric = it.Get("source").Text(), it.Get("metric").Text()
			row.Side = map[string]string{"at-least": "at least", "at-most": "at most"}[it.Get("direction").Text()]
			row.Threshold, row.Confidence = it.Get("threshold").Text(), it.Get("confidence").Text()
		}
		if e := it.Get("window_end"); e != nil {
			if t, ok := e.Value().(time.Time); ok {
				row.Ends = t.Format("2 Jan 2006 15:04")
			}
			row.Closed = it.Get("closed").Value() == true
			row.Entry = it.Get("registered_at_entry").Text()
		}
		rows = append(rows, row)
	}
	s.render(w, r, "claims.html", map[string]any{"Nav": "claims", "Title": "Claim cards",
		"Principal": p, "Rows": rows})
}
