// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sort"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/estate"
	"github.com/aertun/aertun/internal/mcp"
)

// The estate, for an agent: in aggregate, and never by name.
//
// An agent asked "how is our security awareness going" needs the bands,
// the areas, the trend and what could not be checked. It does not need a
// list of who clicked, and a list of named employees and their failings
// inside a model's context is a copy of it in whatever that context is
// logged to. The individual findings stay behind list_findings, where each
// one is read on purpose; the people and their scores are not offered here
// at all.

// opEstateSummary is written once, for the agent interface and the context
// twin alike (mcptwin.go).
var opEstateSummary = mcp.Operation{
	Name: "estate_summary", NeedsRole: "admin", Area: auth.AreaSecurity,
	Summary: "how many people are at each level of risk, where, and what " +
		"could not be checked — numbers only, no names",
	Detail: "Built from the company's tools as last read: bands, the " +
		"areas the risk is in, the trend by day, which tools were read " +
		"and when, and which cross-tool checks could not run and why. " +
		"No person is named; the findings the checks raised are in " +
		"list_findings.",
	Keywords: []string{"workforce", "risk", "estate", "training",
		"phishing", "devices", "compliance", "people"},
}

func registerEstateOps(srv *mcp.Server, root string, caller *Caller) {
	srv.Register(opEstateSummary, func(map[string]any) (any, error) {
		f, err := gatherEstateSummary(root, caller, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		return answerEstateSummary(f).plain()
	})
}

// estateFacts is what estate_summary answers from: the numbers, worked out
// at the instant they were gathered. The estate itself, which names
// people, is never kept — only the counts the answer shows.
type estateFacts struct {
	Scored    int                 `json:"scored"`
	Mean      float64             `json:"mean"`
	Bands     map[estate.Band]int `json:"bands"`
	Areas     map[estate.Area]int `json:"areas"`
	Leavers   int                 `json:"leavers_with_live_devices"`
	People    int                 `json:"people"`
	Joined    int                 `json:"people_in_two_or_more_tools"`
	Machines  int                 `json:"machines"`
	ByCheck   map[string]int      `json:"findings_by_check"`
	Skipped   map[string]string   `json:"checks_not_run"`
	Tools     []estateTool        `json:"tools"`
	TrendRead bool                `json:"trend_read"`
	Trend     []estateDay         `json:"trend"`
}

// estateTool is one tool the estate was read from.
type estateTool struct {
	Name     string `json:"name"`
	ReadAt   string `json:"read_at"`
	Complete bool   `json:"complete"`
}

// estateDay is one day of the trend.
type estateDay struct {
	Date   string  `json:"date"`
	Mean   float64 `json:"mean"`
	AtRisk int     `json:"high_or_critical"`
}

// gatherEstateSummary reads the estate for estate_summary. It is an
// administrator's read — a person's score is a file on an employee — and
// is gated here with the policy alone, as it always was: the tool
// allowlist governs reaches narrower than an administrator's.
func gatherEstateSummary(root string, caller *Caller, now time.Time) (estateFacts, error) {
	if err := authorise(root, caller, auth.ActGrant, auth.AreaSecurity); err != nil {
		return estateFacts{}, &mcp.Refusal{Reason: err.Error()}
	}
	e, o, err := buildEstate(root, now)
	if err != nil {
		return estateFacts{}, err
	}
	sum := estate.Summarise(e.Scores(now), now)
	f := estateFacts{Scored: sum.Scored, Mean: sum.Mean, Bands: sum.Bands,
		Areas: sum.Areas, Leavers: sum.Leavers, People: len(e.People),
		Machines: len(e.Machines), ByCheck: map[string]int{}, Skipped: o.Skipped}
	for _, fd := range o.Findings {
		f.ByCheck[fd.Source]++
	}
	for name, snap := range e.Sources {
		complete := true
		for _, info := range snap.Endpoints {
			complete = complete && info.Complete
		}
		f.Tools = append(f.Tools, estateTool{Name: name,
			ReadAt: snap.At.Format(time.RFC3339), Complete: complete})
	}
	sort.Slice(f.Tools, func(i, j int) bool { return f.Tools[i].Name < f.Tools[j].Name })
	for _, p := range e.People {
		if len(p.Sources) > 1 {
			f.Joined++
		}
	}
	if hist, herr := loadHistory(root); herr == nil {
		f.TrendRead = true
		if len(hist) > 30 {
			hist = hist[len(hist)-30:]
		}
		for _, d := range hist {
			f.Trend = append(f.Trend, estateDay{Date: d.Date, Mean: d.Mean,
				AtRisk: d.Bands[estate.BandHigh] + d.Bands[estate.BandCritical]})
		}
	}
	return f, nil
}

// answerEstateSummary is estate_summary's answer. Every value in it is
// ours: counts, bands and areas from closed sets, the names of the checks
// and of the tools the operator connected, and times.
func answerEstateSummary(f estateFacts) *answer {
	count := func(n int) *answer { return ours(n) }
	a := object().
		with("areas", byKey(f.Areas, count)).
		with("bands", byKey(f.Bands, count)).
		with("checks_not_run", byKey(f.Skipped, oursText)).
		with("findings_by_check", byKey(f.ByCheck, count)).
		with("leavers_with_live_devices", ours(f.Leavers)).
		with("machines", ours(f.Machines)).
		with("mean", ours(f.Mean)).
		with("people", ours(f.People)).
		with("people_in_two_or_more_tools", ours(f.Joined)).
		with("scored", ours(f.Scored)).
		with("tools", listOf(f.Tools, func(t estateTool) *answer {
			return object().with("name", ours(t.Name)).
				with("read_at", ours(t.ReadAt)).with("complete", ours(t.Complete))
		}))
	if f.TrendRead {
		a.with("trend", listOf(f.Trend, func(d estateDay) *answer {
			return object().with("date", ours(d.Date)).with("mean", ours(d.Mean)).
				with("high_or_critical", ours(d.AtRisk))
		}))
	}
	return a
}
