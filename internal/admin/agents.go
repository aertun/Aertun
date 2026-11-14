// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/agentreg"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// The Agents board: what the agents in this estate have been doing, from the
// two places aertun already hears them.
//
// Everything counted here is observed telemetry, read from the spool on
// request the way Events and Hunt read it: aertun/agent — the sidecar's tool
// calls and the analyst's proposals, with the agent as the actor under the
// audit log's pseudonym — and otel/genai — GenAI spans pushed over OTLP, with
// the agent identity the SDK set as the actor. A row exists because an event
// named it, and never otherwise.
//
// The two sources name agents differently, and the difference is kept rather
// than resolved. The actor key is one join; the registry (internal/agentreg)
// is the other, and it runs one way only. A row's own events carry clear
// names — the token's name in raw.client, which for a registered agent is
// agent:NAME, and sometimes an agent field — and where such a name names a
// registry entry, the row can say what the registry holds about it: the
// owner, the tools it may call, the status. Never the other way round: the
// registry cannot put a row on this board, because the board is what
// happened and the registry is what was declared. A registered agent no
// event has named is a fact the header states as a count, with the words
// that silence is not absence — not a row standing on events that do not
// exist. Guessing a join the events do not carry would put one agent's
// refusals on another agent's record, which is the one wrong answer a
// security screen must not give.
//
// An agent's page also groups its window into sessions: every otel/genai
// event that carried one trace id, laid out as a timeline a finding's
// evidence can cite. The trace id is the events' own edge and the only one
// grouped on — aertun/agent events carry no trace id, so they stay one
// chronological stream, said as that rather than fenced into sessions
// nobody observed the edges of. The one annotation the timelines add is
// arithmetic over the same window: a tool the agent had not used in it
// before is marked at its first use, an observation and never a verdict,
// and nothing is marked about the data itself, because no event here
// carries a sensitivity label to mark it with.
//
// Nothing here is written anywhere. It is a view, assembled per request
// inside the same byte budget the other spool screens hold themselves to.

// AgentRegistry is the registry of agents this organisation runs
// (internal/agentreg): who owns each agent, what it may call, whether it is
// still allowed to act. The host sets it when it starts the console beside
// the registry file; unset, it is a registry holding nobody, which is the
// same answer an absent registry file gives and the one the enforcement
// fails closed to.
var AgentRegistry agentreg.Store

const (
	// agentLookback is how far back the board counts. Seven days: long
	// enough for a weekly rhythm to show, short enough that the read stays
	// inside the budget on a busy store.
	agentLookback = 7 * 24 * time.Hour

	// agentSidecar is the sidecar's tool calls and the analyst's proposals,
	// with the agent as the actor under the audit log's pseudonym.
	agentSidecar = "aertun/agent"
	// agentOtel is GenAI telemetry pushed over OTLP, with the agent
	// identity the SDK set as the actor.
	agentOtel = "otel/genai"

	// agentTimeline is how many events one agent's page lists.
	agentTimeline = 50

	// agentToolsShown is how many tool names a row offers as chips before
	// pointing at the agent's page for the rest.
	agentToolsShown = 6
)

// agentSourceKey is the closed set of source filters the board accepts.
// Anything else in the address is read as no filter rather than evaluated as
// whatever was sent.
func agentSourceKey(q string) string {
	switch q {
	case "aertun":
		return "aertun"
	case "otel":
		return "otel"
	}
	return ""
}

// agentHref is an agent's page, under the actor key as stored.
func agentHref(id telemetry.ID) string {
	return "/security/agents/" + url.PathEscape(id.String())
}

// agentTool is one tool an agent called, and how much.
type agentTool struct {
	Name string
	N    int
	Last string
}

// agentRow is one observed agent: everything the window's events said about
// one actor key.
type agentRow struct {
	// Actor is the identity as stored — a pseudonym under aertun/agent, the
	// SDK's identifier under otel/genai — shown verbatim and never resolved
	// into a name nobody recorded.
	Actor telemetry.ID
	Key   string
	Href  string

	// First and Last are arrivals, on this program's clock: an agent whose
	// telemetry claims a time from the future is not the most recent thing
	// on the board for it.
	First, Last time.Time
	LastAgo     string

	// FromSidecar and FromOtel are how many of its events came from each
	// source, because which sources have seen an agent is a fact about the
	// observation, not a detail.
	FromSidecar, FromOtel int

	// Calls is the tool and model calls it made — the sidecar's and every
	// span. Refused is the blocked ones, the sidecar or a policy stopping
	// the call; Failed the ones that did not complete for reasons no
	// control chose. The analyst's proposals and abstentions are counted
	// separately, because they are the model's conduct rather than
	// something it asked to do.
	Calls, Refused, Failed int
	Proposals              int

	Tools      []agentTool
	ToolsShown []agentTool
	ToolsMore  int
	Models     []string

	TokensIn, TokensOut   int64
	TokensInS, TokensOutS string

	// Names is what the aertun/agent records called it (the event's own
	// agent field): a name the event carried, not one this page chose.
	Names []string

	// Matches is the registry entries this row's events named — the clear
	// names they carried (raw.client, raw.agent) matched against the
	// registry, never the registry matched against nothing. Empty means no
	// entry matches any name the agent used, which is shown as that fact
	// rather than as the agent's absence from the registry being meaningful.
	Matches []agentMatch

	// clear is the distinct clear names the row's events carried, kept for
	// the join and shown nowhere: a name nobody registered is a string an
	// event wrote, and strings events write are matched, not displayed.
	clear map[string]bool

	// MaybeSame names other actor keys that may be the same agent, because
	// an event under this key called itself by the other key's value. Said,
	// never merged.
	MaybeSame []string

	Status, StatusTone string
}

// agentMatch is one registry entry a row's events named. Everything on it is
// what the registry holds; the join contributed only the decision that this
// entry is the one to show.
type agentMatch struct {
	Name   string
	Owner  string
	Active bool
	// Word and Tone are the status as the board says it: "active", or
	// "disabled — refused since …", because a disabled agent's calls are
	// refused by the gates and the row it still appears on is the loudest
	// thing on the page.
	Word, Tone string
	// Since is the disable's changed-at as a person reads it, empty when the
	// registry carried no time.
	Since string
	// Allow is the registry's allowlist, its closed set of tool names.
	Allow []string
	// Note is what the registering admin put on record about why this agent
	// exists. Free text, operator-written: shown plainly and escaped, and
	// attributed like every other free field on these screens.
	Note string
	// Why is the reason the kill switch was pulled, and ChangedBy who
	// pulled it — the reason is rendered with its author beside it, not
	// paraphrased and not trusted.
	Why       string
	Changed   string
	ChangedBy string
}

// agentMatches is one entry as the board shows it.
func agentMatches(a agentreg.Agent) agentMatch {
	m := agentMatch{
		Name: a.Name, Owner: a.Owner, Active: a.Status == agentreg.Active,
		Allow: a.Allow, Note: a.Note, Why: a.DisabledWhy, ChangedBy: a.ChangedBy,
	}
	if !a.ChangedAt.IsZero() {
		m.Changed = a.ChangedAt.UTC().Format("2 Jan 2006 15:04") + " UTC"
	}
	switch a.Status {
	case agentreg.Disabled:
		m.Tone = "critical"
		m.Word = "disabled"
		if !a.ChangedAt.IsZero() {
			m.Since = a.ChangedAt.UTC().Format("2 Jan 15:04")
			m.Word = "disabled — refused since " + m.Since
		}
	default:
		m.Tone, m.Word = "good", "active"
	}
	return m
}

// agentJoin is the whole of the registry join: the entries loaded once, and
// each row matched to the ones its own events named. It returns how many
// agents the registry holds — every entry, observed or not, because the
// header's count is the one place a registered-but-silent agent is visible —
// and an error only when the registry is present and cannot be read, which is
// not the same as empty and is said rather than shown as zero matches.
func agentJoin(rows []agentRow) (registered int, err error) {
	entries, err := AgentRegistry.Load()
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return len(entries), nil
	}
	by := make(map[string]agentreg.Agent, len(entries))
	for _, a := range entries {
		by[a.Name] = a
	}
	for i := range rows {
		var matches []agentMatch
		for name := range rows[i].clear {
			a, ok := by[name]
			if !ok {
				continue
			}
			m := agentMatches(a)
			dup := false
			for _, x := range matches {
				if x.Name == m.Name {
					dup = true
				}
			}
			if !dup {
				matches = append(matches, m)
			}
		}
		sort.Slice(matches, func(j, k int) bool { return matches[j].Name < matches[k].Name })
		rows[i].Matches = matches
	}
	return len(entries), nil
}

// agentStatus is the row's one word, derived from the counts and nothing
// else. Refusals outrank recency: an agent being refused is the thing to
// read regardless of when it last called, and "spiking" is held to a bar
// both absolute and relative — three refusals that are a tenth of ten
// thousand calls is noise; three of ten is the agent being stopped
// constantly.
func agentStatus(r *agentRow, now time.Time) {
	switch {
	case r.Refused >= 3 && r.Refused*5 >= r.Calls:
		r.Status, r.StatusTone = "refusals spiking", "serious"
	case now.Sub(r.Last) < 24*time.Hour:
		r.Status, r.StatusTone = "active today", "good"
	default:
		r.Status, r.StatusTone = "quiet", "unknown"
	}
}

// agentTone is the word a disposition renders with, so colour never carries
// the meaning alone.
func agentTone(d telemetry.Disposition) string {
	switch d {
	case telemetry.DispositionAllowed:
		return "good"
	case telemetry.DispositionBlocked:
		return "serious"
	case telemetry.DispositionFailed:
		return "warning"
	case telemetry.DispositionDetected:
		return "serious"
	}
	return "unknown"
}

// agentScan is one walk of the store: the board's rows, what was read, and —
// when a page asked for one agent — that agent's newest events.
type agentScan struct {
	Rows []agentRow
	// Read is every agent event the window held, whatever the filter, so
	// the page's denominators describe the period rather than the view.
	Read                  int
	FromSidecar, FromOtel int
	// From is where the window actually began, which is the budget's
	// decision when Short is set, and the lookback otherwise.
	From  time.Time
	Short bool
	// Stored is the whole store's event count, for the difference between
	// "no agents observed" and "nothing collected".
	Stored int
	// Observed is how many distinct agents the window held, whatever the
	// source filter is showing, because the header's registry count is
	// against the window rather than against the view.
	Observed int
	// Events is the wanted actor's newest events, newest first, only when
	// want named one.
	Events []telemetry.Event
	// Chrono is every event the wanted actor has in the window, oldest
	// first, only when want named one. The session grouping reads it whole,
	// because a session's edges are the events' own trace ids and cutting
	// the newest fifty off would cut a session in half without saying so;
	// Events remains the capped newest end of it for the Recent events
	// table.
	Chrono []telemetry.Event
}

// agentScan reads the two agent sources once and counts them per actor.
//
// The walk reads every agent event in the window so the filter chips can
// carry each source's true count; rows are built only from the source the
// request asked for, so filtering cannot leave a row standing on events it
// no longer includes.
func (s *Server) agentScan(now time.Time, source, want string) (agentScan, error) {
	out := agentScan{}
	sp, closer, err := s.Events.Open()
	if err != nil {
		return out, err
	}
	defer func() { _ = closer() }()
	out.Stored = sp.Events()

	out.From = now.Add(-agentLookback)
	budget := s.Events.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	if wfrom, skipped := window(sp.Segments(), budget); skipped > 0 && wfrom.After(out.From) {
		// Said, because a board that quietly counted less than its stated
		// window reports an agent as quiet that was busy before the cut.
		out.From = wfrom
		out.Short = true
	}

	// An equality a sidecar bloom can answer before the segment is opened:
	// a segment is refused only when it can hold neither source's events,
	// which cannot narrow what the walk would have kept.
	keep := func(seg spool.Segment) bool {
		return sp.CouldHold(seg, "source", agentSidecar) ||
			sp.CouldHold(seg, "source", agentOtel)
	}

	type tally struct {
		row    agentRow
		tools  map[string]*agentTool
		models map[string]bool
		names  map[string]bool
	}
	by := map[string]*tally{}
	// The distinct actors the window named, before any filter narrows the
	// rows: the denominator the header's registry count sits beside.
	seenActor := map[string]bool{}
	// The wanted agent's events, in the order the walk reads them, which is
	// arrival order: the input the session grouping is computed from.
	var mine []telemetry.Event
	err = sp.RangeWhere(out.From, time.Time{}, keep, func(e telemetry.Event) error {
		if e.Source != agentSidecar && e.Source != agentOtel {
			return nil
		}
		out.Read++
		switch e.Source {
		case agentSidecar:
			out.FromSidecar++
		case agentOtel:
			out.FromOtel++
		}
		if !e.Actor.Zero() && !seenActor[e.Actor.String()] {
			seenActor[e.Actor.String()] = true
			out.Observed++
		}
		if source == "aertun" && e.Source != agentSidecar {
			return nil
		}
		if source == "otel" && e.Source != agentOtel {
			return nil
		}
		if e.Actor.Zero() {
			// An event that attributes its actions to nobody cannot be an
			// agent's row; counted as read and shown to no one.
			return nil
		}
		k := e.Actor.String()
		t := by[k]
		if t == nil {
			t = &tally{
				row: agentRow{Actor: e.Actor, Key: k, Href: agentHref(e.Actor),
					clear: map[string]bool{},
					First: e.Received, Last: e.Received},
				tools: map[string]*agentTool{}, models: map[string]bool{},
				names: map[string]bool{},
			}
			by[k] = t
		}
		r := &t.row
		if e.Received.Before(r.First) {
			r.First = e.Received
		}
		if e.Received.After(r.Last) {
			r.Last = e.Received
		}
		// A call, or the analyst's own record? The sidecar's tool calls and
		// every span are calls; the analyst proposing and abstaining is the
		// model's conduct rather than something it asked to do, and counting
		// it as a call would put refusals under a denominator of things that
		// cannot be refused.
		call := true
		switch e.Source {
		case agentSidecar:
			r.FromSidecar++
			switch e.Raw["action"] {
			case "proposal.finding":
				r.Proposals++
				call = false
			case "analyst.abstained", "analyst.model-unusable":
				call = false
			}
			if n := e.Raw["agent"]; n != "" {
				t.names[n] = true
			}
		case agentOtel:
			r.FromOtel++
			if n, perr := strconv.ParseInt(e.Raw["tokens_in"], 10, 64); perr == nil {
				r.TokensIn += n
			}
			if n, perr := strconv.ParseInt(e.Raw["tokens_out"], 10, 64); perr == nil {
				r.TokensOut += n
			}
		}
		// The clear names this event carried — a token issued to a
		// registered agent is named agent:NAME, and some records carry an
		// agent field of their own — are the one thread the registry can be
		// joined on. Collected for the join and shown nowhere: a name no
		// entry matches is a string an event wrote, and the board matches
		// those strings rather than displaying them.
		for _, f := range []string{e.Raw["client"], e.Raw["agent"]} {
			if n, ok := agentreg.Bind(f); ok {
				r.clear[n] = true
			} else if f != "" {
				r.clear[f] = true
			}
		}
		if call {
			r.Calls++
			switch e.Disposition {
			case telemetry.DispositionBlocked:
				r.Refused++
			case telemetry.DispositionFailed:
				r.Failed++
			}
		}
		if name := e.Raw["tool"]; name != "" {
			tool := t.tools[name]
			if tool == nil {
				tool = &agentTool{Name: name}
				t.tools[name] = tool
			}
			tool.N++
			if e.Received.Format("2 Jan 15:04") > tool.Last {
				tool.Last = e.Received.Format("2 Jan 15:04")
			}
		}
		if m := e.Raw["model"]; m != "" {
			t.models[m] = true
		}
		if want != "" && k == want {
			mine = append(mine, e)
		}
		return nil
	})
	if err != nil {
		return out, err
	}

	for _, t := range by {
		r := t.row
		for _, tool := range t.tools {
			r.Tools = append(r.Tools, *tool)
		}
		sort.Slice(r.Tools, func(i, j int) bool {
			if r.Tools[i].N != r.Tools[j].N {
				return r.Tools[i].N > r.Tools[j].N
			}
			return r.Tools[i].Name < r.Tools[j].Name
		})
		// The board's cell offers the few tools that matter and points at
		// the agent's page for the rest; the page lists them all.
		r.ToolsShown = r.Tools
		if len(r.Tools) > agentToolsShown {
			r.ToolsShown = r.Tools[:agentToolsShown]
			r.ToolsMore = len(r.Tools) - agentToolsShown
		}
		r.Models = setList(t.models)
		r.Names = setList(t.names)
		r.TokensInS, r.TokensOutS = humanTokens(r.TokensIn), humanTokens(r.TokensOut)
		agentStatus(&r, now)
		r.LastAgo = agoAt(r.Last.Unix(), now)
		out.Rows = append(out.Rows, r)
	}
	// The most recently active first, so the top of the board is the agent
	// somebody should read about next; the key breaks ties so two loads of
	// the same page read the same.
	sort.Slice(out.Rows, func(i, j int) bool {
		if !out.Rows[i].Last.Equal(out.Rows[j].Last) {
			return out.Rows[i].Last.After(out.Rows[j].Last)
		}
		return out.Rows[i].Key < out.Rows[j].Key
	})

	// Where an event under one key called itself by another key's value,
	// the two rows say so to each other. That is the whole of the join the
	// page is allowed to claim: observed, in the events, and unmerged.
	byValue := map[string]string{}
	for _, r := range out.Rows {
		if _, ok := byValue[r.Actor.Value]; !ok {
			byValue[r.Actor.Value] = r.Key
		}
	}
	for i := range out.Rows {
		for _, n := range out.Rows[i].Names {
			other, ok := byValue[n]
			if !ok || other == out.Rows[i].Key {
				continue
			}
			out.Rows[i].MaybeSame = appendUnique(out.Rows[i].MaybeSame, other)
			for j := range out.Rows {
				if out.Rows[j].Key == other {
					out.Rows[j].MaybeSame = appendUnique(out.Rows[j].MaybeSame, out.Rows[i].Key)
				}
			}
		}
	}

	// The wanted agent's whole window, then the capped newest end of it for
	// the Recent events table: the sessions are grouped from everything the
	// window holds, and the table stays the table it was.
	//
	// Sorted by arrival, because the walk reads segments in the order they
	// were written and a late write inside one segment must not read as the
	// newest thing an agent did.
	if want != "" && len(mine) > 0 {
		sort.SliceStable(mine, func(i, j int) bool {
			return mine[i].Received.Before(mine[j].Received)
		})
		out.Chrono = mine
		n := len(mine)
		if n > agentTimeline {
			n = agentTimeline
		}
		out.Events = make([]telemetry.Event, 0, n)
		for i := n - 1; i >= 0; i-- {
			out.Events = append(out.Events, mine[i])
		}
	}
	return out, nil
}

// setList is a set as a sorted list, so a page reads the same every time.
func setList(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// humanTokens is a token count as a person reads it: "3.5k", "1.2M", "940".
// The exact number is on the agent's page in its counts; the board's question
// is which agent moves millions of tokens, and "2143080" answers it last.
func humanTokens(n int64) string {
	switch {
	case n >= 1_000_000:
		s := fmt.Sprintf("%.1f", float64(n)/1_000_000)
		return strings.TrimSuffix(s, ".0") + "M"
	case n >= 1_000:
		s := fmt.Sprintf("%.1f", float64(n)/1_000)
		return strings.TrimSuffix(s, ".0") + "k"
	}
	return strconv.FormatInt(n, 10)
}

// agentFilter is one chip of the source filter.
type agentFilter struct {
	Key, Label, Href string
	Count            int
	On               bool
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityCan(w, r, auth.ActTriage)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Nav": "agents", "Title": "Agents", "Principal": p}
	if s.Events == nil || s.Events.Open == nil {
		data["Unavailable"] = "This build was started without a telemetry " +
			"store. That is not the same as an estate with no agents: a " +
			"board showing none would say they are quiet, and this build " +
			"cannot see whether they are."
		s.render(w, r, "agents.html", data)
		return
	}
	now := time.Now().UTC()
	source := agentSourceKey(r.URL.Query().Get("source"))
	scan, err := s.agentScan(now, source, "")
	if errors.Is(err, ErrNeverCollected) {
		body := "Nothing has ever been collected here, so no agent has been " +
			"observed. That is not a quiet estate of agents — it is one " +
			"nothing is watching. Agent events arrive from the MCP sidecar " +
			"and the analyst (aertun/agent), and from GenAI telemetry " +
			"pushed over OTLP (otel/genai)."
		// The registry is a separate record, and what it holds is a fact
		// even where nothing observes the agents it names: said here so a
		// registered estate is not made to look unregistered by a store
		// that has collected nothing.
		if n, rerr := agentJoin(nil); rerr == nil && n > 0 {
			body += " The registry, separately, holds " +
				countOf(n, "agent", "agents") + " — registered, and never " +
				"observed, because nothing is being collected here."
		}
		data["Unavailable"] = body
		s.render(w, r, "agents.html", data)
		return
	}
	if err != nil {
		data["Unavailable"] = "The telemetry store could not be opened: " +
			err.Error() + ". A store that cannot be read is not a store " +
			"with no agents in it."
		s.render(w, r, "agents.html", data)
		return
	}
	registered, rerr := agentJoin(scan.Rows)
	if rerr != nil {
		// An unreadable registry is not an empty one, and a board that
		// carried on matching against nothing would print "not registered"
		// as a fact it could not check. The join is withheld and said so;
		// every observed fact on the page stands.
		data["RegistryErr"] = rerr.Error()
	} else {
		data["RegistryErr"] = ""
	}
	data["Registered"], data["Observed"] = registered, scan.Observed
	data["Rows"] = scan.Rows
	data["Read"], data["Stored"] = scan.Read, scan.Stored
	data["From"], data["Short"] = scan.From, scan.Short
	data["Filtered"] = source != ""
	data["Filters"] = []agentFilter{
		{Label: "All sources", Href: "/security/agents", Count: scan.Read, On: source == ""},
		{Label: agentSidecar, Href: "/security/agents?source=aertun",
			Count: scan.FromSidecar, On: source == "aertun"},
		{Label: agentOtel, Href: "/security/agents?source=otel",
			Count: scan.FromOtel, On: source == "otel"},
	}
	refused, proposals, active := 0, 0, 0
	maybe := false
	for _, row := range scan.Rows {
		refused += row.Refused
		proposals += row.Proposals
		if row.Status == "active today" {
			active++
		}
		if len(row.MaybeSame) > 0 {
			maybe = true
		}
	}
	data["Refused"], data["ProposalsN"], data["Active"] = refused, proposals, active
	data["BothSources"] = scan.FromSidecar > 0 && scan.FromOtel > 0
	data["Maybe"] = maybe

	poll, refresh := pollMode(r)
	data["Poll"], data["Refresh"] = poll, refresh
	s.render(w, r, "agents.html", data)
}

// agentEvent is one line of an agent's timeline: closed fields, and a
// refusal's reason carried with the label such text has earned.
type agentEvent struct {
	When              string
	Source, Act, Tool string
	Model             string
	Outcome, Tone     string
	// Why is the reason a refused call was given. It is text a model or a
	// policy wrote about events somebody being detected may have influenced,
	// so it is shown and labelled rather than shown and trusted.
	Why string
}

// agentTimelineEntry is one line of a session's timeline. Every field on it
// is a closed word the event carried — the operation or action, the tool,
// the model, the disposition — plus the two things the window itself
// computes: the duration a GenAI span reported, and whether this was the
// agent's first use of that tool inside the window. No prose field is
// rendered here; the reasons a refusal gave stay in Recent events, where the
// one prose field on this page is shown with the label such text has earned.
type agentTimelineEntry struct {
	When            string
	Op, Tool, Model string
	Outcome, Tone   string
	Dur             string
	FirstUse        bool
}

// agentSessionTool is one tool as one session used it: in first-use order
// with its count, and the window-first mark where this session is where the
// agent first used it at all.
type agentSessionTool struct {
	Name  string
	N     int
	First bool
}

// agentSession is one trace's events as the page shows them. Everything on
// it is the events' own closed fields or arithmetic over them; the session
// exists because its events shared a trace id, and never otherwise.
type agentSession struct {
	// Trace is the trace id as stored, the one edge the events drew
	// themselves; Convs the distinct conversation ids they carried, shown
	// as many times as the telemetry named rather than one picked.
	Trace string
	Convs []string
	// Href is the session's own address, so a finding's evidence can cite
	// it: the page with ?session= set to this trace.
	Href string

	Start, End          time.Time
	StartS, EndS, SpanS string

	// Calls is every event in the trace — a span is a call — with how each
	// ended; Others is the ones that ended in a way the three words do not
	// name, kept visible so the counts sum to their denominator.
	Calls, Allowed, Failed, Blocked, Others int

	Tools  []agentSessionTool
	Models []string

	TokensIn, TokensOut   int64
	TokensInS, TokensOutS string

	Entries []agentTimelineEntry
	// Hidden is how many of the session's events fall beyond the timeline
	// cap, newest kept: said on the page rather than cut in silence.
	Hidden int
}

// agentStream is the sidecar's and the analyst's events as one stream. They
// carry no trace id, so no session can be grouped from them, and the page
// says the stream is arrival order rather than a claim of one session.
type agentStream struct {
	Events int
	// Calls, and how they ended, with the analyst's proposals counted apart
	// — the same distinction the board's row makes, for the same reason: a
	// proposal is the model's conduct, not something it asked to do.
	Calls, Allowed, Failed, Blocked, Others int
	Proposals                               int
	Entries                                 []agentTimelineEntry
	Hidden                                  int
}

// agentDur is a duration as a person reads it: "412 ms", "8.4 s", "9m 41s",
// "1h 4m". GenAI spans report milliseconds; a session's span is the wall
// time between its first and last arrival, which is the honest number — the
// page never claims to know when the agent finished thinking.
func agentDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return strconv.FormatInt(d.Milliseconds(), 10) + " ms"
	case d < time.Minute:
		s := fmt.Sprintf("%.1f", d.Seconds())
		return strings.TrimSuffix(s, ".0") + " s"
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

// agentSessions groups one agent's window into sessions and the stream.
//
// otel/genai events draw one edge themselves — a shared trace id — and that
// edge is the only thing grouped on. An otel event without a trace id
// belongs to no session and is counted for the page to say so; it stays in
// Recent events, ungrouped rather than fenced into a session of one.
// aertun/agent events draw no edges at all, so they are one stream in
// arrival order, said as a rendering choice and never as one session.
//
// The first-use marks are computed in the same single pass over both
// sources, so a tool the sidecar watched this agent use on Monday is not
// re-marked as new when GenAI telemetry reports it on Friday.
func agentSessions(actor telemetry.ID, events []telemetry.Event) (
	sessions []agentSession, stream *agentStream, untraced int) {

	type build struct {
		s      agentSession
		models map[string]bool
		convs  map[string]bool
	}
	byTrace := map[string]*build{}
	var order []string
	seenTool := map[string]bool{}
	for _, e := range events {
		entry := agentTimelineEntry{
			When: e.Received.Format("2 Jan 15:04:05"),
			Op:   e.Raw["operation"], Tool: e.Raw["tool"],
			Model: e.Raw["model"], Outcome: e.Disposition.String(),
			Tone: agentTone(e.Disposition),
		}
		if e.Source == agentSidecar {
			entry.Op = e.Raw["action"]
		} else if ms, perr := strconv.ParseInt(e.Raw["duration_ms"], 10, 64); perr == nil {
			entry.Dur = agentDur(time.Duration(ms) * time.Millisecond)
		}
		if entry.Tool != "" && !seenTool[entry.Tool] {
			// The window's first use of this tool, from either source. The
			// mark the timeline carries is this observation and nothing
			// more: no verdict, and no claim about the data, which these
			// events do not carry.
			entry.FirstUse = true
			seenTool[entry.Tool] = true
		}

		if e.Source == agentSidecar {
			if stream == nil {
				stream = &agentStream{}
			}
			stream.Events++
			call := true
			switch e.Raw["action"] {
			case "proposal.finding":
				stream.Proposals++
				call = false
			case "analyst.abstained", "analyst.model-unusable":
				call = false
			}
			if call {
				stream.Calls++
				switch e.Disposition {
				case telemetry.DispositionBlocked:
					stream.Blocked++
				case telemetry.DispositionFailed:
					stream.Failed++
				case telemetry.DispositionAllowed:
					stream.Allowed++
				default:
					stream.Others++
				}
			}
			stream.Entries = append(stream.Entries, entry)
			continue
		}

		trace := e.Raw["trace_id"]
		if trace == "" {
			untraced++
			continue
		}
		b := byTrace[trace]
		if b == nil {
			b = &build{
				s: agentSession{Trace: trace,
					Href: agentHref(actor) + "?session=" + url.QueryEscape(trace)},
				models: map[string]bool{}, convs: map[string]bool{},
			}
			byTrace[trace] = b
			order = append(order, trace)
		}
		s := &b.s
		if s.Calls == 0 || e.Received.Before(s.Start) {
			s.Start = e.Received
		}
		if e.Received.After(s.End) {
			s.End = e.Received
		}
		s.Calls++
		switch e.Disposition {
		case telemetry.DispositionBlocked:
			s.Blocked++
		case telemetry.DispositionFailed:
			s.Failed++
		case telemetry.DispositionAllowed:
			s.Allowed++
		default:
			s.Others++
		}
		if n, perr := strconv.ParseInt(e.Raw["tokens_in"], 10, 64); perr == nil {
			s.TokensIn += n
		}
		if n, perr := strconv.ParseInt(e.Raw["tokens_out"], 10, 64); perr == nil {
			s.TokensOut += n
		}
		if m := e.Raw["model"]; m != "" {
			b.models[m] = true
		}
		if c := e.Raw["conversation"]; c != "" {
			b.convs[c] = true
		}
		if t := entry.Tool; t != "" {
			found := false
			for i := range s.Tools {
				if s.Tools[i].Name == t {
					s.Tools[i].N++
					found = true
					break
				}
			}
			if !found {
				s.Tools = append(s.Tools, agentSessionTool{Name: t, N: 1,
					First: entry.FirstUse})
			}
		}
		s.Entries = append(s.Entries, entry)
	}

	for _, trace := range order {
		b := byTrace[trace]
		s := b.s
		s.Models = setList(b.models)
		s.Convs = setList(b.convs)
		s.StartS = s.Start.Format("2 Jan 15:04:05")
		s.EndS = s.End.Format("2 Jan 15:04:05")
		s.SpanS = agentDur(s.End.Sub(s.Start))
		s.TokensInS, s.TokensOutS = humanTokens(s.TokensIn), humanTokens(s.TokensOut)
		if len(s.Entries) > agentTimeline {
			s.Hidden = len(s.Entries) - agentTimeline
			s.Entries = s.Entries[len(s.Entries)-agentTimeline:]
		}
		sessions = append(sessions, s)
	}
	// The newest session first, so the top of the page is the session
	// somebody should read next; the trace id breaks ties so two loads of
	// the same page read the same.
	sort.Slice(sessions, func(i, j int) bool {
		if !sessions[i].Start.Equal(sessions[j].Start) {
			return sessions[i].Start.After(sessions[j].Start)
		}
		return sessions[i].Trace < sessions[j].Trace
	})
	if stream != nil && len(stream.Entries) > agentTimeline {
		stream.Hidden = len(stream.Entries) - agentTimeline
		stream.Entries = stream.Entries[len(stream.Entries)-agentTimeline:]
	}
	return sessions, stream, untraced
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityCan(w, r, auth.ActTriage)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	id := strings.TrimPrefix(r.URL.Path, "/security/agents/")
	if id == "" {
		http.Redirect(w, r, "/security/agents", http.StatusSeeOther)
		return
	}
	if len(id) > 512 || strings.ContainsAny(id, "\x00\r\n") {
		// Refused rather than sanitised into a match: an identity is what
		// the events carry, and a near-enough lookup on it would put one
		// agent's record on another's page.
		id = ""
	}
	data := map[string]any{"Nav": "agents", "Title": "Agent", "Principal": p}
	if id == "" {
		s.agentNotFound(w, r, p, "")
		return
	}
	unavailable := func(what string) {
		data["Unavailable"] = what
		s.render(w, r, "agents.html", data)
	}
	if s.Events == nil || s.Events.Open == nil {
		unavailable("This build was started without a telemetry store, so " +
			"nothing can be said about any agent from here.")
		return
	}
	now := time.Now().UTC()
	scan, err := s.agentScan(now, "", id)
	if errors.Is(err, ErrNeverCollected) {
		unavailable("Nothing has ever been collected here, so no agent has " +
			"been observed. That is not a quiet estate of agents — it is one " +
			"nothing is watching.")
		return
	}
	if err != nil {
		unavailable("The telemetry store could not be opened: " + err.Error())
		return
	}
	var row *agentRow
	for i := range scan.Rows {
		if scan.Rows[i].Key == id {
			row = &scan.Rows[i]
			break
		}
	}
	if row == nil {
		s.agentNotFound(w, r, p, id)
		return
	}
	data["Agent"], data["From"], data["Short"] = row, scan.From, scan.Short
	data["CanKill"] = s.KillAgent != nil && s.Policy != nil &&
		s.Policy.Evaluate(p.Name, auth.ActRespond, auth.AreaSecurity).Allowed
	data["Read"] = scan.Read
	// The same join the board makes, so a row's page and its row cannot
	// disagree about what the registry holds.
	if _, rerr := agentJoin(scan.Rows); rerr != nil {
		data["RegistryErr"] = rerr.Error()
	} else {
		data["RegistryErr"] = ""
	}
	var events []agentEvent
	for _, e := range scan.Events {
		act := e.Raw["action"]
		if e.Source == agentOtel {
			act = e.Raw["operation"]
		}
		if act == "" {
			act = e.Message
		}
		events = append(events, agentEvent{
			When:    e.Received.Format("2 Jan 15:04:05"),
			Source:  e.Source,
			Act:     act,
			Tool:    e.Raw["tool"],
			Model:   e.Raw["model"],
			Outcome: e.Disposition.String(),
			Tone:    agentTone(e.Disposition),
			Why:     e.Raw["why"],
		})
	}
	data["Events"] = events

	// The timeline view: the same window the page just listed, grouped by
	// the one edge the events draw themselves. An otel trace is a session;
	// the sidecar's events carry no trace id and stay one stream.
	sessions, stream, untraced := agentSessions(row.Actor, scan.Chrono)
	if q := r.URL.Query().Get("session"); q != "" {
		match := -1
		// A trace id is what the events carried: matched exactly or not at
		// all, the same discipline the identity above is held to, and never
		// echoed back at a length no trace id resembles.
		okay := len(q) <= 512 && !strings.ContainsAny(q, "\x00\r\n")
		if okay {
			for i := range sessions {
				if sessions[i].Trace == q {
					match = i
					break
				}
			}
		}
		if match >= 0 {
			sessions = sessions[match : match+1]
			data["SessionOnly"] = true
		} else {
			// An unknown trace id is an honest empty rather than a 404: the
			// agent's page stands, and every session it did group renders
			// below. A trace id another agent's events carried would look
			// absent here, and the notice says where the miss may live.
			miss := q
			if !okay {
				miss = "a value no trace id in these events resembles"
			}
			data["SessionMiss"] = miss
		}
	}
	data["Sessions"], data["Stream"], data["Untraced"] = sessions, stream, untraced
	s.render(w, r, "agents.html", data)
}

// agentNotFound is the honest answer for an identity no event carried: a
// 404 that says what was looked in, over what period, and that quiet and
// absent are different facts.
func (s *Server) agentNotFound(w http.ResponseWriter, r *http.Request,
	p principal, id string) {

	body := "Nothing arrived from aertun/agent or otel/genai with that " +
		"exact actor in the last seven days. It may have gone quiet before " +
		"then, or the identity is not the one the events carry. Every agent " +
		"observed is on the Agents board."
	if id != "" {
		body = "Nothing arrived from aertun/agent or otel/genai with the " +
			"actor " + id + " in the last seven days. It may have gone " +
			"quiet before then, or the identity is not the one the events " +
			"carry. Every agent observed is on the Agents board."
	}
	s.render(w, r, "message.html", map[string]any{
		"Status": http.StatusNotFound, "Title": "No such agent",
		"Principal": p,
		"Heading":   "No agent has been observed under that identity",
		"Body":      body,
	})
}

// handleAgentKill is the kill switch on the console: the same switch the
// command line pulls (Server.KillAgent), asked of a responder, because the
// person who has to stop an agent at three in the morning holds the pager,
// not necessarily an administrator. It takes a reason, kept on the record
// for whoever decides to enable the agent again.
func (s *Server) handleAgentKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok || !s.can(w, r, p, auth.ActRespond, auth.AreaSecurity) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	back := func(msg string) {
		http.Redirect(w, r, "/security/agents?m="+urlQueryEscape(msg), http.StatusSeeOther)
	}
	name := strings.TrimSpace(r.FormValue("name"))
	why := strings.TrimSpace(r.FormValue("why"))
	switch {
	case s.KillAgent == nil:
		back("This server cannot pull an agent's kill switch; use aertun agent disable.")
		return
	case !agentreg.ValidName(name):
		back("That does not name a registered agent.")
		return
	case why == "" || len(why) > 500 || strings.ContainsAny(why, "\x00\r\n"):
		back("Disabling an agent takes a reason of one line, kept on the record for whoever decides to enable it again.")
		return
	}
	revoked, err := s.KillAgent(name, why, p.Name)
	if err != nil {
		back(err.Error())
		return
	}
	back(fmt.Sprintf("%s is disabled, and %d of its token(s) revoked.", name, revoked))
}
