// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/mcp"
	"github.com/aertun/aertun/internal/twin"
)

// The context twin: the agent interface, answering from a recorded case
// instead of from the store.
//
// An agent's investigation is a run of reads — the queue, a finding, the
// rules' record, the incidents, the vulnerability plan, the estate — and
// against the store no two runs read the same thing, because the store
// moves. To measure an agent, the same case has to be put to it twice and
// answered the same way both times, and a person reviewing what it
// concluded needs to see exactly what it was shown. So a case is recorded
// once (`aertun twin record`), and the twin answers from that record and
// from nothing else (`aertun mcp --twin FILE`).
//
// What a case holds is what the read operations read, taken at the seam
// between their two steps (registerSecurityOps): each operation's gather
// runs once, for the person recording, through the same gates the agent
// interface applies, and what it read is kept. The queue is kept whole,
// because two operations apply their arguments to it — list_findings its
// filters, read_finding its id — and keeping the queue answers every
// argument the live interface would. The other four take no arguments, so
// what is kept is the facts their answer is drawn from and nothing more:
// counts and rows, never the estate's people or the record an incident's
// people wrote. Every answer is then rendered by the operation's own code,
// at the instant the case was recorded, so the twin says what the agent
// interface said then, value for value, and labels every value with
// whether an attacker could have written it (mcpanswer.go).

// twinCase is one recorded case: what the read operations read, as of
// Recorded.
type twinCase struct {
	Recorded   time.Time                `json:"recorded"`
	Findings   []finding.Finding        `json:"findings"`
	Detections twinPart[detectionFacts] `json:"detection_stats"`
	Incidents  twinPart[incidentFacts]  `json:"incident_status"`
	Vulns      twinPart[vulnPlanFacts]  `json:"vuln_plan"`
	Estate     twinPart[estateFacts]    `json:"estate_summary"`
}

// twinPart is what one operation's gather came back with when the case was
// recorded: what it read, or the error the agent interface would have
// answered with at that instant — a store with no estate read into it yet
// answers estate_summary with an error, and so does its replay. A part
// with neither was refused to whoever recorded it, and the twin refuses
// the operation in turn.
type twinPart[F any] struct {
	Facts  *F     `json:"facts"`
	Failed string `json:"failed"`
}

// replay is the answer a part gives: rendered from its facts, its recorded
// error, or a refusal for a part nobody was allowed to record.
func (p twinPart[F]) replay(op, digest string, render func(F) (*answer, error)) (*answer, error) {
	switch {
	case p.Facts != nil:
		return render(*p.Facts)
	case p.Failed != "":
		return nil, errors.New(p.Failed)
	}
	return nil, &mcp.Refusal{Reason: fmt.Sprintf("snapshot %s holds no answer "+
		"for %s: whoever recorded it was not allowed to read it, and a replay "+
		"answers only from what was recorded", digest, op)}
}

// recordTwin runs every read operation's gather for caller, at now, and
// keeps what each read. A part refused to caller is left out and why is
// said in the map returned, keyed by operation; a part whose gather failed
// keeps the failure as its answer, since that is what the agent interface
// said then. The queue is the exception to both, because a case without
// the queue is not a case: refusing it or failing to read it refuses the
// whole recording.
func recordTwin(root string, caller *Caller, now time.Time) (twinCase, map[string]string, error) {
	c := twinCase{Recorded: now}
	q, err := gatherQueue(root, caller, now)
	var ref *mcp.Refusal
	if errors.As(err, &ref) {
		return c, nil, errBlocked{fmt.Errorf("the security queue is not yours "+
			"to read, so there is no case to record: %s", ref.Reason)}
	}
	if err != nil {
		return c, nil, fmt.Errorf("the security queue could not be read, so "+
			"nothing was recorded: %w", err)
	}
	c.Findings = q
	if c.Findings == nil {
		c.Findings = []finding.Finding{}
	}

	omitted := map[string]string{}
	d, err := gatherDetectionStats(root, caller, now)
	c.Detections = keepPart(opDetectionStats.Name, omitted, d, err)
	i, err := gatherIncidentStatus(root, caller, now)
	c.Incidents = keepPart(opIncidentStatus.Name, omitted, i, err)
	v, err := gatherVulnPlan(root, caller, now)
	c.Vulns = keepPart(opVulnPlan.Name, omitted, v, err)
	e, err := gatherEstateSummary(root, caller, now)
	c.Estate = keepPart(opEstateSummary.Name, omitted, e, err)
	return c, omitted, nil
}

// keepPart is one gather's result as a part of a case: what it read, the
// error it failed with, or nothing, for a refusal.
func keepPart[F any](op string, omitted map[string]string, facts F, err error) twinPart[F] {
	var ref *mcp.Refusal
	switch {
	case err == nil:
		return twinPart[F]{Facts: &facts}
	case errors.As(err, &ref):
		omitted[op] = ref.Reason
		return twinPart[F]{}
	}
	return twinPart[F]{Failed: err.Error()}
}

// openTwin reads a snapshot file and builds the twin over it. A file whose
// digest does not match, or that does not read strictly as a case, is
// refused before any server exists to answer from it.
func openTwin(path string) (*mcp.Server, error) {
	var c twinCase
	digest, err := twin.Read(path, &c)
	if err != nil {
		return nil, errUsage{fmt.Errorf("%s cannot be replayed: %w", path, err)}
	}
	if c.Recorded.IsZero() || c.Findings == nil {
		return nil, errUsage{fmt.Errorf("%s cannot be replayed: it does not "+
			"say when it was recorded or holds no queue, and every answer is "+
			"drawn from both", path)}
	}
	return buildTwin(&c, digest), nil
}

// buildTwin is the agent interface over one recorded case. It is handed
// the case and its digest and nothing else — no store, no caller — so
// nothing it answers can come from anywhere but the case, and nothing it
// is asked can reach anything to change.
//
// It offers exactly the operations the agent interface offers, described
// in the same words, so an agent finds the same menu. Each read is
// answered by the same render the agent interface uses, over the recorded
// part at the recorded instant, and printed labelled. Everything else is
// refused: a write, because a replay that changed something, or said it
// had, would no longer be the case it replays; and find, because it
// searches this program's screens rather than the store, so there is no
// recorded answer to give.
func buildTwin(c *twinCase, digest string) *mcp.Server {
	srv := mcp.NewServer("aertun-twin", version)
	// What a caller may read was decided when the case was recorded: only
	// what the recorder could read through the same gates is in it, and the
	// file is the boundary from there, written 0600 to whoever recorded it.
	// There is no store and no policy here to ask again.
	srv.Authorise = func(mcp.Operation) error { return nil }

	reply := func(build func(map[string]any) (*answer, error)) mcp.Handler {
		return func(a map[string]any) (any, error) {
			ans, err := build(a)
			if err != nil {
				return nil, err
			}
			return object().
				with("snapshot", ours(digest)).
				with("recorded", ours(c.Recorded)).
				with("answer", ans).labelled()
		}
	}
	srv.Register(opListFindings, reply(func(a map[string]any) (*answer, error) {
		return answerListFindings(c.Findings, a, c.Recorded), nil
	}))
	srv.Register(opReadFinding, reply(func(a map[string]any) (*answer, error) {
		f, err := answerReadFinding(c.Findings, a, c.Recorded)
		if err != nil {
			return nil, err
		}
		return f.tree(), nil
	}))
	srv.Register(opDetectionStats, reply(func(map[string]any) (*answer, error) {
		return c.Detections.replay(opDetectionStats.Name, digest,
			func(f detectionFacts) (*answer, error) { return answerDetectionStats(f), nil })
	}))
	srv.Register(opIncidentStatus, reply(func(map[string]any) (*answer, error) {
		return c.Incidents.replay(opIncidentStatus.Name, digest,
			func(f incidentFacts) (*answer, error) { return answerIncidentStatus(f), nil })
	}))
	srv.Register(opVulnPlan, reply(func(map[string]any) (*answer, error) {
		return c.Vulns.replay(opVulnPlan.Name, digest, answerVulnPlan)
	}))
	srv.Register(opEstateSummary, reply(func(map[string]any) (*answer, error) {
		return c.Estate.replay(opEstateSummary.Name, digest,
			func(f estateFacts) (*answer, error) { return answerEstateSummary(f), nil })
	}))

	srv.Register(opFind, func(map[string]any) (any, error) {
		return nil, &mcp.Refusal{Reason: "find searches this program's " +
			"screens, not the store, so a replay of a recorded case has no " +
			"answer for it"}
	})
	srv.Register(opProposeFindingDecision, func(map[string]any) (any, error) {
		return nil, &mcp.Refusal{Reason: fmt.Sprintf("this is a replay of "+
			"snapshot %s, recorded %s, and a replay changes nothing: no "+
			"proposal was recorded, here or anywhere", digest,
			c.Recorded.Format(time.RFC3339))}
	})
	return srv
}
