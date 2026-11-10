// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/twin"
)

// `aertun twin record` writes a case for the context twin (mcptwin.go):
// what the agent interface's read operations would read now, for whoever
// runs it, in one file sealed under its digest. `aertun mcp --twin FILE`
// serves it.
//
// Recording takes the security queue and its evidence out of the store
// into a file, so it needs what listing the queue on the command line
// needs (privilege.go), runs every gate the agent interface would for the
// same person, and is audited before the file is written: a copy of the
// queue nobody can account for is the thing the audit log exists to
// prevent.

func cmdTwin(root string, args []string) error {
	if len(args) == 0 {
		return twinUsage()
	}
	switch args[0] {
	case "record":
		return twinRecord(root, args[1:])
	case "help":
		return twinHelp()
	}
	return twinUsage()
}

func twinUsage() error {
	return errUsage{fmt.Errorf("usage: aertun twin record --out FILE | help")}
}

func twinHelp() error {
	w.Human(`  The context twin: an agent's investigation, replayed against one recorded case.

  aertun twin record --out case.json   what the agent interface would answer now, in one file
  aertun mcp --twin case.json          the agent interface over stdio, answering from that file

  Recording runs every read operation's gates for you, as the agent
  interface would, and keeps what each read: the queue with every decision
  applied, and the facts behind the rule statistics, the open incidents,
  the vulnerability plan and the estate summary. A part you are not allowed
  to read is left out, and the twin refuses the operation that reads it; a
  part the agent interface could not answer — no estate read in yet, say —
  is kept as that failure, and replays as it.
  The file is written 0600, names its own sha256 digest, and is recorded in
  the audit log under that digest.

  The twin is handed the file and nothing else. The same question gets the
  same bytes back every time, every value says whether an attacker could
  have written it ("attacker_writable"), and anything that would change
  something — a proposal — is refused. A file whose bytes no longer match
  its digest is refused before anything answers from it.
`)
	return nil
}

func twinRecord(root string, args []string) error {
	fs := flag.NewFlagSet("twin record", flag.ContinueOnError)
	outAt := fs.String("out", "", "where to write the case (written 0600: "+
		"it holds the security queue and its evidence)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outAt == "" || fs.NArg() != 0 {
		return errUsage{fmt.Errorf("twin record needs --out FILE and nothing " +
			"else: the case is a file, written for the replay to read")}
	}
	caller := resolveCaller(root, flagToken)
	now := time.Now().UTC()
	c, omitted, err := recordTwin(root, caller, now)
	if err != nil {
		return err
	}
	doc, digest, err := twin.Seal(c)
	if err != nil {
		return err
	}
	failed := map[string]string{}
	for op, msg := range map[string]string{
		opDetectionStats.Name: c.Detections.Failed, opIncidentStatus.Name: c.Incidents.Failed,
		opVulnPlan.Name: c.Vulns.Failed, opEstateSummary.Name: c.Estate.Failed,
	} {
		if msg != "" {
			failed[op] = msg
		}
	}
	left, errored := sortedOps(omitted), sortedOps(failed)
	if err := recordE(root, caller.auditRecord("twin.record", auth.AreaSecurity,
		audit.Success, map[string]string{
			"snapshot": digest, "findings": strconv.Itoa(len(c.Findings)),
			"not_recorded":    strings.Join(left, ","),
			"recorded_failed": strings.Join(errored, ","),
		})); err != nil {
		return fmt.Errorf("the audit log could not take the record of this "+
			"recording, so nothing was written: %w", err)
	}
	if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
		return err
	}
	if w.JSON(map[string]any{"file": *outAt, "snapshot": digest,
		"recorded": now, "findings": len(c.Findings), "not_recorded": omitted,
		"recorded_failed": failed}) {
		return nil
	}
	w.Human("recorded %d finding(s) as of %s to %s\n  %s%s%s\n",
		len(c.Findings), now.Format(time.RFC3339), *outAt, dim, digest, reset)
	for _, op := range left {
		w.Human("  %snot recorded: %s — %s%s\n", yellow, op, omitted[op], reset)
	}
	for _, op := range errored {
		w.Human("  %s%s failed, and replays as that failure: %s%s\n", dim, op,
			failed[op], reset)
	}
	w.Human("  replay it: aertun mcp --twin %s\n", *outAt)
	return nil
}

// sortedOps is the operations a map names, in order.
func sortedOps(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for op := range m {
		out = append(out, op)
	}
	sort.Strings(out)
	return out
}
