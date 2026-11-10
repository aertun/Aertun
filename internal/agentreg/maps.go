// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentreg

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
)

// The recorder-host to agent mapping: which registered agents an operator
// says run on which recorder host. It is what the watch-then-call chain was
// refused for wanting (the end-of-file comment in the pack's correlations),
// and it is deliberately a declaration rather than an inference — the
// collector's evidence says a file changed on a host and never who changed
// it, and no program in the middle of that can close the gap. An operator
// who runs the estate can, by saying "build01 runs watcher", and that is
// what this file holds: their word, on the record, changeable.
//
// A sibling file to agents.json rather than rows inside it, because the
// registry is the IA-9 review object — who exists, who owns each one, what
// each may call — and a host column is not about who may act but about
// where evidence comes from. Folding it in would make every review of the
// register read past a field no gate consults, and would tie the register's
// tests to a shape that changes on a different cadence: agents are
// registered once and reviewed quarterly, hosts are mapped as recorders are
// onboarded. The discipline is the registry's own either way — one JSON
// document, changed whole under its lock, absent means empty, unreadable
// means refused.

// MaxAgentsPerHost caps how many registered agents one host may be declared
// to run. Four, because a shared CI box is a fact — a build runner with a
// watcher and a triage bot and a docs generator on it is a machine somebody
// can describe in one sentence — and an unbounded mapping is not a
// description but an inference nobody wrote: a host "running" forty agents
// is a host where somebody mapped a fleet instead of saying which machines
// it lives on. Refused past the cap rather than warned, so the mapping stays
// the length of a sentence somebody would actually say out loud.
const MaxAgentsPerHost = 4

// maxHostLen is the length of a host name this will hold. DNS caps one at
// 253 octets, and a host string longer than that is not a host name any
// recorder will report, so it is a paste that went wrong.
const maxHostLen = 253

// validHost says whether s could be a recorder host: one token, no
// whitespace, no control characters, and no longer than a host name is.
// Deliberately not the DNS letter set — os.Hostname reports what the
// machine was named, underscores and all, and a mapping that could not say
// the machine's own name back would be a mapping that never matches.
func validHost(s string) bool {
	if s == "" || len(s) > maxHostLen {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// HostMap is one host's declared agents: the whole of what the operator
// said about that machine.
type HostMap struct {
	Host   string   `json:"host"`
	Agents []string `json:"agents"`
	// ChangedAt and ChangedBy are the last hand on the declaration. The
	// audit log holds every change; these hold whose word the current one
	// is, so a person reading the file can ask the person who wrote it.
	ChangedAt time.Time `json:"changed_at"`
	ChangedBy string    `json:"changed_by"`
}

// mapsFile is the stored document. A list sorted by host, so the file reads
// like the fleet it describes and diffs like a declaration rather than a
// cache.
type mapsFile struct {
	Maps []HostMap `json:"maps"`
}

// MapStore is the mapping as one JSON document at Path, changed whole under
// its lock like the registry beside it. Registry names the registry file the
// mapping refuses names against: a mapping that declared an agent nobody
// registered would attribute evidence to a name no gate has ever heard of,
// which is a guess wearing a declaration's clothes.
type MapStore struct {
	Path     string
	Registry string
}

// Load reads the mapping. An absent file is an empty mapping — every host
// unmapped, which is the fail-closed answer to "whose agents run here":
// nobody said. A file that cannot be parsed is an error, not an empty
// mapping, for the same reason the registry refuses unreadable rather than
// forgetting everybody: a declaration that cannot be read cannot be
// reviewed, and the honest time to say so is when it is read.
func (s MapStore) Load() ([]HostMap, error) {
	b, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f mapsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Path, err)
	}
	sort.Slice(f.Maps, func(i, j int) bool { return f.Maps[i].Host < f.Maps[j].Host })
	return f.Maps, nil
}

// AgentsFor returns the agents declared for one recorder host, folding case
// the way host names compare: a recorder that says BUILD01 and a mapping
// that says build01 are the same machine, and treating them as two is not
// precision, it is a silent miss — the event stores with nothing declared
// and nobody is told why. A host nothing declares maps to nothing.
func AgentsFor(maps []HostMap, host string) []string {
	for _, m := range maps {
		if strings.EqualFold(m.Host, host) {
			return m.Agents
		}
	}
	return nil
}

// Hosts returns the hosts an agent is declared to run on, sorted. The
// listing half of the register's own review: where each agent lives.
func Hosts(maps []HostMap, agent string) []string {
	var out []string
	for _, m := range maps {
		if contains(m.Agents, agent) {
			out = append(out, m.Host)
		}
	}
	sort.Strings(out)
	return out
}

// find returns the host row's place in the file, case folded, or -1.
func (f *mapsFile) find(host string) int {
	for i := range f.Maps {
		if strings.EqualFold(f.Maps[i].Host, host) {
			return i
		}
	}
	return -1
}

// Map declares that an agent runs on a host. Refuses a host that could not
// be a host, an agent the registry does not hold, the same declaration
// twice, and a fifth agent on a host that already declares four — each
// refusal a sentence, because a mapping an operator cannot fix is one they
// delete.
func (s MapStore) Map(host, agent, by string, now time.Time) error {
	host = strings.TrimSpace(host)
	if !validHost(host) {
		return fmt.Errorf("%q is not a host name: one token, no spaces, no "+
			"longer than a host name is. Say the host the way the recorder "+
			"reports it (its config or its own os.Hostname), or the mapping "+
			"matches nothing forever", host)
	}
	if !ValidName(agent) {
		return fmt.Errorf("%q is not an agent name: 2 to 40 lowercase letters, "+
			"digits and hyphens", agent)
	}
	return atomicfile.Update(s.Path, func(f *mapsFile) error {
		// The registry is read inside the update so the refusal cannot race
		// an unregister: between the check and the write, the agent the
		// mapping names has to still be one the register holds.
		reg := Store{Path: s.Registry}
		if _, found, err := reg.Get(agent); err != nil {
			return err
		} else if !found {
			return fmt.Errorf("there is no agent %q to map (aertun agent "+
				"list): a mapping may only name registered agents, because "+
				"evidence attributed to a name nobody registered is "+
				"attributed to nobody the gates have ever heard of", agent)
		}
		i := f.find(host)
		if i < 0 {
			f.Maps = append(f.Maps, HostMap{Host: host, Agents: []string{agent},
				ChangedAt: now, ChangedBy: by})
			return nil
		}
		row := &f.Maps[i]
		if contains(row.Agents, agent) {
			// Refused rather than answered as done, for the same reason a
			// second disable is: an operator told "mapped" twice may believe
			// a second host was named when the first was named again.
			return fmt.Errorf("%s is already declared to run on %s", agent, row.Host)
		}
		if len(row.Agents) >= MaxAgentsPerHost {
			return fmt.Errorf("%s already declares %d agents (%s) and the cap is "+
				"%d. A shared box is a fact; a mapping that grows past the "+
				"machines somebody can describe in a sentence is an "+
				"inference nobody wrote — say which of these does not belong "+
				"here, or give this fleet its own host", row.Host,
				len(row.Agents), strings.Join(row.Agents, ", "), MaxAgentsPerHost)
		}
		row.Agents = append(row.Agents, agent)
		sort.Strings(row.Agents)
		row.ChangedAt, row.ChangedBy = now, by
		return nil
	})
}

// Unmap takes a declaration back. Removing the last agent takes the host's
// row with it — a host declared to run nothing and a host never mapped are
// the same machine, and a row that lingered empty would say "somebody was
// here" about a mapping that no longer says anything. What changed is in
// the audit log, which is the record; this file is the current word only.
func (s MapStore) Unmap(host, agent, by string, now time.Time) error {
	return atomicfile.Update(s.Path, func(f *mapsFile) error {
		i := f.find(strings.TrimSpace(host))
		if i < 0 || !contains(f.Maps[i].Agents, agent) {
			return fmt.Errorf("%s is not declared to run on %s, so there is "+
				"nothing to unmap (aertun agent list says what is)", agent,
				strings.TrimSpace(host))
		}
		rest := drop(f.Maps[i].Agents, agent)
		if len(rest) == 0 {
			f.Maps = append(f.Maps[:i], f.Maps[i+1:]...)
			return nil
		}
		f.Maps[i].Agents = rest
		f.Maps[i].ChangedAt, f.Maps[i].ChangedBy = now, by
		return nil
	})
}
