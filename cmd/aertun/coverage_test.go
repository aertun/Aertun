// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every capability has to be reachable from the interface people actually use.
//
// This exists because the gap got large without anybody noticing: thirty-nine
// commands on the command line, about ten areas in the admin, and seven tools
// over MCP. Each feature was built, tested and shipped correctly — on one
// surface — and "the GUI comes later" turned out to mean it did not come.
//
// The table below is the answer, and the point is that it is a table. A gap
// with a written reason is a decision; a gap with nothing next to it is an
// oversight, and this test cannot tell them apart unless somebody writes the
// reason down. Adding a command means adding a row, and the row is where you
// notice you have built something nobody can see.
type surfaces struct {
	// GUI is the admin path that reaches this, or empty with a reason.
	GUI string
	// MCP are the operation names this command's capability is reachable
	// through, or empty with a reason in NoMCP. A list because the machine
	// interface is not one-to-one with the command line and pretending it is
	// would mean leaving operations out of the table to make the shape fit.
	MCP []string
	// Why explains a missing screen. Required whenever GUI is empty.
	Why string
	// NoMCP explains why this is not on the machine interface. Required
	// whenever MCP is empty, and required to be a real argument rather than a
	// shrug: this column sat unasserted through the whole first pass, which is
	// how it ended up describing seven operations against thirty-nine
	// commands.
	//
	// The line this project draws: anything that reads, and anything that
	// authors content, belongs on the agent surface. Anything that changes who
	// may do what, what code runs, or what the keys are, does not — because a
	// prompt injection in a page the agent is reading is a plausible route to
	// whatever the agent can call, and "it could grant itself a role" is a
	// sentence nobody should be able to write about their CMS.
	NoMCP string
}

var coverage = map[string]surfaces{
	// Work tracking, and the argument for four states.
	"work": {
		Why: "it builds a board for the run to show what a team's extra " +
			"statuses really were; the boards people use arrive with the " +
			"work, and the argument is one a terminal can make",
		NoMCP: "a model moving work between states and excusing " +
			"requirements would be deciding what counts as finished, " +
			"which is the one judgement a definition of done exists to " +
			"keep with people",
	},

	// Detection rules in the open standard, compiled and reported on.
	"sigma": {
		Why: "it reads rule files from a path and prints what came " +
			"across; the screen for a rule library arrives with the " +
			"library, and an import report is a table",
		NoMCP: "a model that could import rules could import one whose " +
			"exclusion clause it wrote, and a detection nobody reviewed " +
			"is the failure this package refuses at every other step",
	},

	// Any scanner's findings, and what the scanner left out.
	"sarif": {
		Why: "it reads a file a scanner produced and prints what came " +
			"across; the queue these alerts land in is internal/appsec's " +
			"and has its own screen, and an import report is a table",
		NoMCP: "a tool here would let a model hand this program a set of " +
			"findings, and a findings queue whose contents nobody can " +
			"trace to a scanner run is not evidence of anything",
	},

	// Which dependencies are affected, and which anybody can fix.
	"sca": {
		Why: "it reads a bill and an advisory file from a path; the queue " +
			"these land in is internal/vuln's and has its own screen, " +
			"and the thing worth seeing here — what is a bump and what " +
			"is a conversation — is a list",
		NoMCP: "a tool here would let a model supply the bill, and an " +
			"inventory nobody can trace to a build is not evidence of " +
			"what is deployed",
	},

	// Detections about several events, and when a window may close.
	"correlate": {
		Why: "it runs correlations over events built for the run to show " +
			"what a clock-closed window loses; the alerts these produce " +
			"land in internal/finding, which has its own screen",
		NoMCP: "a correlation decides what several events mean together, " +
			"and a model that could write one could write the window that " +
			"never closes",
	},

	"pending": {GUI: "/people",
		NoMCP: "every change waiting here makes somebody more powerful or hides what they did; " +
			"a model proposing or approving one is a model deciding who may do what"},
	"incident": {GUI: "/security/cases", MCP: []string{"incident_status"},
		Why: "an agent reads which clocks are running and which nobody " +
			"has started; the decisions that start them are a person's",
	},

	// How old the databases a scanner compares against are.
	"feed": {
		Why: "it shows the freshness of mirrors built for the run; the " +
			"real ones arrive with the fetching, and what is worth " +
			"seeing — which feed is behind and whose problem it is — is " +
			"a table",
		NoMCP: "this decides whether a clean scan can be read as a clean " +
			"scan, and a model adjusting a feed's cadence would be " +
			"adjusting what counts as current",
	},

	// What a fetched log record means, per platform.
	"source": {
		Why: "it lists the mappings and checks one against records a " +
			"caller supplies; the events these produce land in " +
			"internal/telemetry, which has its own screen",
		NoMCP: "a mapping decides what an event means, and a model " +
			"editing one could make a stream of failures look like a " +
			"quiet day",
	},

	// What a code scanner found, and the part it left undone.
	"appsec": {
		Why: "it reads a scanner's output and gates a change, which happens " +
			"in a pipeline rather than on a screen; the screen arrives " +
			"with the stored register",
		NoMCP: "the queue names credentials found in source by their " +
			"location, and a model with a tool here has a list of where " +
			"the secrets are",
	},

	// Access reviews, closed by a later import rather than by the
	// reviewer.
	"access": {
		Why: "the campaign is driven from an import and closed by another " +
			"one; the screen arrives with the stored register, where an " +
			"unremediated revocation belongs beside every other finding",
		NoMCP: "whether somebody still needs an access is a question about " +
			"what they do all day, which is the one thing a model cannot " +
			"see; Decision.Validate refuses an AI reviewer for that reason",
	},

	// Third parties, tiered by what they reach.
	"vendor": {
		Why: "the register is compared against the connector manifests, " +
			"which are files an operator reviews at a terminal; the screen " +
			"arrives with the stored register, where a lingering " +
			"credential belongs at the top of the same queue",
		NoMCP: "this register says which third parties hold credentials in " +
			"this estate and what each can reach, which is the shape of a " +
			"target list; a model with a tool here has it too",
	},

	// The vulnerability queue, read from an inventory and a set of
	// advisories that a connector or a scanner produces.
	"analyst": {GUI: "/findings",
		Why: "its suggestions are shown on each finding's page, where a " +
			"person agrees with them or not",
		NoMCP: "it is the agent. A model starting the analyst is a model " +
			"starting a model, with nobody in the loop to have asked for it",
	},

	// The open benchmark of the analyst's first pass: the labelled corpus,
	// the metrics over it, and the document a run produces.
	"bench": {
		Why: "a benchmark's results are terminal output and documents that " +
			"carry their own digests, compared run against run by the " +
			"people who changed the analyst between them; the screen worth " +
			"building is the trend over runs, which arrives when there are " +
			"runs to trend",
		NoMCP: "measuring the analyst is not an operation an agent " +
			"performs: an agent invoking the benchmark would be the thing " +
			"being measured spending the model budget to measure itself, " +
			"and a document an agent generates about its own performance " +
			"is the one nobody should be able to hand somebody",
	},

	// Breach simulation by replay: scripted malicious-agent sessions spliced
	// into a recorded stream, scored against the reference pack, sealed and
	// signed.
	"windtunnel": {
		Why: "a scorecard is a document that carries its own digest and two " +
			"signatures, read the way a benchmark's results are read — by " +
			"the people deciding whether the detections changed between " +
			"runs; the screen worth building is the trend over scorecards, " +
			"which arrives when there are scorecards to trend",
		NoMCP: "running an attack simulation is not an operation an agent " +
			"performs: an agent firing the wind tunnel would be the thing " +
			"under test choosing what gets tested, and a scorecard an " +
			"agent generates about the controls that watch it is the one " +
			"nobody should be able to hand somebody",
	},
	// Proofs: a claim about a detection checked against evidence its author
	// did not write, and signed whatever the verdict.
	"proof": {
		Why: "a proof is a file that carries its own signatures and is " +
			"checked where the work is used — in CI, by a reviewer, by " +
			"whoever was handed the rule; the screen worth building is the " +
			"ledger of proofs per author, which arrives when agents submit " +
			"claims through the store rather than the command line",
		NoMCP: "the first cut signs with a key file named on the command " +
			"line, and an MCP server must never hold a signing key on a " +
			"caller's behalf; agents will submit claims to a queue the " +
			"store's own key signs from, with the claim's author recorded",
	},
	// The forge: what the analyst saw and answered, and how a person ruled,
	// as signed training episodes.
	"forge": {
		Why: "an export is a signed file made for a training run somewhere " +
			"else and checked where it is used; its record is in the audit " +
			"log, which has its own screen, and the suggestions it is made " +
			"from are already on each finding's page",
		NoMCP: "exporting the analyst's record is not an operation an agent " +
			"performs: a model choosing what goes into the next model's " +
			"training set is the thing being trained choosing its own " +
			"lessons, and the export signs with a key file named on the " +
			"command line, which an MCP server must never hold on a " +
			"caller's behalf",
	},
	"action": {GUI: "/security/cases",
		Why: "an action is asked for and approved on the incident's page; " +
			"installing one and giving it a credential are the operator's",
		NoMCP: "it changes something in another tool, on somebody's " +
			"account. A model takes no part: it neither installs one, asks " +
			"for one, nor approves one",
	},
	"identity": {GUI: "/security/entity/",
		Why: "a person's page shows every identifier known to be theirs; " +
			"saying whose one is happens once, by the operator",
		NoMCP: "whose an identifier is decides whose activity is whose. A " +
			"model that could say it could make one person's activity " +
			"count as another's",
	},
	"collect": {GUI: "/security/events",
		Why: "what each source sent and when is on the Events screen; " +
			"installing a connector and a schedule are the operator's",
		NoMCP: "it reads other tools with stored credentials. A model " +
			"deciding when that happens is a model spending those " +
			"credentials",
	},
	"intel": {GUI: "/security/indicators",
		Why: "what an indicator found is a finding, and findings are " +
			"what an agent reads",
		NoMCP: "adding an indicator raises findings about whoever touched " +
			"it, so a model that could add one could accuse anybody; and " +
			"the list itself is other people's infrastructure, which a " +
			"model has no use for that the findings do not serve",
	},
	"vuln": {GUI: "/security/vulns", MCP: []string{"vuln_plan"},
		Why: "an agent reads the plan and the counts; deciding that " +
			"something does not apply stays a person's, and " +
			"Assessment.Validate refuses an AI author",
	},

	// One reviewable file per tool, and the credentials to reach them.
	"connect": {
		Why: "a connector manifest is reviewed by reading it and a " +
			"credential is set from the environment; a screen that edited " +
			"either would be a screen that could point this program at a " +
			"host nobody approved",
		NoMCP: "this is the component that holds credentials to every " +
			"system the company uses, which is exactly what was stolen in " +
			"the Drift compromise; a model with a tool here has them too",
	},

	// The tools' records joined, and where they disagree.
	"estate": {GUI: "/workforce", MCP: []string{"estate_summary"},
		Why: "an agent gets the numbers — bands, areas, trend, what could " +
			"not be checked — and never the people; the findings it raised " +
			"are read one at a time through list_findings"},

	"remind": {GUI: "/workforce/reminders",
		NoMCP: "it sends a message to every employee with something " +
			"outstanding, and to their managers; an agent able to do that " +
			"can send whatever it was talked into to the whole company"},

	// Reconciling people and devices across systems, from a file of
	// normalised identities.
	"workforce": {
		Why: "it reads an export and reports what the join could and could " +
			"not do; the screen arrives with the connectors that produce " +
			"those exports on a schedule, rather than with the join",
		NoMCP: "a model that can merge two people can merge the auditor " +
			"into the intern; Link.Validate refuses an AI assertion, and a " +
			"tool that could only propose would be a tool whose one useful " +
			"call is the one it may not make",
	},

	// The contact list, the notices and what was delivered.
	"notify": {
		Why: "the contact list is personal data and the suppression list " +
			"is a list of people who asked to be left alone; neither goes " +
			"in the store a web process serves, so the screen arrives with " +
			"the customer-facing inbox rather than with the operator's side",
		NoMCP: "a notice is the organisation speaking to its customers and " +
			"to a regulator, and Notice.Validate refuses an AI author for " +
			"that reason; a model may draft one and a person sends it",
	},

	// The event store. A screen over it is the analyst surface the whole
	// SIEM half needs, and it arrives with querying rather than with storage.
	"spool": {
		GUI: "/security/events",
		Why: "storing and retaining events is an operator's job at a " +
			"terminal; the screen arrives with the query surface that " +
			"reads the store, not with the store",
		NoMCP: "a model that can run retention can delete the evidence of " +
			"what it did, and a hold it can lift is not a hold",
	},

	"automate": {
		GUI: "/security/automations",
		NoMCP: "rules decide what is done to people's sessions and accounts; " +
			"changing them, or approving what they wait for, is a person's job",
	},

	// The data-protection surface: one person's whole history as a document,
	// and the posture statement that makes the append-only design defensible.
	// The export is personal data by definition — the complete set of it this
	// store holds about one person — so it is made by a person at a terminal
	// and handed over, the same reasoning that keeps the notify contact list
	// out of the store a web process serves.
	"privacy": {
		Why: "the export is a document a data-protection officer hands over, " +
			"made on request at a terminal; the statement is facts the " +
			"settings screen already shows, in the words a regulator reads",
		NoMCP: "one person's entire history across every source is the most " +
			"sensitive view this store can produce; an agent handed it for " +
			"anybody's name is a surveillance tool wearing a data-protection " +
			"badge",
	},
	"inbound": {
		GUI: "/security/feeds",
		NoMCP: "a feed decides whose word reaches the automations; adding one, " +
			"or handing a transmitter a stream, is a person's decision",
	},
	"geo": {
		GUI: "/security/signins",
		NoMCP: "where sign-ins are said to come from decides which of them are " +
			"stepped up; a model must not be able to name a network an office",
	},
	"telemetry": {
		Why: "it checks a file a connector produced, at the point where " +
			"there is no connector yet and nothing in the store to look at",
		NoMCP: "an agent reading unvalidated telemetry is the thing the " +
			"validation exists to prevent",
	},
	"scim": {
		GUI: "/provisioning",
		NoMCP: "provisioning decides who holds which role, and its token " +
			"is a credential; both are an administrator's to handle",
	},

	"finding": {
		GUI: "/findings",
		// Read, and propose. A decision stays off this surface: a model that
		// can close its own findings can close the one that would have
		// caught it, and Decision.Validate refuses an AI actor besides.
		MCP: []string{"list_findings", "read_finding", "propose_finding_decision"},
	},

	// Detections over exported events, ranked. The screen and the agent
	// surface both come once findings are stored rather than computed per
	// run, which is the next piece rather than this one.
	"triage": {
		GUI: "/findings",
		MCP: []string{"list_findings"},
	},

	// Stacking over a file somebody exported, at the point where they are
	// looking for something and do not yet know what.
	"hunt": {GUI: "/security/hunt",
		Why: "the command stacks a file the analyst chose; the screen " +
			"stacks the store, where the events are",
		NoMCP: "an agent given the rarity list is given the map of what is " +
			"least likely to be noticed",
	},

	// Detections are reviewed, versioned and diffed, so they live in a
	// repository and the tooling is a command. `detect test` runs in CI on
	// every change, which a screen cannot.
	"detect": {GUI: "/security/detections", MCP: []string{"detection_stats"},
		Why: "a rule is reviewed and diffed like code, so it is tested in " +
			"the repository; the screen shows what each has been worth and " +
			"moves rings and suppressions. An agent reads the numbers and " +
			"the proposals and changes neither: one that could quieten a " +
			"detection could quieten the one that would have caught it"},

	// The signed content plane: detection packs as data, on their own
	// cadence, verified before anything moves. Detections are data files
	// administered on disk — built and signed at a terminal, arrived by
	// file — and the screen for them is the update flow the roadmap
	// schedules next (the Today-screen content line), not this slice.
	"content": {
		Why: "packs are data files administered on disk: signed where they " +
			"are built and installed from a directory somebody delivered, " +
			"and the audit log is the record of both. The screen arrives " +
			"with the scheduled update checking and its staleness " +
			"reporting, which is the next slice rather than this one",
		NoMCP: "installing content changes what every detection says and " +
			"signing it spends a key this store holds, so a model with a " +
			"tool here could ship rules past the review the rules " +
			"repository exists to be; the one thing an agent may do is " +
			"read, and `aertun content verify` at a terminal answers " +
			"anything it would have asked"},

	"approvals": {GUI: "/approvals",
		NoMCP: "what waits is decided by a person, and an app reading the queue " +
			"of approvals is a model reading what it and others are waiting to " +
			"have approved; the machine interface answers none of it either"},
	"network": {GUI: "/settings",
		NoMCP: "what this deployment may connect to is the boundary an " +
			"isolated network is built on, and a model that could read it " +
			"could tell you which purpose is still permitted — a shape of " +
			"reconnaissance this surface should not answer"},

	"auditlog": {GUI: "/logs", NoMCP: "holds who did what across everybody, pseudonymously; an agent is not handed everybody's record"},
	// The NIST mapping and the evidence packs generated from the signed log.
	// A pack is a document an operator hands to an assessor: generated at a
	// terminal, verified from its file, and never a live surface. The screen
	// that would earn one is the CSF 2.0 / AI RMF roll-up computed from the
	// mapping and these same queries,
	// which is the next slice rather than this one.
	"compliance": {
		Why: "the pack is a document an assessor takes away, generated from " +
			"the signed log and checked from its file; the screen arrives " +
			"with the framework roll-up the mapping feeds, not with the " +
			"mapping",
		NoMCP: "an evidence pack is the audit log opened to a third party, " +
			"pseudonymised but whole for its control; an agent handed this " +
			"is handed everybody's record, which is the line drawn for " +
			"auditlog",
	},
	"config": {GUI: "/settings", NoMCP: "changes the security floors. An agent that can widen a limit can widen the limit that was stopping it"},
	"auth":   {GUI: "/people", NoMCP: "grants roles. Nothing that decides who may do what belongs on this surface"},
	"token":  {GUI: "/people", NoMCP: "mints credentials, for the same reason"},
	// The agent register is read through the surfaces it feeds: an agent
	// and its owner sit with the credentials on /people, and every change
	// to the register is in the log with its reason. A page of its own
	// arrives with the review campaign the AC-2 story needs, where the
	// register is the thing being reviewed.
	"agent": {
		Why: "the registry is read through the people and audit surfaces it " +
			"feeds — owners beside the credentials on /people, changes in " +
			"the log with their reasons; a page of its own arrives with the " +
			"access review that reviews it",
		NoMCP: "this surface decides which agents exist and what each may " +
			"call; a model that could register or disable one would be " +
			"deciding who may act, and the one call this surface must not " +
			"answer is a model un-killing itself",
	},
	"oidc": {GUI: "/sso", NoMCP: "points sign-in at an identity provider; changing it changes who can become an administrator"},
	"saml": {GUI: "/sso", NoMCP: "trusts an identity provider's key, and whoever holds that key can sign anybody in as anybody; that is a person's decision, made by checking a fingerprint"},
	// The kill switch's outward half: receivers are a setting shown on the
	// Settings screen, and every push (or failure to push) is in the audit
	// log under ssf.transmitted. A screen of its own arrives with delivery
	// status and retry, which is the stream half of the same framework.
	"ssf": {GUI: "/settings",
		NoMCP: "this tells other platforms this organisation killed an agent, " +
			"in a form their automations act on; a model deciding when partners " +
			"are told is a model spending trust in this deployment's name, and " +
			"a re-announced kill is a claim about this store"},
	"vault": {Why: "the key is shown once, where a person types the command, and the console never holds it",
		NoMCP: "handles key material"},
	"siem": {GUI: "/settings", NoMCP: "exports the audit log and can be asked to reveal identifiers"},

	// -- deliberately not in the interface either -----------------------------
	"init": {Why: "creates the store, which is what you do before there is an " +
		"interface to open",
		NoMCP: "creates the store an agent would already have to be connected to"},
	"serve": {Why: "starts the interface; a button inside it could not",
		NoMCP: "starts a server"},
	"logd": {Why: "runs as another account and must not be startable from this one",
		NoMCP: "runs as another account"},
	"mcp": {Why: "is the machine interface; it does not appear inside itself",
		NoMCP: "is this surface"},
	// The command lists every command; the console's Find screen and the
	// find operation find a screen by words.
	"help":      {GUI: "/find", MCP: []string{"find"}},
	"version":   {Why: "prints a version", NoMCP: "prints a version"},
	"--version": {Why: "prints a version", NoMCP: "prints a version"},
	"-V":        {Why: "prints a version", NoMCP: "prints a version"},
	"-h":        {Why: "prints usage", NoMCP: "as help"},
	"--help":    {Why: "prints usage", NoMCP: "as help"},
}

// Every dispatched command must appear, with a route or a reason.
func TestEveryCommandIsReachableOrExplained(t *testing.T) {
	cmds := dispatchedCommands(t)
	if len(cmds) < 30 {
		t.Fatalf("found only %d commands; the parse is wrong and a test that "+
			"sees nothing passes", len(cmds))
	}
	var undeclared []string
	for _, c := range cmds {
		s, ok := coverage[c]
		if !ok {
			undeclared = append(undeclared, c)
			continue
		}
		if s.GUI == "" && strings.TrimSpace(s.Why) == "" {
			t.Errorf("%q has no admin route and no reason. Either add the "+
				"screen or write down why it does not need one — an "+
				"unexplained gap is indistinguishable from an oversight, "+
				"which is how this one got to twenty-six.", c)
		}
		if len(s.MCP) == 0 && strings.TrimSpace(s.NoMCP) == "" {
			t.Errorf("%q has no MCP operation and no reason. This column was "+
				"in the table and asserted by nothing for a whole pass, which "+
				"is how it came to describe seven operations against "+
				"thirty-nine commands. Add the operation or write down why an "+
				"agent must not have it.", c)
		}
		// A reason has to be an argument. "n/a" and "no" are what somebody
		// writes to make a test go green, and a column full of them is the
		// same as no column — which is what this column was.
		//
		// "as webhook" is allowed, and only when webhook is a row that carries
		// a real reason: an alias should point at the thing it is an alias of
		// rather than repeat its argument and then drift from it.
		if len(s.MCP) == 0 && !isRealReason(s.NoMCP) {
			t.Errorf("%q gives %q as its reason for not being on the machine "+
				"interface, which is not one", c, s.NoMCP)
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		t.Errorf("these commands are dispatched and not in the coverage "+
			"table:\n  %s\nAdding a command means adding a row, which is "+
			"where you notice you have built something nobody can see.",
			strings.Join(undeclared, "\n  "))
	}
}

// Any route the table claims must actually be served, or the table is a
// description of a product that does not exist.
func TestEveryClaimedRouteIsServed(t *testing.T) {
	served := map[string]bool{}
	for _, r := range adminRoutes(t) {
		served[r] = true
	}
	if len(served) < 10 {
		t.Fatalf("found %d admin routes; the parse is wrong", len(served))
	}
	for cmd, s := range coverage {
		if s.GUI == "" {
			continue
		}
		if !served[s.GUI] {
			t.Errorf("%q claims the admin serves %q and it does not",
				cmd, s.GUI)
		}
	}
}

// Any operation the table claims must actually be registered.
//
// The mirror of the route check, and it exists because the MCP column spent a
// whole pass being a description of intentions. A name in this table that no
// call to Register produces is a claim that an agent can do something it
// cannot.
func TestEveryClaimedMCPOperationIsRegistered(t *testing.T) {
	registered := registeredOperations(t)
	if len(registered) < 6 {
		t.Fatalf("found %d MCP operations; the parse is wrong and a test that "+
			"sees nothing passes", len(registered))
	}
	for cmd, s := range coverage {
		for _, op := range s.MCP {
			if !registered[op] {
				t.Errorf("%q claims the MCP server offers %q and nothing "+
					"registers it", cmd, op)
			}
		}
	}
}

// And every registered operation must be in the table.
//
// The other direction, which is the one that catches an operation added to the
// agent surface without anybody deciding it belonged there. An agent surface
// grows by accident more easily than either of the other two, because adding a
// tool is twenty lines and nobody has to draw a screen.
func TestEveryRegisteredMCPOperationIsAccountedFor(t *testing.T) {
	claimed := map[string]bool{}
	for _, s := range coverage {
		for _, op := range s.MCP {
			claimed[op] = true
		}
	}
	var loose []string
	for op := range registeredOperations(t) {
		if !claimed[op] {
			loose = append(loose, op)
		}
	}
	if len(loose) > 0 {
		sort.Strings(loose)
		t.Errorf("these MCP operations are registered and no row in the "+
			"coverage table accounts for them:\n  %s\nEvery capability an "+
			"agent can reach should be one somebody decided it should reach.",
			strings.Join(loose, "\n  "))
	}
}

// The size of the gap, reported rather than asserted.
//
// No threshold, because a number that fails the build would be turned into a
// number that passes it. This prints, so that anybody running the suite sees
// how much of the product is invisible.
func TestReportHowMuchIsNotInTheInterface(t *testing.T) {
	var gaps []string
	for cmd, s := range coverage {
		if strings.HasPrefix(s.Why, "GAP:") {
			gaps = append(gaps, cmd+" — "+strings.TrimPrefix(s.Why, "GAP: "))
		}
	}
	sort.Strings(gaps)
	t.Logf("%d capabilities are not in the admin interface:", len(gaps))
	for _, g := range gaps {
		t.Logf("    %s", g)
	}

	// And the same count for the machine interface, which is deliberately not
	// zero: an agent surface that reaches everything is an agent surface with
	// nothing withheld from a prompt injection.
	var withheld int
	for _, s := range coverage {
		if len(s.MCP) == 0 && s.NoMCP != "" && s.Why == "" {
			withheld++
		}
	}
	t.Logf("%d capabilities are in the interface and withheld from agents, "+
		"each with a reason next to it", withheld)
}

// registeredOperations reads the operation names out of the MCP source.
func registeredOperations(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	// Every mcp*.go rather than a list, so a file of operations added later
	// is read without anybody remembering to add it here — the list form
	// missed mcpsecurity.go on the day it was written.
	files, err := filepath.Glob("mcp*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no MCP sources found: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		for _, m := range reOpName.FindAllStringSubmatch(readFile(t, file), -1) {
			out[m[1]] = true
		}
	}
	return out
}

// The name field of an mcp.Operation literal. Whitespace-insensitive, because
// gofmt aligns struct literals differently depending on what is beside them
// and a fixed-spacing match silently found nine of eighteen operations.
var reOpName = regexp.MustCompile(`(?m)^\s*Name:\s*"([a-z_]+)"`)

// isRealReason rejects a reason that is not one.
//
// Either three words of argument, or a reference to another row — "as
// webhook" — which is how an alias should be written: pointing at the
// argument rather than repeating it and then drifting from it.
func isRealReason(why string) bool {
	fields := strings.Fields(why)
	if len(fields) == 2 && fields[0] == "as" {
		if _, ok := coverage[fields[1]]; ok {
			return true
		}
	}
	return len(fields) >= 3
}

// adminRoutes reads the mux registrations out of the admin package.
func adminRoutes(t *testing.T) []string {
	t.Helper()
	body := readFile(t, "../../internal/admin/server.go")
	var out []string
	for _, line := range strings.Split(body, "\n") {
		i := strings.Index(line, `mux.HandleFunc("`)
		if i < 0 {
			i = strings.Index(line, `mux.Handle("`)
			if i < 0 {
				continue
			}
		}
		rest := line[i:]
		start := strings.Index(rest, `"`) + 1
		end := strings.Index(rest[start:], `"`)
		if end <= 0 {
			continue
		}
		out = append(out, rest[start:start+end])
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A capability hiding inside a flag.
//
// The table above is keyed by command, and that granularity is what let a whole
// operation go missing from the interface for months: removing a page lived at
// `aertun add --remove NAME`, so the row for "add" pointed at /page/ and was
// perfectly true about writing pages while saying nothing about deleting them.
// Every screen test passed, because a capability with no screen has nothing to
// fail on. It was found by building an application and wanting to delete
// something.
//
// Most flags are parameters — a message, an address, an author — and belong to
// whatever their command already covers. The ones that are separate
// capabilities are the ones that take something away, so those are the ones
// asked about here: a flag whose name is a verb of removal has to be reachable
// from the interface, or say why not.
func TestEveryRemovalFlagIsReachableFromTheInterface(t *testing.T) {
	// Where each removal flag lives in the admin, or why it does not.
	removal := map[string]surfaces{
		// Not a removal at all, and it is in this table because its name is
		// a verb of removal and the guard reads names. It records that
		// somebody rewrote a repository's history elsewhere, which is a
		// fact being reported rather than an action being taken: nothing
		// here removes anything, and the credential being dead is what
		// closes the finding either way.
		// Takes away what was said about an asset, which widens its SSVC
		// decisions back to a range.
		// Takes away an agent's program; it then runs only by walking its
		// manifest or with a model.
		"auth enrol.revoke": {
			GUI: "/people",
			NoMCP: "an enrolment link adds a passkey, a way in as a person; a model giving or " +
				"ending one is a model deciding who may sign in",
		},
		"agent program.remove": {
			GUI: "/agents",
			NoMCP: "what runs as an agent, with a run's reach, is an " +
				"administrator's decision, and a model changing what its own " +
				"agent runs is the thing a declaration exists to stop",
		},
		"agent workspace.clear": {
			Why: "emptying an agent's workspace removes what its runs built and is done on the " +
				"machine that holds it, by the operator, with the claim taken so no run is " +
				"working on it; the screen shows each command and its output, not the folder",
			NoMCP: "a model emptying the workspace it works in is the destroying a declaration " +
				"makes wait for a person; it is an operator's step, not an agent's",
		},
		// Taking a tool out of an agent's allowlist narrows what that agent
		// may reach, which is the register's whole lever. Not on a screen
		// for the register's own reason (the row above): it is read through
		// the people and audit surfaces until the review that reviews the
		// register arrives.
		"allow.remove": {
			Why: "narrowing an agent's reach is an operator's decision at the " +
				"register, read back through the people and audit surfaces; " +
				"the screen arrives with the review the register is for",
			NoMCP: "an agent narrowing its own allowlist is the one hand on " +
				"the register this surface must not offer; what an agent may " +
				"call is decided about it, never by it",
		},
		// Taking a host declaration back removes an agent's name from the
		// evidence that host's records carry. Same surface and same argument
		// as the allowlist half beside it: the mapping says whose name joins
		// whose evidence, and that is decided about agents, never by them.
		"maps.remove": {
			Why: "unmapping a host takes an agent's name off the evidence " +
				"that host's records carry, and is an operator's decision at " +
				"the same register, read back through the people and audit " +
				"surfaces like every change to it",
			NoMCP: "the mapping decides whose name joins whose evidence, and " +
				"a model that could edit it could aim its own actions at " +
				"another agent's name; where an agent runs is decided about " +
				"it, never by it",
		},
		"asset.remove": {
			GUI: "/security/vulns",
			NoMCP: "how exposed a machine is and what is lost with it is " +
				"the organisation's judgement; a model removing one " +
				"changes what is urgent without anybody deciding it",
		},
		"budget.remove": {
			GUI: "/models",
			NoMCP: "as gateway: the model route and its limits are " +
				"administrative, and an agent lifting its own budget is the " +
				"thing the budget exists to stop",
		},
		// Removes an action from a chatbot, which only ever narrows what it
		// may offer.
		"action.remove": {
			GUI: "/assistants",
			NoMCP: "what a public chatbot may offer to do is decided by a " +
				"person; the agent surface builds chatbots and does not " +
				"touch their actions",
		},
		"rotated.purged": {
			GUI: "",
			NoMCP: "a model asserting that a credential is dead is how a " +
				"finding gets closed over a key that still works; " +
				"Rotation.Validate refuses an AI author",
			Why: "it records that a history rewrite happened in the " +
				"repository, which this program neither performs nor can " +
				"verify. The screen for it would be a checkbox that " +
				"changes nothing outside this log",
		},
		// Article 17, which outranks the rest of this package's design.
		// An ordinary removal takes the words and leaves the shape; this
		// one takes the words from the log as well, because an obligation
		// to erase is not satisfied by a copy kept for integrity.
		"remove.erase": {
			GUI: "",
			NoMCP: "a model with a tool here could erase what somebody is " +
				"recorded as having said; the author field would stop " +
				"meaning anything",
			Why: "the reading surface arrives with the client, and an " +
				"erasure is requested by a person and performed against a " +
				"named message rather than browsed to",
		},
		"add.remove": {GUI: "/page/delete",
			MCP:   []string{"write_page"},
			NoMCP: ""},
		"focus.clear": {
			// Back to the centre, which is where every picture starts. Not a
			// deletion of anything that was asserted about the world: a focal
			// point is a layout preference, and clearing it restores the
			// default rather than removing a claim.
			GUI: "/media",
			MCP: nil,
			NoMCP: "as media, whose whole surface is off the agent interface " +
				"— and a focal point is a judgement about what matters in a " +
				"photograph, which is the part a model has not made",
		},
		"captions.remove": {
			// No screen, and the reason is that the gate is the interface.
			//
			// Taking the last captions track off a video makes every page
			// showing it unpublishable — the accessibility gate refuses a
			// <video> with no captions at Level A. So this is not a tidying
			// operation somebody reaches for in a list; it is the deliberate
			// undoing of the thing that lets the video be published, and the
			// refusal at the next publish is what tells them so.
			//
			// A screen for attaching captions belongs in the admin and is
			// worth building. A button for removing them, beside a video, with
			// no indication that pressing it stops the site going out, is the
			// version of this feature that should not exist.
			GUI: "",
			Why: "removing the last captions track makes every page showing " +
				"the video unpublishable, so it is a deliberate act at the " +
				"command line rather than a button in a list. Attaching them " +
				"is the operation a screen should carry",
			MCP: nil,
			NoMCP: "as media, whose whole surface is off the agent interface " +
				"— and whether a caption file describes a recording is a " +
				"judgement about the recording, which a model that has not " +
				"watched it has not made",
		},
		"origin.clear": {
			// The provenance screen is where a page's disclosure is set, and a
			// picture's belongs beside it. Clearing is not deletion of a
			// record so much as a correction: a declaration made in error is
			// worse than none, because it is signed into every copy of the
			// picture and read by other people's software as fact.
			GUI: "/provenance",
			MCP: nil,
			NoMCP: "a disclosure is the marking a regulator asks for, and an " +
				"agent that could clear one could quietly unmark " +
				"model-generated media — the same line drawn for licences",
		},
		"shield playbook propose.remove": {
			// A playbook added here is removed from the Shield screen, where
			// it was added, and the removal is a proposal like any other
			// change to what aertun does on its own.
			GUI: "/security/shield",
			MCP: nil,
			NoMCP: "a playbook acts without asking anybody; an agent that could " +
				"remove one could take away a protection the administrators " +
				"put in place, which is the line drawn for access",
		},
		"rights set.clear": {
			// The media screen records rights now, and clearing is the button
			// beside recording. It used to say "there is no rights screen at
			// all", which was true and was the bug: the publish gate refuses a
			// publication over an expired licence, and an editor working in a
			// browser had no field anywhere to answer it with.
			GUI: "/media",
			MCP: nil,
			NoMCP: "a licence is a legal record about what may be published, " +
				"and an agent that could clear one could publish an image " +
				"nobody has permission for — the same line drawn for access " +
				"and keys",
		},
	}

	verbs := regexp.MustCompile(
		`^(remove|delete|drop|purge|erase|revoke|unbind|cancel|clear)`)
	declared := regexp.MustCompile(
		`fs\.(?:String|Bool|Int|Duration|Float64)\("([a-z-]+)"`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]bool{}
	for _, r := range adminRoutes(t) {
		routes[r] = true
	}

	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body := readFile(t, e.Name())
		// The command a flag belongs to is the flag set it was created on,
		// which is named at the NewFlagSet call above it.
		command := ""
		for _, line := range strings.Split(body, "\n") {
			if i := strings.Index(line, `NewFlagSet("`); i >= 0 {
				rest := line[i+len(`NewFlagSet("`):]
				if j := strings.Index(rest, `"`); j > 0 {
					command = rest[:j]
				}
			}
			m := declared.FindStringSubmatch(line)
			if m == nil || !verbs.MatchString(m[1]) {
				continue
			}
			found++
			key := command + "." + m[1]
			s, listed := removal[key]
			if !listed {
				t.Errorf("%s takes something away and is not in the removal "+
					"table.\n  A flag that removes is a capability, not a "+
					"parameter, and the command-level table above cannot see "+
					"it. Add %q with the admin path that reaches it, or a "+
					"written reason there is none.", key, key)
				continue
			}
			if s.GUI == "" {
				if !isRealReason(s.Why) {
					t.Errorf("%s has no interface and no reason worth the name",
						key)
				}
				continue
			}
			if !routes[s.GUI] {
				t.Errorf("%s claims the interface serves %q and it does not",
					key, s.GUI)
			}
		}
	}
	// The guard every source-walking test in this repo needs: one that matches
	// nothing passes forever.
	if found == 0 {
		t.Fatal("no removal flags were found at all, so this test is checking " +
			"nothing — the pattern has stopped matching the source")
	}
}

// A command nobody can find is a command nobody has.
//
// `aertun demo` shipped working, declared its privilege, sat in the coverage
// table with a screen and a reason — and was absent from the help text, so the
// only way to discover it was to read the dispatch switch. Every check above
// passed, because each of them asks whether a command is *declared* somewhere
// and none of them asks whether a person could find it.
//
// The help output is the index of this program. A command missing from it is
// missing, whatever the tables say.
func TestEveryCommandAppearsInTheHelp(t *testing.T) {
	help := readFile(t, "main.go")
	// The help text is a raw string literal in main.go, and every line in it
	// begins "  aertun ". Reading the source rather than running the command
	// keeps this a source check like the others around it.
	listed := map[string]bool{}
	for _, line := range strings.Split(help, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "aertun ") {
			continue
		}
		rest := strings.TrimPrefix(line, "aertun ")
		if i := strings.IndexAny(rest, " \t"); i > 0 {
			rest = rest[:i]
		}
		listed[rest] = true
	}
	if len(listed) < 30 {
		t.Fatalf("only %d commands were found in the help text; the parse is "+
			"wrong and a test that reads nothing passes", len(listed))
	}

	// Aliases are read out of the dispatch switch rather than listed here.
	// `case "records", "record":` makes the second an alias of the first, and
	// help rightly documents one of them. A hand-written list would need
	// maintaining and would quietly excuse the next real omission that happened
	// to be added to it.
	alias := aliasesOf(t)

	// Self-referential, and the only entries excused. A person reading `aertun
	// help` has already found help.
	selfEvident := map[string]bool{"help": true, "-h": true, "--help": true}

	for _, c := range dispatchedCommands(t) {
		if listed[c] || selfEvident[c] {
			continue
		}
		if primary, is := alias[c]; is && listed[primary] {
			continue
		}
		t.Errorf("%q is dispatched and does not appear in `aertun help`. "+
			"The only way to find it is to read the source, which means it "+
			"ships for nobody.", c)
	}
}

// aliasesOf maps every secondary name in a dispatch case to the first one.
func aliasesOf(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	re := regexp.MustCompile(`case ("[a-z-]+"(?:, "[a-z-]+")+):`)
	for _, m := range re.FindAllStringSubmatch(readFile(t, "main.go"), -1) {
		names := regexp.MustCompile(`"([a-z-]+)"`).FindAllStringSubmatch(m[1], -1)
		for _, n := range names[1:] {
			out[n[1]] = names[0][1]
		}
	}
	return out
}

// State that two processes share must be written atomically.
//
// The admin and the site are separate processes over one store. os.WriteFile
// truncates and then writes, so a reader landing in that window gets a parse
// error rather than stale data — and a store whose token file will not parse is
// correctly treated as one nobody may write to, so the site refuses to start.
// Starting both together reproduced it; under load it would not be rare.
//
// A source check rather than a behavioural one, because the failure is a race
// and the next writer somebody adds will be correct by inspection or not at all.
func TestSharedStateIsWrittenAtomically(t *testing.T) {
	// Files both processes read. Anything here must go through atomicfile.
	shared := []string{
		"tokensPath", "policyPath", "configPath", "envsPath", "extPath",
		"menuPath", "listingPath", "vocabPath", "formsPath", "provPath",
		"storePath",
	}
	// Writes that are not shared state, each with the reason.
	//
	// The compliancecmd.go row this table carried was stale from the project
	// this one grew out of: no such file existed here and nothing in this
	// program writes an SBOM (`sca` and `vuln import` read one), so the row
	// described a file nobody could have written. Removed rather than
	// repurposed — this program's compliance command writes an evidence pack
	// to an operator-named path and touches none of the shared state above,
	// which needs no exemption the way privacycmd.go and sarifcmd.go need
	// none.
	exempt := map[string]string{
		"democmd.go":   "writes a template and a stylesheet, once, into a new directory",
		"main.go":      "renders a page to a file the operator named",
		"auditlog.go":  "the audit key and its directory marker, written once at setup",
		"timestamp.go": "writes a token or a root to a path the operator named",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body := readFile(t, e.Name())
		for _, line := range strings.Split(body, "\n") {
			if !strings.Contains(line, "os.WriteFile(") {
				continue
			}
			found++
			if _, ok := exempt[e.Name()]; ok {
				continue
			}
			for _, p := range shared {
				if strings.Contains(line, p+"(") {
					t.Errorf("%s writes %s with os.WriteFile, which truncates "+
						"before it writes. The other process reads this file, "+
						"and half a document is a parse error rather than old "+
						"data. Use atomicfile.Write.", e.Name(), p)
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("no os.WriteFile calls were found at all; the pattern has " +
			"stopped matching and this test is checking nothing")
	}
}
