// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Command aertun is security operations for the systems an organisation
// runs: collection, detection, cases, response and vulnerability
// management, with the command line, the console and the agent interface in
// one binary. Every action is on the command line, so a person, a script and
// an agent reach the same things.
package main

import (
	"errors"
	"fmt"
	"github.com/aertun/aertun/internal/egress"
	"os"
	"strings"

	"github.com/aertun/aertun/internal/out"
)

const defaultRoot = ".aertun"

// Colours are resolved at startup from whether stdout is a terminal, so piping
// or capturing output yields clean text. They were unconditional constants
// before, which put escape codes into every captured demo in this project's
// own history.
var (
	bold, dim, green, yellow, red, reset string
	w                                    *out.Writer

	// flagToken holds a --token given anywhere on the command line.
	//
	// Set by the global pass in main, which also removes it, so every
	// subcommand accepts it and none has to declare it. Read through
	// tokenFromArgs so the one authorisation call site did not have to change.
	flagToken string
)

func overrideNote(forced bool, reason string) string {
	if !forced {
		return ""
	}
	return reason
}

// errBlocked marks a refusal by a gate rather than a failure of the command.
type errBlocked struct{ error }

func (e errBlocked) Unwrap() error { return e.error }

// errUsage marks a command that cannot do its job with what it was handed
// — the arguments, or the files they name. Kept distinct from a plain
// failure because a caller branching on exit status must be able to tell
// "the command was wrong" from "the command ran and found something":
// diff's CI contract is 0 clean, 1 regression, 2 not runnable, and the
// plain failure code belongs to the middle one.
type errUsage struct{ error }

func (e errUsage) Unwrap() error { return e.error }

var version = "dev"

func usage() {
	fmt.Print(`aertun — the wind tunnel for AI agents

  aertun init [--owner NAME]               create a store, and its Owner
  aertun serve [--addr HOST:PORT]          the console, on loopback by default
  aertun mcp [--list]                      the agent interface, over stdio

Collecting what happens
  aertun connect catalogue | list          the connectors that ship, and those installed
  aertun connect add NAME [--region R]     install a shipped connector as a readable file
  aertun connect secret NAME               store a credential, from the environment
  aertun connect check NAME|FILE           read a manifest and say what it may touch
  aertun connect probe NAME ENDPOINT       what shape a tool's response is, never its values
  aertun connect run NAME [ENDPOINT] [--save]   pull records, one JSON object per line
  aertun collect run [SOURCE]              read each platform's new log records, map them, store them
  aertun collect file ISSUER/STREAM FILE   the same for a log that arrives as a file
  aertun collect status | auto 15m|off     what each source did last, and the schedule
  aertun source list | add MAPPING.json --sample RECORDS.json | check --source S RECORDS.json
  aertun telemetry check [FILE] | fields [FILE]   can a source's events be used, and what a rule may name
  aertun inbound list | add okta|webhook|ssf|quilzo NAME | connect NAME | verify NAME | status NAME
  aertun inbound rotate NAME | on NAME | off NAME | remove NAME | help
  aertun spool add [FILE] | stats | verify | retain [--apply] | hold NAME --why W | lift NAME
  aertun identity list | link ISSUER:VALUE PERSON@… | unlink ISSUER:VALUE

Detecting and deciding
  aertun detect test | list | fields | run [--rules DIR] | stats | pack [install]
  aertun detect ring RULE live|trial|off --because "…"   move a rule in or out of the queue
  aertun detect suppress RULE FIELD=VALUE --owner W --until DATE --because "…" | unsuppress ID | suppressions
  aertun detect replay [--strict] | learn FINDING
  aertun content keygen | rotate-root | sign DIR | verify DIR | install DIR | list [DIR] | installed | rollback
                                        signed detection packs, updated without a binary release
  aertun sigma import ./rules              bring your own detections, in the open standard
  aertun correlate demo                    detections about several events, and when a window closes
  aertun triage [FILE] --rules DIR         run the rules, rank what they found
  aertun hunt --field F [FILE]             what is rare, which is what is worth a look
  aertun finding list [--state S --kind K] | risk | decide ID STATE | story [ID]
  aertun intel import FILE --source NAME | add VALUE --source NAME | list | remove ID
  aertun analyst plan | triage [--limit N] [--dry-run] | eval [--k 3]
  aertun bench run [--stub] [--out F] [--k N] | report FILE   the labelled corpus, and how the analyst scored on it
  aertun windtunnel run --sigma DIR [--mutate N] [--out F]   replay agent attacks against your own Sigma rules: the primary mode
  aertun windtunnel run --score reference | list-scenarios | preflight | scorecard | diff OLD NEW | verify   the shipped pack, self-graded; signed only in CI; diff is the CI gate
  aertun proof detection --rule F [--corpus F] --key F | verify FILE --key F   a rule checked against evidence its author did not write, signed; verify is the CI gate
  aertun automate list | templates | add TEMPLATE | runs   rules: when this happens, do this
  aertun automate mode ID watch|ask|act | on ID | off ID | remove ID | approve RUN | decline RUN
  aertun geo status | network add PREFIX NAME --kind office|vpn | network remove PREFIX | help   where sign-ins come from

Cases and response
  aertun incident declare --title T --grade sev2 [--finding ID]   open one, under the regimes set
  aertun incident list | show ID | decide ID aware --because "…" | discharge|waive ID "REGIME" --because "…"
  aertun incident note|assign|link|watch|reopen|close ID …   the rest of the record
  aertun incident playbooks [show ID | check FILE] | propose|approve|withdraw ID PLAYBOOK
  aertun incident step ID PLAYBOOK STEP done|skip|undo --because "…"
  aertun incident act ID ACTION ISSUER:VALUE --because "…" | act-approve ID N
  aertun incident regimes [eu nis2 …] | duties | demo
  aertun action catalogue | list | add NAME --org ORG | remove NAME
  aertun notify add|object|erase ISSUER:VALUE | contacts | draft --kind K --subject S | list
  aertun notify plan|send|publish NOTICE | inbox ISSUER:VALUE
  aertun work demo                         four states, and what the other statuses really were

Vulnerabilities and code
  aertun vuln load | import [--bom F --where A] [--osv P] [--kev F] [--epss F] | reach --source DIR --where A
  aertun vuln queue [INVENTORY] | plan | why CVE-ID | reasons | assets | ssvc-tree FILE
  aertun vuln asset MATCH --exposure E --impact I --because "…"
  aertun vuln assess CVE PKG STATUS | accept CVE PKG --owner W --until DATE --because "…"
  aertun vuln vex --author A --id URL      the decisions as an OpenVEX draft
  aertun feed status                       what the scanner is working from, and how old it is
  aertun sca scan --bom sbom.json --osv db.json   which dependencies you can actually fix
  aertun sarif read results.sarif          import any scanner's findings, and what it left out
  aertun appsec triage | gate | accept ALERTS.jsonl | rotated FINGERPRINT

The estate and its people
  aertun estate show | build | scores [--limit N] | sync [--remind] | auto --every 24h | sample [--remove]
  aertun workforce coverage | propose | people | gaps [FILE] | link A B --because W
  aertun remind preview | enable | disable | send
  aertun vendor list | show ID | reconcile | review ID
  aertun access open ID [FILE] --scope S | items ID | decide ID ACCOUNT VERDICT | close ID [FILE] | list

People, sign-in and changes
  aertun auth owner [transfer WHO]         who owns the store; a transfer the Owner confirms a day later
  aertun auth grant WHO ROLE [--on PATH]   viewer | analyst | responder | admin
  aertun auth grant WHO JOB [--for 30d]    engineer | vuln-manager | auditor (must end)
  aertun auth deny|revoke WHO ROLE [--on PATH] | explain WHO [ACTION] | list | roles
  aertun auth invite WHO ROLE              grant a role and print the enrolment link in one step
  aertun auth enrol WHO [--for 24h]        a one-time link that adds their passkey (--revoke ends it)
  aertun auth unlock WHO                   let them sign in again after a lockout
  aertun auth recover                      break-glass when every admin token is lost
  aertun oidc configure | status | check   sign in with an OpenID Connect provider
  aertun saml add | list | show | metadata | presets | remove   sign in with a SAML provider
  aertun scim status | token | map GROUP ROLE|JOB | unmap GROUP   provisioning from your identity provider
  aertun token issue NAME --principal WHO | exchange | keygen FILE | proof | list | revoke ID | stale
  aertun agent list | add NAME --owner WHO --allow TOOL | allow NAME --add|--remove TOOL | maps NAME --host HOST | disable NAME --why "…" | enable NAME --why "…" | token NAME --tools TOOL[,TOOL] --for-run ID | consents [revoke ID] | help
                                        the register of AI agents: who runs, what each may call, where each runs, one kill switch each, what was consented to
  aertun ssf receivers | key | send NAME --why "…" | help
                                        where the kill switch is announced: receivers hearing session-revoked
  aertun pending [list] | approve | decline | withdraw | redeem ID   privileged changes, approved by a second administrator
  aertun approvals                         everything waiting for you to decide

Its own record and settings
  aertun privacy export SUBJECT [--out FILE] [--audit] [--pseudonym p_…] | statement
                                        a data subject's events as a handover document, and the honest privacy posture
  aertun auditlog dir | verify | show SEQ | export -o FILE | head --save | verify-head FILE | prove SEQ | consistency
  aertun auditlog anchor [submit|upgrade|status]   the log head, committed to Bitcoin
  aertun logd [status]                     the log writer, run as its own account
  aertun siem ocsf|cef|jsonl --envelope F | verify FILE --envelope F   its own audit log, still verifiable
  aertun siem stream [status] | key | send  its own audit log, pushed to a SIEM as it is written
  aertun compliance controls | evidence CONTROL [--out FILE] | verify FILE [--keys KEYS]
                                        SP 800-53: the map, and evidence packs proved from the signed log
  aertun vault status | enable | rotate | rewrap   the keyring credentials are sealed under
  aertun config show | list | explain KEY | set KEY VALUE | unset KEY
  aertun network                           what this may connect to, and whether
  aertun version                           what this binary is
  aertun --version                         version, copyright and licence
  aertun -V                                the same, shorter
  aertun --help | help                     this list

Every command takes --json, --root DIR and --token T.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// --json is global rather than per-command, because a caller scripting this
	// should not have to remember which subcommands happen to support it.
	args := os.Args[1:]
	jsonMode := false
	filtered := args[:0]
	for _, a := range args {
		if a == "--json" {
			jsonMode = true
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered

	w = out.New(jsonMode)
	bold, dim = w.Bold(), w.Dim()
	green, yellow, red, reset = w.Green(), w.Yellow(), w.Red(), w.Reset()

	root := defaultRoot
	// A tiny hand-rolled global flag pass, so `--root` and `--token` work
	// before the subcommand as well as after it.
	//
	// --token is here because it was read globally and removed nowhere. The
	// authorisation check picked it out of the raw arguments, then handed the
	// same arguments to the subcommand's own flag set — which rejected an
	// undeclared flag. Seven of eighty-one flag sets declared it, so `publish
	// --token X` worked and `add --token X` exited 1 with "flag provided but
	// not defined: -token".
	//
	// The command that mattered most was the one printing the advice. Every
	// refusal in this program ends "Present one with --token,
	// ~/.aertun/token, or AERTUN_TOKEN", and for `aertun add` on a store with
	// access control the first of those three could not be done at all.
	//
	// Stripping it here makes the sentence true everywhere, and the seven
	// local declarations are gone rather than left to shadow it.
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--root" && i+1 < len(args) {
			root = args[i+1]
			i++
			continue
		}
		if v, ok := strings.CutPrefix(args[i], "--root="); ok {
			root = v
			continue
		}
		if args[i] == "--token" && i+1 < len(args) {
			flagToken = args[i+1]
			i++
			continue
		}
		if v, ok := strings.CutPrefix(args[i], "--token="); ok {
			flagToken = v
			continue
		}
		rest = append(rest, args[i])
	}
	if len(rest) == 0 {
		usage()
		os.Exit(2)
	}

	cmd, cmdArgs := rest[0], rest[1:]

	// The network boundary, applied once for every command before any of them
	// runs.
	//
	// Here rather than in the two servers, because an isolated deployment is
	// not only a running site: `import`, `fediverse`, `auditlog anchor` and
	// the chat bots all reach the network from the command line, and a
	// boundary that only the server honoured would be one somebody steps over
	// by running a command.
	//
	// A mode that cannot be read leaves the default. Refusing to run because
	// a config file is unreadable would make an unrelated fault look like a
	// network policy.
	if cfg, cerr := loadConfig(root); cerr == nil {
		if m := strings.TrimSpace(cfg.Raw("network.mode")); m != "" {
			if serr := egress.SetMode(egress.Mode(m)); serr != nil {
				fmt.Fprintf(os.Stderr,
					"network.mode is %q; it is open or offline\n", m)
				os.Exit(2)
			}
		}
	}

	// Authorisation happens here, once, for every command. See privilege.go
	// for why it is a table rather than a call at the top of each one.
	if cmd != "help" && cmd != "-h" && cmd != "--help" {
		if err := authoriseCommand(root, cmd, cmdArgs); err != nil {
			w.Error(err)
			os.Exit(out.ExitFailure)
		}
	}

	var err error
	switch cmd {
	case "init":
		_, existed := os.Stat(root)
		if err = cmdInit(root); err == nil {
			err = initAdmin(root, cmdArgs, existed != nil)
		}
	case "auditlog":
		err = cmdAuditLog(root, cmdArgs)
	case "network":
		err = cmdNetwork(root, cmdArgs)
	case "logd":
		if len(cmdArgs) > 0 && cmdArgs[0] == "status" {
			err = cmdLogdStatus(root)
		} else {
			err = cmdLogd(root, cmdArgs)
		}
	case "oidc":
		err = cmdOIDC(root, cmdArgs)
	case "saml":
		err = cmdSAML(root, cmdArgs)
	case "siem":
		if len(cmdArgs) > 0 && cmdArgs[0] == "verify" {
			err = cmdSiemVerify(root, cmdArgs[1:])
		} else if len(cmdArgs) > 0 && cmdArgs[0] == "stream" {
			err = cmdSiemStream(root, cmdArgs[1:])
		} else {
			err = cmdSiem(root, cmdArgs)
		}
	case "detect":
		err = cmdDetect(root, cmdArgs)
	case "hunt":
		err = cmdHunt(root, cmdArgs)
	case "triage":
		err = cmdTriage(root, cmdArgs)
	case "finding":
		err = cmdFinding(root, cmdArgs)
	case "scim":
		err = cmdSCIM(root, cmdArgs)
	case "automate":
		err = cmdAutomate(root, cmdArgs)
	case "geo":
		err = cmdGeo(root, cmdArgs)
	case "telemetry":
		err = cmdTelemetry(root, cmdArgs)
	case "inbound":
		err = cmdInbound(root, cmdArgs)
	case "spool":
		err = cmdSpool(root, cmdArgs)
	case "privacy":
		err = cmdPrivacy(root, cmdArgs)
	case "notify":
		err = cmdNotify(root, cmdArgs)
	case "estate":
		err = cmdEstate(root, cmdArgs)
	case "remind":
		err = cmdRemind(root, cmdArgs)
	case "workforce":
		err = cmdWorkforce(root, cmdArgs)
	case "connect":
		err = cmdConnect(root, cmdArgs)
	case "vuln":
		err = cmdVuln(root, cmdArgs)
	case "intel":
		err = cmdIntel(root, cmdArgs)
	case "collect":
		err = cmdCollect(root, cmdArgs)
	case "identity":
		err = cmdIdentity(root, cmdArgs)
	case "action":
		err = cmdAction(root, cmdArgs)
	case "analyst":
		err = cmdAnalyst(root, cmdArgs)
	case "bench":
		err = cmdBench(root, cmdArgs)
	case "windtunnel":
		err = cmdWindtunnel(root, cmdArgs)
	case "proof":
		err = cmdProof(cmdArgs)
	case "vendor":
		err = cmdVendor(root, cmdArgs)
	case "access":
		err = cmdAccess(root, cmdArgs)
	case "appsec":
		err = cmdAppsec(root, cmdArgs)
	case "work":
		err = cmdWork(cmdArgs)
	case "sigma":
		err = cmdSigma(cmdArgs)
	case "sarif":
		err = cmdSarif(cmdArgs)
	case "sca":
		err = cmdSCA(cmdArgs)
	case "correlate":
		err = cmdCorrelate(cmdArgs)
	case "incident":
		err = cmdIncident(root, cmdArgs)
	case "pending":
		err = cmdPending(root, cmdArgs)
	case "feed":
		err = cmdFeed(cmdArgs)
	case "content":
		err = cmdContent(root, cmdArgs)
	case "source":
		err = cmdSource(root, cmdArgs)
	case "mcp":
		err = cmdMCP(root, cmdArgs)
	case "serve":
		err = cmdServe(root, cmdArgs)
	case "auth":
		err = cmdAuth(root, cmdArgs)
	case "token":
		err = cmdToken(root, cmdArgs)
	case "agent":
		err = cmdAgent(root, cmdArgs)
	case "ssf":
		err = cmdSSF(root, cmdArgs)
	case "vault":
		err = cmdVault(root, cmdArgs)
	case "config":
		err = cmdConfig(root, cmdArgs)
	case "approvals":
		err = cmdApprovals(root, cmdArgs)
	case "compliance":
		err = cmdCompliance(root, cmdArgs)
	// --version and --help as well as the subcommands.
	//
	// The GNU Coding Standards ask for both as options, and the reason is not
	// ceremony: a script or a packaging tool checking a program's version
	// tries `--version` and nothing else. `aertun version` printed the same
	// string and was unreachable to everything that looks for it.
	case "version", "--version", "-V":
		fmt.Printf("aertun %s\n", version)
		fmt.Println("Copyright (C) 2026 Rashik Adhikari")
		fmt.Println("Licensed under the Apache License, Version 2.0 " +
			"<https://www.apache.org/licenses/LICENSE-2.0>.")
		fmt.Println("There is NO WARRANTY, to the extent permitted by law.")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		w.Error(err)
		// A gate refusing is a different outcome from the command breaking, and
		// a caller branching on exit status should be able to tell which.
		var blocked errBlocked
		if errors.As(err, &blocked) {
			os.Exit(out.ExitBlocked)
		}
		var usage errUsage
		if errors.As(err, &usage) {
			os.Exit(out.ExitUsage)
		}
		os.Exit(out.ExitFailure)
	}
}

// open is the one place any command gets a store, which is why encryption is
// wired here: every command inherits it, including the ones added next year by
// somebody who has not read this file.
// reorder moves flags ahead of positional arguments.
//
// Go's flag package stops parsing at the first non-flag argument, so
// `add index=home.json -m "msg"` treats -m as a filename. That is the natural
// order to type and the CLI has to accept it, so flags are lifted out first.
// `valued` names the flags that consume the following argument; a boolean flag
// must not swallow the token after it.
func reorder(args []string, valued map[string]bool) []string {
	flags, positional := splitFlags(args, valued)
	return append(flags, positional...)
}

// splitFlags separates the flags, and the values they consume, from the
// positional arguments.
//
// Pulled out of reorder because the privilege gate needs the positional
// arguments too: it has to know which page a command is about before the
// command has parsed anything, so that a grant or a deny scoped to part of the
// site is enforced here as well as in the browser.
//
// One function rather than two readings of the same arguments. A second copy
// of "which flags take a value" would drift, and a drifted copy reads as a
// page name the word the command reads as a flag value — which authorises one
// resource and acts on another, and a check on the wrong resource is not a
// check.
func splitFlags(args []string, valued map[string]bool) (flags, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if n, _, hasEq := strings.Cut(name, "="); hasEq {
			_ = n
			continue // --flag=value carries its own value
		}
		if valued[name] && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return flags, positional
}

// cmdInit makes the store: a directory private to this account, with the
// detection rules that ship.
func cmdInit(root string) error {
	// main builds the writer; a test calling this first has not.
	if w == nil {
		w = out.New(false)
	}
	entries, statErr := os.ReadDir(root)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	switch {
	case statErr != nil:
		w.Human("created %s\n", root)
	case len(entries) == 0:
		// The container image ships the store's directory empty, so a
		// first init there finds it already made.
		w.Human("using %s, which was empty\n", root)
	default:
		w.Human("reusing %s\n", root)
	}
	// Whether the directory was made here or arrived empty, a store
	// starts with the shipped rules; one that has its own keeps them.
	return ensureRules(root, "init")
}
