// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
)

// What every command needs before it is allowed to run.
//
// This exists because the check was in one place and needed to be in twenty.
// `publish` called authorise and nothing else did, so with a policy configured
// and no token presented at all:
//
//	auth grant mallory admin              succeeded
//	auth revoke alice admin               succeeded
//	token issue evil --role admin         succeeded, and printed a live token
//	schedule add 1h                       succeeded, deferring a publish
//
// which is the entire access-control model bypassed by anyone able to run the
// binary. publish refused correctly the whole time, and that inconsistency is
// what shows it was an omission rather than a decision: if the reasoning had
// been "filesystem access to the store is already game over", publish would
// not have been checking either.
//
// It is not game over, and the rest of this program is built on that. The
// audit log is written by a separate account precisely so that code execution
// as aertun is not enough to rewrite it, and a store on a shared volume is a
// normal deployment.
//
// So the table, rather than a call at the top of each command. A call has to
// be remembered; a table is a list somebody has to add a row to, and the test
// below refuses to pass until every dispatched command has one. This is the
// same shape as the content-type gate test, which is what caught the HTTP API
// writing content without validating it.
type need struct {
	// action is what the caller must be permitted to do. Empty means the
	// command needs no authority, and then why must say why that is safe.
	action auth.Action
	why    string
}

// commandNeeds is keyed by "command" or by "command subcommand" where the
// subcommand changes the answer. The more specific key wins, so `auth explain`
// can be readable while `auth grant` is not.
var commandNeeds = map[string]need{
	// Deciding what an automation holds takes the approve permission, and
	// whoever wrote the rule does not approve its runs (internal/automate).
	"automate approve": {action: auth.ActApprove},
	"automate decline": {action: auth.ActApprove},
	// Reading what a person has to do is an administrator's, like the
	// workforce screen: a person's record is a file on an employee.
	"workforce people": {action: auth.ActGrant},
	"estate scores":    {action: auth.ActGrant},
	"vault rewrap":     {action: auth.ActToken},
	"auditlog anchor":  {action: auth.ActGrant},

	"siem": {action: auth.ActView},
	// Reading what this deployment may connect to is a view. Changing it is
	// `config set`, which is already privileged.
	"network": {action: auth.ActView},
	// Each part of the list is filtered by what the caller may decide; the
	// list itself needs only that they are somebody here.
	"approvals": {action: auth.ActView},
	// Strict parent, narrowing children — see the note on posture. Pointing
	// every reader at a different audit log is an operator act, so the parent
	// takes that answer and the seven reading subcommands step down from it.
	"auditlog": {action: auth.ActGrant},
	// The evidence pack is the audit log opened to a third party, so it
	// carries the auditlog shape: a strict parent, and the three reading
	// subcommands — the map, the pack, the offline check — stepping down to
	// the same view `auditlog prove` needs. Generating one signs a head,
	// which is what `auditlog head` does with the view action.
	"compliance":          {action: auth.ActGrant},
	"compliance controls": {action: auth.ActView},
	"compliance evidence": {action: auth.ActView},
	"compliance verify":   {action: auth.ActView},
	// The theme is what every page is rendered against, so changing it changes
	// what every reader sees — the same authority as changing the template, and
	// for the same reason.
	// Deciding a risk is acceptable is a statement the organisation stands
	// behind — the same weight as putting something in front of the public,
	// and far heavier than editing a draft. `finding story` reads and is
	// checked separately below.
	"finding": {action: auth.ActTriage},
	// Privileged changes waiting for a second administrator: deciding one
	// is a whole-site administrator's; receiving an approved token is
	// whoever asked for it, as issuing one is.
	"pending":            {action: auth.ActGrant},
	"pending list":       {action: auth.ActView},
	"pending redeem":     {action: auth.ActToken},
	"automate":           {action: auth.ActTune},
	"automate list":      {action: auth.ActView},
	"automate runs":      {action: auth.ActView},
	"automate templates": {action: auth.ActView},
	// Feeds bring in what other systems say, and what they say reaches
	// the automations. Adding one is the whole site's decision (the
	// command asks for it again); reading them is a view.
	"inbound":        {action: auth.ActGrant},
	"inbound list":   {action: auth.ActView},
	"inbound status": {action: auth.ActView},
	"inbound help":   {action: auth.ActView},
	// Where sign-ins come from decides which of them are stepped up, so
	// naming a network is a decision for all of Aertun; reading is a view.
	"geo":        {action: auth.ActGrant},
	"geo status": {action: auth.ActView},
	"geo help":   {action: auth.ActView},
	// Grant: provisioning decides who holds which role.
	"scim":          {action: auth.ActGrant},
	"scim status":   {action: auth.ActGrant},
	"finding story": {action: auth.ActView},

	// A board built for the run, to make an argument about states.
	"work": {action: auth.ActView},

	// Reads rule files and compiles them. Writes nothing.
	"sigma": {action: auth.ActView},

	// Reads a scanner's output file and reports on it. Writes only where
	// the caller asked for an output path.
	"sarif": {action: auth.ActView},

	// Reads a bill and an advisory file and matches them. Writes nothing.
	"sca": {action: auth.ActView},

	// Runs correlations over events built for the run. Reads no store.
	"correlate": {action: auth.ActView},

	// The reporting table, and an incident built for the run. Notifies
	// nobody: internal/notify is what sends anything.
	// A live incident names what went wrong and who knew when. The table
	// of deadlines and the worked example name nothing.
	"incident":        {action: auth.ActRespond},
	"incident duties": {action: auth.ActView},
	"incident demo":   {action: auth.ActView},
	// The checklists themselves name no incident.
	"incident playbooks": {action: auth.ActView},

	// Feed freshness, over mirrors built for the run. Fetches nothing:
	// internal/fetch is what reaches a network.
	"feed": {action: auth.ActView},

	// Log source mappings, and a check against records a caller supplies.
	// Fetches nothing.
	// Adding a mapping decides what an application's records become.
	"source":       {action: auth.ActTune},
	"source list":  {action: auth.ActView},
	"source check": {action: auth.ActView},

	// Baselining a codebase's debt decides what this organisation stops
	// reporting, and recording a rotation asserts that a credential is
	// dead: both are publishes. Reading a run and gating on it touch
	// nothing.
	"appsec":        {action: auth.ActAssess},
	"appsec triage": {action: auth.ActView},
	"appsec gate":   {action: auth.ActView},

	// A decision about somebody's access is signed and appended to the
	// audit chain: the same authority as publishing. Opening a campaign is
	// an ordinary write, and reading one is a view.
	"access":       {action: auth.ActGrant},
	"access open":  {action: auth.ActGrant},
	"access list":  {action: auth.ActView},
	"access items": {action: auth.ActView},
	"access close": {action: auth.ActView},

	// Signing off a third party's access is a statement the organisation
	// stands behind: the same authority as publishing. Reading the
	// register and comparing it against the connectors are views.
	"vendor":           {action: auth.ActGrant},
	"vendor list":      {action: auth.ActView},
	"vendor show":      {action: auth.ActView},
	"vendor reconcile": {action: auth.ActView},

	// Deciding a vulnerability does not apply is a statement the
	// organisation stands behind and is appended to the audit chain rather
	// than edited: the same authority as publishing. Reading the queue is a
	// view.
	// The analyst reads every finding and spends the model budget.
	"analyst":      {action: auth.ActTriage},
	"analyst plan": {action: auth.ActView},
	// Calibrating reads every ruled finding and spends the model budget,
	// the weight of the analyst's own eval: like eval, the command itself
	// asks for tune before it runs, because a row here may only narrow
	// its parent and the parent is the analyst's triage.
	"analyst calibrate": {action: auth.ActTriage},
	// A vendor's export of what its AI said is evidence brought into the
	// security area, the weight of importing intelligence. Proving signs a
	// measurement of a product in the organisation's name, so the command
	// itself asks for tune before it reads anything, as calibrating does;
	// the row may only narrow its parent.
	// Blind review: drawing a sample and proving one sign a measurement in
	// the organisation's name and ask for tune themselves; judging is a
	// reviewer's work, and asking how big a sample must be is arithmetic.
	// Claim cards: registering and testing one ask for tune themselves, as
	// the other signed measurements do; reading the cards is reading.
	"claim":           {action: auth.ActTriage},
	"claim list":      {action: auth.ActView},
	"adjudicate":      {action: auth.ActTriage},
	"adjudicate list": {action: auth.ActView},
	"adjudicate size": {action: ""},
	"verdict":         {action: auth.ActTriage},
	"verdict list":    {action: auth.ActView},
	"verdict prove":   {action: auth.ActTriage},
	// The benchmark measures the analyst and, against a real model, spends
	// the model budget to do it: the same weight as the analyst's own eval.
	// Rendering a document somebody already has is only reading.
	"bench":        {action: auth.ActTune},
	"bench report": {action: auth.ActView},
	// The wind tunnel replays synthetic attack sessions over an embedded
	// or operator-named stream: it opens no store, contacts nobody, and
	// spends nothing — the scratch spools are files nobody reads back but
	// the operator. The signature a run may add is the compliance-evidence
	// weight, a signed statement about a test this program ran, and the
	// key it signs with is one the caller named on the command line.
	"windtunnel": {action: auth.ActView},
	// A proof checks files the caller named against a corpus the caller
	// named and signs with a key the caller named: it opens no store,
	// contacts nobody and spends nothing, the wind tunnel's weight.
	// Reading proofs, and verifying one, is reading. Keeping one adds to what
	// the store shows as proven — the weight of importing intelligence — and
	// the operation asks for that itself before it runs (internal/proving),
	// because a row here may only narrow its parent.
	"proof": {action: auth.ActView},
	// A recorded case is the security queue and its evidence copied out of
	// the store into a file, which is what listing the queue on the command
	// line takes (`finding`); each part of it is gated again, operation by
	// operation, exactly as the agent interface gates it for the same
	// person.
	"twin": {action: auth.ActTriage},
	// An export is one file holding, for every finding the analyst looked
	// at, what it was shown, what it answered and how a person ruled —
	// this organisation's whole triage record, signed in its name and made
	// to leave the store for a training run. That is the weight of a
	// data-subject export: an administrator's. Not the tune permission the
	// analyst's eval takes, because the eval prints numbers to whoever ran
	// it and this hands the record itself to somebody else. Checking a
	// file is reading, and --log reads the audit log, so it is asked about
	// the log's area below, where an auditor holds view.
	"forge":        {action: auth.ActGrant},
	"forge verify": {action: auth.ActView},
	// An action changes something in somebody else's tool.
	"action":           {action: auth.ActGrant},
	"action catalogue": {action: auth.ActView},
	// Whose an identifier is decides whose activity is whose.
	"identity": {action: auth.ActGrant},
	// Collection reads other tools with stored credentials and writes the
	// event store.
	"collect": {action: auth.ActGrant},
	// An indicator raises findings about whoever touched it.
	"intel":        {action: auth.ActTriage},
	"vuln":         {action: auth.ActAssess},
	"vuln queue":   {action: auth.ActView},
	"vuln why":     {action: auth.ActView},
	"vuln reasons": {action: auth.ActView},
	"vuln plan":    {action: auth.ActView},
	"vuln vex":     {action: auth.ActView},
	"vuln assets":  {action: auth.ActView},

	// Storing a credential for another company's system is the heaviest
	// thing here, and running a connector is an ordinary write. Reading a
	// manifest is a view; probing makes a request and returns field names
	// rather than data, which is still a read of somebody else's system and
	// is checked as an edit.
	"connect":       {action: auth.ActGrant},
	"connect run":   {action: auth.ActGrant},
	"connect probe": {action: auth.ActGrant},
	"connect list":  {action: auth.ActView},
	"connect check": {action: auth.ActView},
	// Listing what ships is reading the binary. Adding one installs a file
	// that can reach another company's system with a stored credential,
	// which is the weight of storing the credential itself.
	"connect catalogue": {action: auth.ActView},
	// Scores name employees, so the estate is an administrator's; building
	// it writes findings, as detect run does, and a summary is reading.
	"estate":       {action: auth.ActGrant},
	"estate build": {action: auth.ActGrant},
	"estate show":  {action: auth.ActView},
	// Reminders name people and what they have not done, and send messages
	// to every employee: an administrator's, all of it.
	"remind":      {action: auth.ActGrant},
	"connect add": {action: auth.ActGrant},

	"workforce":          {action: auth.ActGrant},
	"workforce coverage": {action: auth.ActView},
	"workforce propose":  {action: auth.ActView},
	"workforce gaps":     {action: auth.ActView},

	"notify":          {action: auth.ActRespond},
	"notify add":      {action: auth.ActRespond},
	"notify object":   {action: auth.ActRespond},
	"notify draft":    {action: auth.ActRespond},
	"notify publish":  {action: auth.ActRespond},
	"notify contacts": {action: auth.ActView},
	"notify list":     {action: auth.ActView},
	"notify plan":     {action: auth.ActView},
	"notify inbox":    {action: auth.ActView},

	"spool":        {action: auth.ActGrant},
	"spool add":    {action: auth.ActGrant},
	"spool stats":  {action: auth.ActView},
	"spool verify": {action: auth.ActView},

	// A data-subject export is one person's whole history in one document:
	// the same weight as the workforce record, an administrator's, and for
	// the same reason — it is a file on an employee. The statement is about
	// the store rather than about anybody, and is a view.
	"privacy":           {action: auth.ActGrant},
	"privacy export":    {action: auth.ActGrant},
	"privacy statement": {action: auth.ActView},

	// Running rules over a file and ranking the result. Reads, writes
	// nothing, and is the job an analyst does first.
	"triage": {action: auth.ActView},

	// Counting values in a file it is handed. No store, no network, no
	// writes. The person running it is hunting, which is the job view exists
	// for.
	"hunt": {action: auth.ActView},

	// Reading a file somebody hands it and saying whether the events in it
	// are usable. Touches no store and writes nothing, so it is the authority
	// to look rather than the authority to change anything — and the person
	// most likely to run it is whoever is writing a connector, who may well
	// have been given nothing else.
	"telemetry": {action: auth.ActView},

	// Reading rule files and running them against their own fixtures. No
	// store, no network, no writes — the same authority as looking at the
	// repository the rules live in, which is where they are reviewed.
	"detect":      {action: auth.ActView},
	"oidc check":  {action: auth.ActView},
	"logd status": {action: auth.ActView},

	// The signed content plane. Signing and installing a pack changes what
	// the detections say, so it carries the tune permission — the same
	// authority as editing a rule by hand, which is what a pack is a batch
	// of. Keygen is key material, the token weight: whoever could re-run it
	// could re-anchor trust for every pack this store verifies. Reading a
	// pack directory and the installed list are views.
	"content":           {action: auth.ActTune},
	"content keygen":    {action: auth.ActToken},
	"content list":      {action: auth.ActView},
	"content installed": {action: auth.ActView},
	"content verify":    {action: auth.ActView},

	"auditlog verify":      {action: auth.ActView},
	"auditlog show":        {action: auth.ActView},
	"auditlog export":      {action: auth.ActView},
	"auditlog head":        {action: auth.ActView},
	"auditlog prove":       {action: auth.ActView},
	"auditlog consistency": {action: auth.ActView},
	// Anchoring sends the log's digest to outside timestamp authorities and
	// writes what they return: an act, not a read, so an auditor who may
	// read the log may not do it.

	// -- changing who may do anything. Admin.
	"auth":  {action: auth.ActGrant},
	"token": {action: auth.ActToken},
	// The agent register decides what may act in this store, so changing it
	// is an administrator's — with the one deliberate exception: the kill
	// switch is a responder's, because the person who has to stop an agent
	// at 3am is the one holding the pager, and "wait for an admin" is how a
	// misbehaving agent earns its keep: registration is grant, suspension
	// is respond.
	"agent":      {action: auth.ActGrant},
	"agent list": {action: auth.ActView},
	// Reconciling reads an agent's telemetry and its calls and signs an
	// account of it in the organisation's name: the command asks for tune
	// itself before it reads anything, as the other signed proofs do.
	"agent reconcile": {action: auth.ActTriage},
	"agent disable":   {action: auth.ActRespond},
	// The consent register's read-and-end surface, and the responder's
	// rung for both halves: revoking a consent is the delegation kill —
	// the same rung `agent disable` holds, for the same 3am reason — and
	// the listing rides at the same rung because the table reads one word
	// deep. Over-guarded rather than under-, which is the direction this
	// table's own test insists on; an auditor who only needs to read the
	// register has the audit log, where every consent.grant and
	// consent.revoke is already recorded.
	"agent consents": {action: auth.ActRespond},
	// The transmitter speaks in this deployment's name — its kill switch,
	// announced to other platforms. Sending is the responder's weight, the
	// same rung as the disable that causes it; reading where events go and
	// what signs them is a view, so somebody locked out can still find out
	// what this store has been telling its neighbours.
	"ssf":           {action: auth.ActRespond},
	"ssf receivers": {action: auth.ActView},
	"ssf key":       {action: auth.ActView},
	"oidc":          {action: auth.ActGrant},
	"saml":          {action: auth.ActGrant},
	"vault":         {action: auth.ActToken},

	// Configuration decides how every other control behaves, so changing it is
	// an admin act. Reading it is not: an author who cannot see the settings
	// cannot tell why a publish was refused.
	"config":         {action: auth.ActGrant},
	"config show":    {action: auth.ActGrant},
	"config list":    {action: auth.ActGrant},
	"config explain": {action: auth.ActView},

	// Serving starts the process that authorises every request itself. Who
	// may start it is decided where logd's authority is: by the operating
	// system, which lets only the store's own account open its directory.
	// Asking for an administrator's token here protected nothing — whoever
	// can start the server can read the store — and it stopped every new
	// store from serving, because init makes a passkey link, not a token,
	// and stopped every service restart that had no token in its
	// environment.
	"serve": {why: "starts the process that authorises every request " +
		"itself; who may start it is whoever the operating system lets open " +
		"the store's directory, as with logd"},
	"mcp":  {action: auth.ActView},
	"init": {why: "creates the store; there is no policy to consult until one exists"},
	"logd": {why: "runs as its own account and derives its authority from the " +
		"socket peer's uid, not from a token in this store"},
	"version":   {why: "prints a version"},
	"--version": {why: "prints a version"},
	"-V":        {why: "prints a version"},
	"help":      {why: "prints usage"},
	"-h":        {why: "prints usage"},
	"--help":    {why: "prints usage"},

	// -- read-only subcommands of otherwise privileged commands, so that
	// somebody locked out can still find out why.
	"auth explain": {action: auth.ActView},
	// Naming the Owner is reading; asking to transfer ownership checks
	// the administrator's permission, and the Owner's identity, itself.
	"auth owner": {action: auth.ActView},
	// The break-glass. It cannot require authority: the situation it exists
	// for is that no credential remains to present. It checks for itself that
	// no usable admin token exists, refuses when one does, and records what it
	// did in a log this account cannot rewrite.
	"auth recover": {why: "recovers a store with no usable admin token, which " +
		"is the one situation where requiring a token is a contradiction"},
	"auth list":    {action: auth.ActView},
	"token list":   {action: auth.ActView},
	"vault status": {action: auth.ActView},
	// A program's own key and its proofs are made on the program's machine
	// from a file given as an argument; neither opens the store.
	"token keygen": {why: "writes a new key to a file given as an argument and never opens the store"},
	"token proof":  {why: "signs a proof with a key file given as an argument and never opens the store"},
}

// Which page a command is about, so that a binding scoped to part of the site
// means something on the command line.
//
// # What was wrong
//
// This used to be one line returning "/" for everything, and its comment
// called that coarse by design: "the finer per-page checks stay where the page
// name is known". There were no finer per-page checks. Every authorise() call
// on this surface passes "/", so the coarse gate was the only gate, and being
// coarse had two consequences that are not the same shape.
//
// A grant narrowed with --on /blog stopped working altogether. covers("/blog",
// "/") is false, so an author scoped to part of the site could run no command
// at all, and the flag the help text calls "enforced" was a way to lock
// somebody out. That is the wrong answer, but it is the safe wrong answer.
//
// A deny narrowed the same way stopped working too, and that one is a hole. A
// publisher denied on /legal still holds publisher on "/"; the deny does not
// cover "/"; the target was always "/". So the deny never matched, and
// `aertun section set legal/notice 0 body=…` was permitted by the very policy
// written to forbid it. The browser interface enforced it and the command line
// did not, which is worse than not having the feature at all: somebody reads
// the policy, sees the deny, and believes it.
//
// # Why a table, and why it is allowed to give up
//
// The page has to be identified before the command parses its own arguments,
// which is the awkward part — at this point `args` is just words. Most
// commands make that easy by taking their positional arguments first and
// finding them with leadingArgs, which stops at the first flag. Those get a
// row here naming which positional is the page, read with leadingArgs itself,
// so the gate and the command cannot disagree about which word they are
// looking at.
//
// Anything not in the table, and anything in it whose page argument is missing
// or is not a name this can be sure of, falls back to "/". That is the strict
// direction: "/" is covered only by a binding on the whole site, so a command
// this cannot read is authorised as though it touched everything. A new
// command therefore arrives over-guarded, which is a bug report, rather than
// under-guarded, which is a breach.
//
// The corollary is the one thing that must not be got wrong: a row here is a
// claim that the command touches *that page and nothing else*. A row for a
// command that also writes somewhere else would narrow the check away from the
// place it was needed.

// unknownCommand explains a name nothing recognises.
//
// Suggestions come from the same table that decides privileges, so a command
// that exists is always offered — there is no second list to fall behind.
func unknownCommand(cmd string) error {
	// The threshold is relative to the shorter word, not to a constant.
	//
	// A fixed two edits is most of a four-letter word and a rounding error in
	// a twelve-letter one, which is how "prov" came back as the suggestion for
	// "aprove". Requiring the distance to be under half the shorter word keeps
	// short aliases from matching everything and still catches a transposition
	// in a five-letter name.
	var near []string
	for known := range commandNeeds {
		if strings.HasPrefix(known, cmd) || strings.HasPrefix(cmd, known) {
			near = append(near, known)
			continue
		}
		shorter := len(cmd)
		if len(known) < shorter {
			shorter = len(known)
		}
		if d := editDistance(cmd, known); d*2 < shorter {
			near = append(near, known)
		}
	}
	sort.Strings(near)
	if len(near) > 4 {
		near = near[:4]
	}
	if len(near) > 0 {
		return fmt.Errorf("there is no %q command. Did you mean %s?\n"+
			"  aertun help — every command", cmd, strings.Join(near, ", "))
	}
	return fmt.Errorf("there is no %q command.\n  aertun help — every command",
		cmd)
}

// editDistance is Levenshtein, bounded by the length of the shorter word.
//
// Two rows rather than a full matrix: the words are command names, so this is
// never the expensive part, and the small version is easier to be sure of.
func editDistance(a, b string) int {
	if len(a) > 24 || len(b) > 24 {
		return 99
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

// authoriseCommand is the single point every command passes through.
func authoriseCommand(root, cmd string, args []string) error {
	n, ok := lookupNeed(cmd, args)
	if !ok {
		// A command nobody declared. Refusing is the only safe answer: the
		// alternative is that adding a command silently adds an unguarded one,
		// which is exactly how this hole appeared.
		//
		// What it *says* depends on who is reading. A developer who added a
		// command and forgot the table needs the file name. A person who
		// mistyped needs to know they mistyped — and telling them to edit a Go
		// source file is the worst possible answer to a typo. Every unknown
		// command took the developer message for as long as this check has
		// existed, because the two cases were never distinguished.
		//
		// They are distinguishable: a command in the dispatch switch and
		// absent from the table is the developer's; anything else is a typo,
		// and a test walks the source to guarantee the first case never
		// reaches a user.
		return unknownCommand(cmd)
	}
	if n.action == "" {
		return nil
	}
	// The bootstrap, and the only way out of a chicken and egg that otherwise
	// bricks the store on the first grant.
	//
	// `auth grant alice admin` is permitted when no policy exists, and creates
	// one. From that moment `token issue` needs manage-tokens — which needs a
	// token, which cannot be issued. The store locks itself the instant access
	// control is switched on, and the operator's only recovery is editing JSON
	// by hand.
	//
	// So: issuing is allowed without a token while the token store is empty
	// and the principal being issued to already holds a binding. Both halves
	// matter. It escalates nothing, because when no token exists nobody holds
	// any authority to escalate from — the store is in exactly the state it
	// was in before the grant. And it closes permanently the moment any token
	// exists, rather than staying open as a mode somebody has to remember to
	// turn off.
	if n.action == auth.ActToken && bootstrapIssue(root, cmd, args) {
		return nil
	}
	// Asking a command for help must not require the authority to run it.
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			return nil
		}
	}

	caller := resolveCaller(root, tokenFromArgs(args))
	resource := "/"
	if area, ok := commandArea(cmd, args); ok {
		resource = area
	}
	if err := authorise(root, caller, n.action, resource); err != nil {
		sub := cmd
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			sub = cmd + " " + args[0]
		}
		record(root, caller.auditRecord(sub, resource, audit.Denied,
			map[string]string{"reason": "authorisation"}))
		return err
	}
	return nil
}

// bootstrapIssue reports whether this is the first token being issued to a
// principal the policy already knows.
func bootstrapIssue(root, cmd string, args []string) bool {
	if cmd != "token" || len(args) == 0 || args[0] != "issue" {
		return false
	}
	toks, err := loadTokens(root)
	if err != nil || len(toks.Tokens) > 0 {
		return false
	}
	principal := ""
	for i, a := range args {
		if a == "--principal" && i+1 < len(args) {
			principal = args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--principal="); ok {
			principal = v
		}
	}
	if principal == "" {
		return false
	}
	p, err := loadPolicy(root)
	if err != nil {
		return false
	}
	for _, b := range p.Bindings {
		if b.Principal == principal {
			return true
		}
	}
	return false
}

// commandAreas are the commands that work in an area of the admin rather
// than on the site's content, and are asked about that area: see
// auth.AreaSecurity. A whole-site role covers every area, so nothing here
// changes what anybody granted on "/" may run; it is what lets somebody
// granted one area run that area's commands and nothing else. A subcommand
// is looked up before its command, so "board held" can be moderation while
// "board add", opening a board, stays a whole-site publish.
var commandAreas = map[string]string{
	"finding": auth.AreaSecurity, "incident": auth.AreaSecurity, "intel": auth.AreaSecurity,
	"vuln": auth.AreaSecurity, "analyst": auth.AreaSecurity, "action": auth.AreaSecurity,
	"identity": auth.AreaSecurity, "collect": auth.AreaSecurity, "source": auth.AreaSecurity,
	"connect": auth.AreaSecurity, "estate": auth.AreaSecurity, "remind": auth.AreaSecurity,
	"workforce": auth.AreaSecurity, "hunt": auth.AreaSecurity, "detect": auth.AreaSecurity,
	"sigma": auth.AreaSecurity, "correlate": auth.AreaSecurity, "telemetry": auth.AreaSecurity,
	"siem": auth.AreaLog, "automate": auth.AreaSecurity, "inbound": auth.AreaSecurity,
	"auditlog": auth.AreaLog, "compliance": auth.AreaLog, "bench": auth.AreaSecurity,
	"windtunnel": auth.AreaSecurity, "proof": auth.AreaSecurity, "verdict": auth.AreaSecurity,
	"twin":  auth.AreaSecurity,
	"forge": auth.AreaSecurity, "forge verify": auth.AreaLog,
}

// commandArea is the area a command works in, if it works in one.
func commandArea(cmd string, args []string) (string, bool) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if a, ok := commandAreas[cmd+" "+args[0]]; ok {
			return a, true
		}
	}
	a, ok := commandAreas[cmd]
	return a, ok
}

func lookupNeed(cmd string, args []string) (need, bool) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if n, ok := commandNeeds[cmd+" "+args[0]]; ok {
			return n, true
		}
	}
	n, ok := commandNeeds[cmd]
	return n, ok
}

// tokenFromArgs finds --token before the subcommand's own flag parsing runs,
// because the authorisation decision happens before that.
func tokenFromArgs(args []string) string {
	// The global pass in main has already taken it out of the arguments, so
	// there is nothing left here to scan for. Kept as a function because the
	// alternative is the authorisation path reading a package variable
	// directly, and this way the one call site says what it is asking for.
	return flagToken
}
