// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/admin"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/clientip"
	"github.com/aertun/aertun/internal/config"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/dual"
	"github.com/aertun/aertun/internal/estate"
	"github.com/aertun/aertun/internal/fetch"
	"github.com/aertun/aertun/internal/incident"
	"github.com/aertun/aertun/internal/indicator"
	"github.com/aertun/aertun/internal/listen"
	"github.com/aertun/aertun/internal/logd"
	"github.com/aertun/aertun/internal/oidc"
	"github.com/aertun/aertun/internal/proving"
	"github.com/aertun/aertun/internal/remind"
	"github.com/aertun/aertun/internal/saml"
	"github.com/aertun/aertun/internal/throttle"
	"github.com/aertun/aertun/internal/travel"
	"github.com/aertun/aertun/internal/upkeep"
	"github.com/aertun/aertun/internal/vuln"
	"github.com/aertun/aertun/internal/webauthn"
)

// cmdServe is `aertun serve`: the console, the feeds other systems push
// to, and everything the console does on its timer.
func cmdServe(root string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	openBrowser := fs.Bool("open", false,
		"open the console in a browser once the server is listening")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := loadPolicy(root)
	if err != nil {
		return err
	}
	toks, err := loadTokens(root)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	for _, why := range cfg.Dropped() {
		fmt.Fprintf(os.Stderr, "  %sconfiguration: %s%s\n", dim, why, reset)
	}
	srv, err := admin.New(pol, toks)
	if err != nil {
		return err
	}
	// The agents board joins what was observed onto what was registered;
	// the registry lives beside the policy and is loaded per request, so a
	// change the CLI makes is on the board without restarting the console.
	admin.AgentRegistry = agentStore(root)
	// The on-behalf-of half of the token exchange: the register a consent
	// lives in, the key a run credential's caveats are signed under, and
	// the audit record an exchange writes. All three existed before the
	// exchange did — the exchange composes them, it does not add state of
	// its own.
	srv.Consents = consentStore(root)
	srv.RunKey = func() ([]byte, error) { return loadRunKey(root) }
	// The one origin the console's links, feeds and token exchange name
	// when the operator has set one (publicOrigin); read once, here, as the
	// OAuth metadata is, so the two cannot drift apart while serving.
	srv.Origin = cfg.Raw("admin.base_url")
	srv.AuditAgent = func(action, resource, agent string, detail map[string]string) {
		record(root, audit.Record{
			Action: action, Resource: resource, Outcome: audit.Success,
			// The agent is the actor and the record says so: an AI
			// principal, acting under its own name, so the aertun/agent
			// telemetry (selfwatch.go) picks the exchange up as the
			// agent's act. Who the agent acts for stays in this log and
			// out of the wider-read event store.
			Principal: agent, Kind: audit.KindAI, Model: agent, Verified: true,
			Detail: detail,
		})
	}
	// Persistence and auditing for the changes the console makes. Without
	// these an access change lives until the process restarts, and the
	// administrator has already been told it worked.
	srv.UpdatePolicy = func(change func(*auth.Policy) error) (*auth.Policy, error) {
		return updatePolicy(root, change)
	}
	// Passkeys, kept beside the tokens they mint a session as. Loaded here
	// so that a store which cannot be read is a startup failure rather than
	// a sign-in that silently offers nobody a key.
	pk := &admin.Passkeys{}
	if err := loadJSON(passkeysPath(root), pk); err != nil {
		return err
	}
	pk.Save = func(p *admin.Passkeys) error {
		return saveJSON(passkeysPath(root), p)
	}
	// Which authenticators may enrol. Empty constrains nothing.
	pk.Enrol.RequireIdentified = cfg.Bool("passkey.require_hardware")
	for _, raw := range splitList(cfg.Raw("passkey.authenticators")) {
		id, perr := webauthn.ParseAAGUID(raw)
		if perr != nil {
			return fmt.Errorf("passkey.authenticators: %w", perr)
		}
		pk.Enrol.Allowed = append(pk.Enrol.Allowed, id)
	}
	srv.Passkeys = pk
	srv.SaveTokens = func(t *auth.TokenStore) error {
		return saveTokens(root, t)
	}
	srv.Audit = func(action, resource string, detail map[string]string) {
		record(root, audit.Record{
			Action: action, Resource: resource, Outcome: audit.Success,
			Principal: detail["by"], Kind: audit.KindHuman, Verified: true,
			Detail: detail,
		})
	}
	// The proving ground's operations, the same ones the command line and
	// the agent interface run; its record fails when it cannot be written,
	// so a change made there is never made without one.
	srv.Proving = &admin.ProvingGround{Ops: proving.Ops(root),
		Record: func(by, action, resource string, detail map[string]string) error {
			return recordE(root, audit.Record{Action: action, Resource: resource,
				Outcome: audit.Success, Principal: by, Kind: audit.KindHuman, Verified: true,
				Detail: detail})
		}}
	srv.Settings = &admin.Settings{
		Load: func() (*config.Config, error) { return loadConfig(root) },
		Save: func(c *config.Config) error { return saveConfig(root, c) },
	}
	srv.SCIM = scimHooks(root)
	// Events other systems push, the moment they happen.
	inb := newInboundServer(root)
	srv.Inbound = inb
	srv.Feeds = feedsHooks(root, inb)
	inboundCtx, stopInbound := context.WithCancel(context.Background())
	defer stopInbound()
	go inb.run(inboundCtx)
	// Sign-ins are judged as they are made, and the rules act on them.
	srv.SignInRisk = signInRisk(root)
	// Two factors on every request a person makes (see mfa.go).
	srv.MFAFrom = mfaFrom(root, time.Now())
	// The one-time links that give people their passkeys (enrolcmd.go).
	srv.Enrol = enrolStore(root)
	// Smart lockout for the failures that belong to an account, kept in the
	// store so every process and every restart counts the same failures.
	srv.Lockout = lockoutStore(root)
	srv.Dual = &admin.Dual{Store: dualStore(root),
		Apply: func(r dual.Request, by string) error { return applyDual(root, r, by) }}
	srv.SessionPlace, srv.SessionMovedTo, srv.Reported, srv.SignInSignal = sessionHooks(root)
	srv.Automations = &admin.AutomationsAdmin{
		Engine:  automationEngineAsync(root),
		SignIns: (&travel.Store{Dir: signinsPath(root)}).Since,
		Geo: func() string {
			_, desc, err := cachedGeo(root)
			if err != nil {
				return err.Error()
			}
			return desc
		},
	}
	srv.Events = &admin.Events{Open: eventsOpener(root)}
	srv.Findings = findingsCapability(root)
	srv.Workforce = &admin.Workforce{
		Load: func(now time.Time) (*estate.Estate, estate.Outcome, error) {
			return buildEstate(root, now)
		},
		History: func() ([]estate.Summary, error) { return loadHistory(root) },
		Status:  func() (admin.SyncStatus, error) { return syncStatus(root) },
		Sync: func(by string) error {
			if syncRunning(root) {
				return fmt.Errorf("the tools are being read already")
			}
			// In the background: a read paced to the tools' limits can take
			// longer than a browser waits. The lock inside estateSync is
			// what keeps two from overlapping; this check is only so the
			// button can say so.
			go func() {
				caller := &Caller{Name: by, Kind: audit.KindHuman, Verified: true}
				if _, err := estateSync(root, time.Now().UTC(), caller,
					false); err != nil {
					fmt.Fprintf(os.Stderr, "  %sestate sync: %v%s\n", dim, err,
						reset)
				}
			}()
			return nil
		},
	}
	srv.Detections = &admin.Detections{
		Load: func(now time.Time) (admin.DetectionView, error) {
			t, err := loadTuning(root, "", now)
			return admin.DetectionView{Rules: t.Rules, Stats: t.Stats,
				Proposals: t.Proposals, Suppressions: t.Suppressions,
				Hits: t.Hits}, err
		},
		Ring: func(rule string, ring detect.Ring, because, by string,
			kind audit.Kind) error {
			return setRing(root, "", rule, ring, because, by, kind)
		},
		Suppress: func(sp detect.Suppression) error {
			_, err := addSuppression(root, "", sp)
			return err
		},
		Unsuppress: func(id, by string, kind audit.Kind) error {
			return removeSuppression(root, id, by, kind)
		},
	}
	srv.Vulns = &admin.Vulns{
		Load: func(now time.Time) (admin.VulnView, error) {
			v, err := loadVulnView(root, now)
			seen := map[string]bool{}
			var assets []string
			for _, c := range v.Inventory {
				if a := c.Where.String(); !seen[a] {
					seen[a] = true
					assets = append(assets, a)
				}
			}
			sort.Strings(assets)
			return admin.VulnView{Advisories: v.Advisories,
				Tree: v.Tree, Tags: v.Tags, Assets: assets,
				Components: len(v.Inventory), Matched: v.Matched,
				Assessments: v.Assessments, History: v.History,
				AdvisoriesAt: v.AdvisoriesAt, InventoryAt: v.InventoryAt}, err
		},
		// From the screen an assessment always names something the screen
		// showed, so it is refused if the store does not know it.
		Assess: func(a vuln.Assessment) error {
			return recordAssessment(root, a, true)
		},
		Tag: func(tag vuln.AssetTag, by string) error {
			return setAssetTag(root, &Caller{Name: by, Kind: audit.KindHuman,
				Verified: true}, tag)
		},
		Untag: func(match, by string) error {
			return removeAssetTag(root, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, match)
		},
	}
	srv.Cases = &admin.Cases{
		List: func() ([]*incident.Incident, error) { return listIncidents(root) },
		Get: func(id string) (*incident.Incident, error) {
			return loadIncident(root, id)
		},
		Regimes: func() []string { return loadRegimes(root) },
		Playbooks: func() ([]incident.Playbook, error) {
			return loadPlaybooks(root)
		},
		Actions: func(id string) ([]admin.ActionOffer, error) {
			all, err := loadActions(root)
			if err != nil || len(all) == 0 {
				return nil, err
			}
			i, err := loadIncident(root, id)
			if err != nil {
				return nil, err
			}
			var out []admin.ActionOffer
			for _, a := range all {
				targets, terr := actionTargets(root, i, a, time.Now().UTC())
				if terr != nil {
					return nil, terr
				}
				out = append(out, admin.ActionOffer{Name: a.Name,
					Title: a.Title, Effect: a.Effect, Reverts: a.Reverts,
					Reversible: a.Reversible(), Targets: targets})
			}
			return out, nil
		},
		ActRequest: func(id, by, name, target, why string) error {
			return requestAct(root, id, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, name, target, why,
				time.Now().UTC())
		},
		ActApprove: func(id, by string, act int) (int, error) {
			return approveAct(root, id, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, act, time.Now().UTC())
		},
		ActUndo: func(id, by string, act int, why string) (int, error) {
			return undoAct(root, id, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, act, why,
				time.Now().UTC())
		},
		// Signed in to the admin: a person, verified.
		Declare: func(title string, grade incident.Grade, regimes,
			findings []string, by string) (string, error) {
			i, err := declareIncident(root, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, title, grade, regimes,
				findings, time.Now().UTC())
			if err != nil {
				return "", err
			}
			return i.ID, nil
		},
		Act: func(id, by string, a incident.Action) error {
			_, err := actOnIncident(root, id, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, a, time.Now().UTC())
			return err
		},
	}
	srv.People = func() map[string]string {
		aliases, err := loadAliases(root)
		if err != nil {
			return nil
		}
		out := make(map[string]string, len(aliases))
		for id, a := range aliases {
			out[id] = a.Person
		}
		return out
	}
	srv.Indicators = &admin.Indicators{
		List: func(now time.Time) ([]indicator.Indicator,
			map[string]admin.IndicatorHits, error) {
			set, err := loadIndicators(root)
			if err != nil {
				return nil, nil, err
			}
			q, err := loadQueue(root, now)
			if err != nil {
				return nil, nil, err
			}
			hits := map[string]admin.IndicatorHits{}
			for id, h := range countIntelHits(q) {
				hits[id] = admin.IndicatorHits{Findings: h.Findings,
					Real: h.Real, False: h.False, Last: h.Last}
			}
			return set.All(), hits, nil
		},
		Add: func(kind, value, source, note, until, by string) (int, int,
			bool, error) {
			now := time.Now().UTC()
			i, err := makeIndicator(kind, value, source, note, until, now)
			if err != nil {
				return 0, 0, false, err
			}
			res, err := takeIndicators(root, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true},
				[]indicator.Indicator{i}, indicator.Report{Read: 1}, now)
			return res.Hits, res.Opened, res.Known > 0, err
		},
		Remove: func(id, by string) error {
			return removeIndicator(root, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, id)
		},
	}
	srv.Reminders = &admin.Reminders{
		Preview: func(now time.Time) (remind.Config, []remind.Message,
			[]remind.Held, map[remind.Channel]string, error) {
			c, msgs, held, err := remindPlan(root, now)
			if err != nil {
				return c, nil, nil, nil, err
			}
			_, missing := remindSenders(root, c)
			return c, msgs, held, missing, nil
		},
		Ledger: func() ([]remind.Sent, error) { return loadLedger(root) },
		Enable: func(on bool, by string) error {
			// Signed in to the admin: a person, verified.
			return setRemindEnabled(root, on, by, audit.KindHuman)
		},
		Send: func(now time.Time, by string) (int, int, error) {
			return remindSendNow(root, now, by, audit.KindHuman)
		},
	}
	// The detection rules, with the shipped ones in place if the store had
	// none, read over what arrives and over this program's own log.
	if err := ensureRules(root, "server-start"); err != nil {
		fmt.Fprintf(os.Stderr, "  %s%v%s\n", dim, err, reset)
	}
	upkeepCtx, stopUpkeep := context.WithCancel(context.Background())
	defer stopUpkeep()
	// The audit log out to a SIEM as it is written, on its own quicker
	// timer; how it is going is kept where status reads it, and a failure
	// is not written to the log it is failing to send.
	go upkeep.Run(upkeepCtx, StreamEvery, func(upkeep.Job, int, error) {}, streamJob(root))
	go upkeep.Run(upkeepCtx, upkeep.Every, func(j upkeep.Job, n int, err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s%s: %v%s\n", dim, j.Name, err, reset)
			return
		}
		switch j.Name {
		case "estate":
			fmt.Printf("  %sestate: synced %s%s\n", dim, count(n, "tool"), reset)
		case "detect":
			if n > 0 {
				fmt.Printf("  %sdetect: opened %s%s\n", dim, count(n, "finding"), reset)
			}
		}
	}, upkeepJobs(root)...)

	// What people say about themselves. A display name and a way to reach
	// them, and deliberately nothing else.
	srv.Profile = &admin.Profile{
		Load: func() (map[string]admin.PersonDetails, error) { return loadProfiles(root) },
		Save: func(m map[string]admin.PersonDetails) error {
			return saveJSON(profilesPath(root), m)
		},
	}
	srv.ReloadTokens = tokenReloader(root, toks)
	srv.Version = version
	// The audit log, read-only. This process cannot write it where the writer
	// has been separated out, so there is no edit path to withhold.
	srv.LoadAudit = func() ([]audit.Event, error) {
		return audit.Read(auditPath(root))
	}
	srv.LogSeparated = func() bool {
		ok, _ := logd.CheckOwnership(auditPath(root), os.Geteuid())
		return ok
	}()
	// Forward matching only. The HMAC cannot be reversed; this computes the
	// pseudonym for each principal the store knows and compares, so somebody
	// the policy has never heard of stays opaque — which is itself worth
	// seeing on the page.
	srv.ResolvePrincipal = func(pseudonym string) string {
		l, err := openAudit(root)
		if err != nil {
			return ""
		}
		for _, name := range pol.Principals() {
			if l.Matches(pseudonym, name) {
				return name
			}
		}
		for _, t := range toks.Snapshot() {
			if l.Matches(pseudonym, t.Principal) {
				return t.Principal
			}
		}
		return ""
	}
	srv.Throttle = throttle.New(throttlePolicy(cfg))
	srv.OnAuthFailure = func(source string, failures int) {
		// ASVS 5.0 asks for a reaction above five failures an hour. An audit
		// record is the reaction: a SIEM rule can match it, and this program
		// does not send email.
		record(root, audit.Record{
			Action: "auth.failures", Resource: "/admin",
			// Unknown, not service: nobody proved who they were.
			Outcome: audit.Denied, Principal: source,
			Kind: audit.KindUnknown,
			Detail: map[string]string{
				"failures": fmt.Sprintf("%d", failures),
				"surface":  "admin",
			},
		})
	}
	// An identity provider, if one is configured. Discovery happens at startup
	// rather than on the first sign-in, so a misconfiguration is a failure to
	// start rather than a person who cannot log in and no information about why.
	if cfg, cerr := loadOIDC(root); cerr == nil && cfg != nil {
		secret := os.Getenv(oidcSecretEnv)
		if secret == "" {
			return fmt.Errorf(
				"%s is configured as the identity provider but %s is not set.\n"+
					"  Refusing to start rather than offering a sign-in button "+
					"that cannot work", cfg.Issuer, oidcSecretEnv)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		provider, derr := oidc.Discover(ctx, cfg.Issuer, fetch.For("sso"))
		cancel()
		if derr != nil {
			return fmt.Errorf("cannot reach the identity provider: %w", derr)
		}
		if err := provider.Warm(context.Background()); err != nil {
			return fmt.Errorf("cannot read the provider's signing keys: %w", err)
		}
		srv.OIDC = &admin.OIDC{
			Provider: provider, ClientID: cfg.ClientID, Secret: secret,
			RedirectURI: cfg.RedirectURI, Claim: cfg.Claim,
			RequireVerifiedEmail: cfg.RequireVerifiedEmail,
			Label:                cfg.providerLabel(), Tenant: cfg.Tenant,
			Domains: cfg.Domains, MFAACR: cfg.MFAACR,
		}
		if cfg.Provider == "google" {
			srv.OIDC.HostedDomains = cfg.Domains
		}
		srv.SaveTokens = func(ts *auth.TokenStore) error {
			return saveTokens(root, ts)
		}
		srv.OnSignIn = func(principal, tokenID string) {
			record(root, audit.Record{
				Action: "signin.oidc", Resource: "/", Outcome: audit.Success,
				// Verified, and this is the one place that word is fully
				// earned: the provider proved the identity cryptographically
				// rather than it being taken from an environment variable.
				Principal: principal, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{
					"issuer": cfg.Issuer, "session": tokenID,
				},
			})
		}
		fmt.Fprintf(os.Stderr, "  %ssign-in via %s%s\n", dim, cfg.Issuer, reset)
	}

	// SAML identity providers, read fresh on every use so one added from the
	// command line applies at once. Changes from the screen are recorded
	// here, under the person who made them.
	srv.SAML = &admin.SAMLAdmin{
		Providers: func() ([]saml.Config, error) { return loadSAML(root) },
		Fetch:     samlFetch,
		Save: func(c saml.Config) error {
			if err := saveSAML(root, c); err != nil {
				return err
			}
			record(root, audit.Record{Action: "saml.add", Resource: "/", Outcome: audit.Success,
				Principal: c.AddedBy, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"provider": c.Name, "entity": c.EntityID,
					"certs": fmt.Sprint(len(c.Certs)), "domains": strings.Join(c.Domains, ","),
					"required": fmt.Sprint(c.Required)}})
			return nil
		},
		Remove: func(name, by string) error {
			if err := removeSAML(root, name); err != nil {
				return err
			}
			record(root, audit.Record{Action: "saml.remove", Resource: "/", Outcome: audit.Success,
				Principal: by, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"provider": name}})
			return nil
		},
	}
	if srv.SaveTokens == nil {
		srv.SaveTokens = func(ts *auth.TokenStore) error { return saveTokens(root, ts) }
	}

	srv.Reload = func() (*auth.Policy, *auth.TokenStore, error) {
		pol, err := loadPolicy(root)
		if err != nil {
			return nil, nil, err
		}
		toks, err := loadTokens(root)
		if err != nil {
			return nil, nil, err
		}
		return pol, toks, nil
	}

	// Loopback by default. A console that binds every interface the moment
	// someone runs it is how a development server ends up on the internet,
	// and the fix has to be a decision rather than a default.
	//
	// The agent interface is mounted beside the console, on the same port
	// and outside the console's session middleware (mcp.go): it answers
	// bearer tokens, not cookies.
	mux := http.NewServeMux()
	mountMCP(mux, root, cfg, *addr)
	mountOAuthAS(mux, root, cfg, *addr, srv)
	mountOTLP(mux, root)
	mountCollector(mux, root)
	mux.Handle("/", srv.Handler())

	// Who each request came from is decided once, here, for everything
	// behind: limits, placing a sign-in, the audit log (internal/clientip).
	httpSrv := &http.Server{Addr: *addr,
		Handler: clientip.Middleware(proxies(root, "admin.trusted_proxy"), mux)}

	fmt.Printf("console on http://%s\n", *addr)
	if base := cfg.Raw("admin.base_url"); base != "" {
		fmt.Printf("  %sreached as %s (admin.base_url): links, feeds and OAuth all name it%s\n", dim, base, reset)
	}
	// A passkey belongs to a name, and a browser refuses an address as one,
	// so the loopback default is opened as localhost.
	if host, port, err := net.SplitHostPort(*addr); err == nil && (host == "127.0.0.1" || host == "::1") {
		fmt.Printf("  %sopen it as http://localhost:%s: passkeys need a name, not an address%s\n", dim, port, reset)
	}
	// People sign in with a passkey, two factors at once; somebody without
	// one is given a link that adds it. A token alone is one factor and
	// reaches only "Confirm it's you" (see mfa.go).
	fmt.Printf("  %ssign in with a passkey; somebody without one gets a link that adds it:%s\n", dim, reset)
	fmt.Printf("  %s    aertun auth enrol NAME   (on a new store, aertun init --owner NAME)%s\n", dim, reset)
	fmt.Printf("  %sagents reach it over MCP at http://%s/mcp with a token from 'aertun token issue', or 'aertun mcp' on stdio%s\n", dim, *addr, reset)
	fmt.Printf("  %san agent asking to act for somebody is consented to at http://%s/oauth/authorize; 'aertun agent consents' reviews what was agreed%s\n", dim, *addr, reset)
	if *openBrowser {
		// Not an error if it fails: a container, a machine over SSH and CI
		// have no desktop, and the address is on the line above.
		if !admin.Open("http://" + *addr) {
			fmt.Printf("  %snothing here knows how to open a browser; the "+
				"address is above%s\n", dim, reset)
		}
	}
	return listen.Uploads().Serve(httpSrv)
}

// sessionCaller is a person signed in to the console, verified, with the
// limits of the credential their session was made from. They cap what the
// session may do on the command line's side exactly as they do there.
func sessionCaller(by admin.Actor) *Caller {
	return &Caller{Name: by.Name, Kind: audit.KindHuman, Verified: true,
		Role: by.Role, Scope: by.Scope, Limits: by.Limits}
}

// upkeepJobs is everything the server does on its timer.
func upkeepJobs(root string) []upkeep.Job {
	return []upkeep.Job{estateJob(root), collectJob(root), detectJob(root)}
}
