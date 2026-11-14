// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/clientip"
	"github.com/aertun/aertun/internal/throttle"
)

// Every setting, in one table.
//
// A table rather than scattered constants for the same reason the privilege
// table is one: a knob nobody can find is a knob nobody can audit, and
// `aertun config list` has to be able to print all of them. Adding a setting
// anywhere else in the program is a setting that does not appear here, and a
// test refuses that.
//
// The Weaker functions are the interesting column. They are not "is this
// number bigger" — weaker is not always a direction. A longer token life is
// weaker because a stolen credential lasts longer. A longer lockout is also
// weaker, in the other direction, because it hands an attacker a way to lock
// real users out by failing their logins for them. Both are written out.
var settings = []Setting{
	// -- authentication throttling -------------------------------------------
	//
	// Always on, and each number held between hard bounds (internal/throttle):
	// a value outside them is refused, and no reason accepts it, because a
	// limit that can be raised far enough is no limit at all.
	{
		Key: "auth.throttle.after", Kind: Int, Default: "5",
		Summary:  "failures before delays begin",
		Params:   []string{"ac-07_odp.01"},
		Controls: []string{"AC-7"},
		Why: "ASVS 5.0 asks that more than five failures in an hour on one " +
			"account triggers a reaction. Five is that number. Raising it " +
			"buys tolerance for people who mistype, at the cost of giving an " +
			"attacker that many free attempts per window; NIST suggests no " +
			"more than 10, which is the most this accepts.",
	},
	{
		Key: "auth.throttle.ceiling", Kind: Int, Default: "100",
		Summary:  "failures per hour after which nothing is accepted",
		Params:   []string{"ac-07_odp.05"},
		Controls: []string{"AC-7", "IA-5"},
		Why: "ASVS 5.0 puts the ceiling at 100 failed attempts per hour on a " +
			"single account, which is the most this accepts. Past it the " +
			"account stops answering for the rest of the window however long " +
			"the caller waits. At least 10, because a ceiling a handful of " +
			"attempts reaches lets anybody keep a name's owner out for an hour.",
	},
	{
		Key: "auth.throttle.base", Kind: Duration, Default: "1s",
		Summary: "the first delay, doubling with each further failure",
		Params:  []string{"ac-07_odp.05"},
		Why: "The delay doubles: 1s, 2s, 4s, and so on to the maximum. A " +
			"person who mistyped waits a second; a script trying a dictionary " +
			"is stopped by the same rule without anybody deciding it is an " +
			"attack. At least a second, below which an attacker barely " +
			"notices it.",
	},
	{
		Key: "auth.throttle.max", Kind: Duration, Default: "15m",
		Summary:  "the longest a delay grows to",
		Params:   []string{"ac-07_odp.05"},
		Controls: []string{"AC-7"},
		Why: "The delay stops doubling here. This is deliberately not very " +
			"long, because the delay is a cost imposed on whoever is failing " +
			"and an attacker can be failing on somebody else's behalf. At " +
			"most an hour: longer is worth triggering deliberately, to keep " +
			"somebody out.",
	},
	{
		Key: "auth.lockout.alert", Kind: Int, Default: "5",
		Summary:  "failures in an hour that raise an audit alert",
		Params:   []string{"ac-07_odp.03"},
		Controls: []string{"AU-6", "SI-4"},
		Why: "ASVS 5.0: more than five failures per hour on one account " +
			"should trigger some reaction. Here the reaction is an audit " +
			"record a SIEM rule can match. Between 1 and 20: above that, a " +
			"slow credential-stuffing run stays under the alert and is never " +
			"reported.",
	},

	// -- tokens ---------------------------------------------------------------
	{
		Key: "token.ttl.default", Kind: Duration, Default: "168h",
		Summary:  "how long a new token lasts when no --ttl is given",
		Controls: []string{"IA-5(1)", "AC-2"},
		Why: "A week. A program that runs for longer exchanges its token for a " +
			"short one, or a CI job exchanges its platform's identity token and " +
			"keeps no token at all, so a token leaked into a log or a shell " +
			"history stops working within days.",
		Weaker: atMostDur(90*24*time.Hour, "a %s default means a leaked "+
			"token stays useful for that long, and nobody rotates what has "+
			"not expired"),
	},
	{
		Key: "token.ttl.max", Kind: Duration, Default: "2160h",
		Summary:  "the longest life any token may be issued with",
		Params:   []string{"ia-05_odp.01"},
		Controls: []string{"IA-5(1)"},
		Why: "Ninety days: a ceiling on --ttl, so a long-lived credential is a " +
			"decision somebody made against a limit rather than a number typed once.",
		Weaker: atMostDur(365*24*time.Hour, "%s is longer than a year, which "+
			"is longer than most people stay in a role"),
	},
	{
		Key: "token.api.ttl.default", Kind: Duration, Default: "1h",
		Summary: "default life of a token scoped for API use",
		Why: "Short, because an API token is issued to a program that can ask " +
			"for another one. This is the setting that makes `--api` tokens " +
			"short-lived without anybody remembering to pass --ttl.",
		Weaker: atMostDur(24*time.Hour, "an API token living %s is a long-"+
			"lived credential in a config file somewhere"),
	},

	// -- admin sessions ---------------------------------------------------------
	{
		Key: "session.max", Kind: Duration, Default: "8h",
		Summary:  "the longest a sign-in to the console lasts before signing in again",
		Controls: []string{"AC-12", "IA-11"},
		Params:   []string{"ac-12_odp"},
		Why: "Eight hours: a working day. Whatever signed somebody in — a token, a " +
			"passkey, single sign-on — the session it starts ends after this, and " +
			"signing out or revoking the credential ends it sooner. At most twelve " +
			"hours, the ceiling on any session this program issues.",
		Weaker: atMostDur(8*time.Hour, "a sign-in lasting %s outlives a working day, "+
			"so a browser left open overnight is still signed in in the morning"),
	},
	{
		Key: "session.idle", Kind: Duration, Default: "1h",
		Summary:  "sign out of the console after this long with nobody using the page",
		Controls: []string{"AC-2(5)", "AC-11", "AC-12"},
		Params:   []string{"ac-02.05_odp"},
		Why: "An hour, the most NIST SP 800-63B-4 allows at AAL2, and fifteen minutes " +
			"for anybody who can grant access. The page reports that somebody is " +
			"typing, scrolling or clicking, so a person writing a long note is not " +
			"signed out; it warns a minute before, keeps them signed in if they " +
			"answer, and afterwards lets them sign in again with their passkey " +
			"without leaving the page. Between five minutes and an hour.",
	},

	// -- the console and the network it is on ---------------------------------
	{
		Key: "admin.trusted_proxy", Kind: Bool, Default: "false",
		Summary: "the console is behind a proxy on this machine or a private network",
		Why: "Who is signing in, and from where: for the rate limits, for " +
			"lockout and for placing a sign-in. Behind a reverse proxy the " +
			"connection is the proxy's for everybody.\n\n" +
			"With this on and network.trusted_proxies empty, a forwarded " +
			"address is believed from a connection on the inside (loopback, " +
			"a private network); name the proxies in network.trusted_proxies " +
			"to believe only them. Off by default: X-Forwarded-For is a " +
			"header anybody can write, and believed from anybody it lets a " +
			"sign-in say where it is.",
	},
	{
		Key: "network.trusted_proxies", Kind: List, Default: "",
		Summary: "the proxies whose forwarded addresses are believed, as ranges or addresses",
		Why: "The one rule for who a request came from, on the console and " +
			"the feeds alike. A forwarded address is believed only when the " +
			"connection comes from one of these; the header is then read from " +
			"the right, past the proxies, and the first address that is not a " +
			"proxy is the client. Anything unreadable before that point is " +
			"an unknown client, never a guess.\n\n" +
			"Name what is actually in front: 10.0.0.5, or 10.0.0.0/8 for a " +
			"cluster, or a CDN's published ranges. Empty means no proxy, " +
			"unless admin.trusted_proxy says it is on the inside.",
		Weaker: func(v string) (bool, string) {
			for _, p := range strings.Split(v, ",") {
				pfx, err := clientip.ParseProxy(strings.TrimSpace(p))
				if err != nil {
					continue
				}
				if (pfx.Addr().Is4() && pfx.Bits() < 8) || (pfx.Addr().Is6() && pfx.Bits() < 16) {
					return true, pfx.String() + " is most of the internet: almost anybody " +
						"can then write their own address into a forwarded header"
				}
			}
			return false, ""
		},
		Controls: []string{"SC-7", "AU-3", "AC-7"},
	},
	{
		Key: "admin.base_url", Kind: Text, Default: "",
		Summary: "where people and programs reach the console, e.g. https://aertun.example.com",
		Why: "The address an enrolment link names, and the one a feed tells " +
			"the system pushing to it. Taken from each request's Host header " +
			"instead, anybody could have a link name an address of their " +
			"choosing. https, or http to this machine for trying it out; an " +
			"origin with no path.",
	},
	{
		Key: "admin.behind_tls_proxy", Kind: Bool, Default: "false",
		Summary: "the console is served over HTTPS by something in front of it",
		Why: "Whether the session cookie is marked Secure. Behind a reverse " +
			"proxy speaking HTTPS to the browser and plain HTTP to this, the " +
			"connection alone cannot say so. The cookie carries the session, " +
			"and without Secure a browser will send it over a plain-HTTP " +
			"request to the same host -- so one mixed-content link or one " +
			"downgraded request leaks a working credential.\n\n" +
			"An operator setting rather than a header, because the header " +
			"that would answer this is X-Forwarded-Proto and anybody can " +
			"write it. internal/httpsig already refuses to trust it and says " +
			"why. Trusting it here to decide whether a credential may travel " +
			"in clear would be the same mistake with a worse consequence, so " +
			"the deployment says once, deliberately, what it is.\n\n" +
			"Leave it off when the console is on loopback, which is the " +
			"default: a Secure cookie over plain HTTP is dropped by the " +
			"browser, and sign-in would stop working.",
	},
	{
		Key: "passkey.require_hardware", Kind: Bool, Default: "false",
		Summary: "enrol only authenticators that say what they are",
		Why: "A passkey synced through a platform account is a key that " +
			"exists in more than one place by design, and a verifier cannot " +
			"tell it from a hardware key by the signature — both produce a " +
			"valid assertion. The only thing that distinguishes them is what " +
			"the authenticator says about itself at registration.\n\nNIST " +
			"SP 800-63B AAL3 requires a hardware authenticator with a " +
			"non-exportable key, so a deployment at that level turns this " +
			"on. Everybody else should leave it off: turning it on without a " +
			"list of issued keys locks people out.",
	},
	{
		Key: "passkey.authenticators", Kind: Text, Default: "",
		Summary: "AAGUIDs this deployment enrols, comma-separated",
		Why: "The makes and models allowed to register, as the hyphenated " +
			"identifiers vendors publish. Empty means any that identifies " +
			"itself.\n\nWorth knowing what this proves: an AAGUID is " +
			"self-reported and this program does not verify the attestation " +
			"chain, because that needs FIDO metadata refreshed on a schedule " +
			"and an isolated network cannot refresh anything. Against " +
			"somebody plugging in a consumer key when policy says otherwise, " +
			"it works. Against hardware built to impersonate an approved " +
			"model, it does not — pair it with procurement, so that only " +
			"issued keys are ever enrolled.",
	},
	{
		Key: "network.mode", Kind: Text, Default: "open",
		Summary: "whether this deployment may reach the network: open or offline",
		Why: "offline refuses every connection that would leave this host, " +
			"before a packet is sent, and names the feature that wanted it, " +
			"which is what an isolated deployment needs.\n\nLoopback is " +
			"still permitted, because a " +
			"connection that does not leave the host is not egress and a " +
			"local model or identity provider is normal here. `aertun " +
			"network` prints every purpose, whether it is permitted, and " +
			"what stops working without it.",
	},
	{
		Key: "security.contact", Kind: Text, Default: "",
		Summary: "where the security team is reached, as mailto:, https: or tel: URIs",
		Why: "The first mailto: address is who an automation tells when it " +
			"acts, so a rule that disabled an account or ended a session is " +
			"never a surprise to the people answering for it. Several may be " +
			"given, comma-separated.",
	},
	{
		Key: "siem.stream.url", Kind: Text, Default: "",
		Summary:  "a SIEM to push the audit log to as it is written",
		Controls: []string{"AU-4(1)", "AU-6(4)", "AU-9(2)"},
		Why: "The audit log kept where this program cannot reach it, so a person who " +
			"takes the store over cannot take the record of it too. Batches of " +
			"OCSF, each following the last, carrying a signed tree head and an " +
			"HTTP message signature, so the receiver can prove nothing was " +
			"dropped or changed. Empty sends nothing; aertun siem exports by hand.",
	},
	{
		Key: "siem.stream.allow_remote", Kind: Bool, Default: "false",
		Summary: "permit a SIEM that is not on this machine or network",
		Why: "The audit log says who did what, when, from where. Sending it to " +
			"a hosted service is a disclosure that should be a sentence " +
			"somebody typed rather than a consequence of pasting an address. " +
			"Loopback and private addresses need no flag.",
		Weaker: onIsWeaker("the audit log leaves this network"),
	},
	{
		Key: "siem.stream.reveal", Kind: Bool, Default: "false",
		Summary: "send people's names in the stream instead of pseudonyms",
		Why: "The stream carries the pseudonyms the log keeps, which whoever " +
			"holds the log's key can turn back into names. Revealing them " +
			"hands every name to the receiving system and to whoever can read it.",
		Weaker: onIsWeaker("people's names leave in the audit stream"),
	},
	{
		Key: "ssf.transmit.receivers", Kind: List, Default: "",
		Summary:  "addresses that hear the agent kill switch, as SSF receivers",
		Controls: []string{"AC-2(3)", "AC-2"},
		Why: "Each entry is where a receiver listens for security event tokens " +
			"(https, or http to this machine), and may name the stored secret " +
			"holding its bearer token after a bar: URL|SECRET. When an agent " +
			"is disabled, a signed session-revoked event is pushed to every " +
			"entry, best-effort — a failed push is recorded and the local kill " +
			"stands. Empty means transmitting is off: the kill switch still " +
			"works, it says nothing to other platforms.",
	},
	{
		Key: "ssf.transmit.allow_remote", Kind: Bool, Default: "false",
		Summary: "permit a kill-switch receiver that is not on this machine or network",
		Why: "A session-revoked event names an agent and carries the reason a " +
			"person typed. Sending that to a hosted service is a disclosure that " +
			"should be a sentence somebody typed rather than a " +
			"consequence of pasting an address. Loopback and private " +
			"addresses need no flag.",
		Weaker: onIsWeaker("the kill switch's events leave this network"),
	},

	// -- compliance ------------------------------------------------------------
	{
		Key: NISTModeKey, Kind: Bool, Default: "false",
		Summary:  "refuse to weaken a setting while the NIST floors hold",
		Controls: []string{"AC-5"},
		Why: "A profile of defaults rather than a different program. While it " +
			"is on, a value that a setting's floor calls weaker is refused " +
			"outright — not accepted with a reason, and not waiting for a " +
			"second administrator. The floors it holds are exactly the " +
			"settings whose weakening would otherwise need that second " +
			"administrator: how long a token or a sign-in may last, what may " +
			"leave this network, and how much of the internet a forwarded " +
			"address may be believed from.\n\n" +
			"The two NIST caps this program is named for hold for every " +
			"deployment, mode or no mode, so the mode does not tighten them: " +
			"a console session nobody is using ends after an hour, and after " +
			"fifteen minutes for anybody who can grant access.\n\n" +
			"Turning the mode off is allowed and is recorded like any other " +
			"change; nothing is locked. The Compliance screen shows what the " +
			"mode holds and what the audit chain evidences.",
	},
}

// -- the shapes a floor takes ------------------------------------------------

// onIsWeaker is the setting whose being on gives something up.
func onIsWeaker(cost string) func(string) (bool, string) {
	return func(v string) (bool, string) {
		if b, err := strconv.ParseBool(v); err == nil && b {
			return true, cost
		}
		return false, ""
	}
}

func atMost(limit int, format string) func(string) (bool, string) {
	return func(v string) (bool, string) {
		n, err := strconv.Atoi(v)
		if err != nil || n <= limit {
			return false, ""
		}
		return true, fmt.Sprintf(format, v)
	}
}

func atMostDur(limit time.Duration, format string) func(string) (bool, string) {
	return func(v string) (bool, string) {
		d, err := time.ParseDuration(v)
		if err != nil || d <= limit {
			return false, ""
		}
		return true, fmt.Sprintf(format, d)
	}
}

// -- lookup -------------------------------------------------------------------

// Lookup finds a setting by key.
func Lookup(key string) (Setting, bool) {
	for _, s := range settings {
		if s.Key == key {
			return s, true
		}
	}
	return Setting{}, false
}

// All returns every setting.
func All() []Setting { return append([]Setting(nil), settings...) }

// hardBounds are the settings held between bounds no reason steps outside:
// a count, or a duration in nanoseconds. The throttle's are internal/throttle's;
// session.idle's are NIST SP 800-63B-4's AAL2 inactivity limit above and,
// below, the shortest a person reading a page is not interrupted by.
var hardBounds = map[string][2]int64{
	"auth.throttle.after":   {0, throttle.MostFree},
	"auth.throttle.ceiling": {throttle.LeastCeiling, throttle.MostCeiling},
	"auth.throttle.base":    {int64(throttle.LeastDelay), int64(throttle.LongestDelay)},
	"auth.throttle.max":     {int64(throttle.LeastDelay), int64(throttle.LongestDelay)},
	"auth.lockout.alert":    {1, throttle.LatestAlert},
	"session.idle":          {int64(5 * time.Minute), int64(time.Hour)},
}

// ErrOutOfBounds is a value outside a setting's hard bounds.
type ErrOutOfBounds struct {
	Key, Value, Least, Most string
}

func (e *ErrOutOfBounds) Error() string {
	return fmt.Sprintf("%s is outside its bounds, %s to %s", e.Value, e.Least, e.Most)
}

// shortDuration writes a duration as a person would: 1h, not 1h0m0s.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func (s Setting) bounds(n int64) error {
	b, ok := hardBounds[s.Key]
	if !ok || (n >= b[0] && n <= b[1]) {
		return nil
	}
	if s.Kind == Duration {
		return &ErrOutOfBounds{Key: s.Key, Value: shortDuration(time.Duration(n)),
			Least: shortDuration(time.Duration(b[0])), Most: shortDuration(time.Duration(b[1]))}
	}
	return &ErrOutOfBounds{Key: s.Key, Value: strconv.FormatInt(n, 10),
		Least: strconv.FormatInt(b[0], 10), Most: strconv.FormatInt(b[1], 10)}
}

// Validate checks a value against a setting's kind.
func (s Setting) Validate(v string) error {
	switch s.Kind {
	case Int:
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%q is not a number", v)
		}
		if n < 0 {
			return fmt.Errorf("%d is negative", n)
		}
		if err := s.bounds(int64(n)); err != nil {
			return err
		}
	case Duration:
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%q is not a duration (try 30s, 15m, 720h)", v)
		}
		if d < 0 {
			return fmt.Errorf("%s is negative", d)
		}
		if err := s.bounds(int64(d)); err != nil {
			return err
		}
		if s.Key == "session.max" && (d < 5*time.Minute || d > 12*time.Hour) {
			return fmt.Errorf("a sign-in lasts between 5m and 12h; %s is outside that", d)
		}
	case Bool:
		if _, err := strconv.ParseBool(v); err != nil {
			return fmt.Errorf("%q is not true or false", v)
		}
	case Text:
		if s.Key == "siem.stream.url" && v != "" {
			u, err := url.Parse(v)
			if err != nil || u.Host == "" || u.User != nil ||
				(u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
				return fmt.Errorf("%q is not an https address (http only to this machine)", v)
			}
		}
		if s.Key == "security.contact" {
			// URIs, as RFC 9116 requires. A bare address was accepted and
			// published as a Contact line no scanner can use, and the
			// automations that mail the security team read only mailto:,
			// so it also quietly told nobody.
			for _, c := range strings.Split(v, ",") {
				c = strings.TrimSpace(c)
				if c == "" {
					continue
				}
				scheme, rest, _ := strings.Cut(c, ":")
				switch strings.ToLower(scheme) {
				case "mailto", "https", "tel":
				default:
					return fmt.Errorf("%q is not a mailto:, https: or tel: "+
						"URI; for an address, give mailto:%s", c, c)
				}
				if strings.TrimSpace(rest) == "" {
					return fmt.Errorf("%q says how to reach somebody but "+
						"not who", c)
				}
			}
		}
		if s.Key == "admin.base_url" && v != "" {
			u, err := url.Parse(v)
			local := err == nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
			switch {
			case err != nil || u.Host == "" || u.User != nil:
				return fmt.Errorf("%q is not an address like https://admin.example.com", v)
			case u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(v, "/"):
				return fmt.Errorf("%q has more than a scheme and a host; give the origin only", v)
			case u.Scheme != "https" && !(u.Scheme == "http" && local):
				return fmt.Errorf("%q is not https; OAuth needs https except on this machine", v)
			case strings.ToLower(v) != v:
				return fmt.Errorf("%q has capitals; give it in lower case, as apps compare it exactly", v)
			}
		}
	case List:
		for _, p := range strings.Split(v, ",") {
			if strings.ContainsAny(p, " \t\r\n;'\"") {
				return fmt.Errorf("%q contains a character that cannot appear "+
					"in a list entry", p)
			}
		}
		if s.Key == "network.trusted_proxies" && strings.TrimSpace(v) != "" {
			if _, err := clientip.ParseProxies(strings.Split(v, ",")); err != nil {
				return err
			}
		}
		if s.Key == "ssf.transmit.receivers" && strings.TrimSpace(v) != "" {
			// Each entry is a receiver's address, and may carry the name of
			// the stored secret that holds its bearer token after a bar. The
			// address rule is siem.stream.url's: https, or http only to this
			// machine, because the push is signed but the line to it is not.
			for _, entry := range strings.Split(v, ",") {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				where, secret, _ := strings.Cut(entry, "|")
				u, err := url.Parse(where)
				if err != nil || where == "" || u.Host == "" || u.User != nil ||
					(u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
					return fmt.Errorf("%q is not an https address a receiver listens on "+
						"(http only to this machine)", where)
				}
				if secret != "" && (len(secret) > 64 ||
					strings.Trim(secret, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != "") {
					return fmt.Errorf("%q is not a secret name; letters, digits, dots, "+
						"dashes and underscores", secret)
				}
			}
		}
	}
	return nil
}

// IsWeaker reports whether a value gives up security relative to the default.
func (s Setting) IsWeaker(v string) (bool, string) {
	if s.Weaker == nil {
		return false, ""
	}
	return s.Weaker(v)
}

// isLoopbackHost reports a host name that is this machine.
func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
