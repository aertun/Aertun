<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/aertun-wordmark-dark.svg">
    <img src="docs/brand/aertun-wordmark-light.svg" alt="Aertun" width="300">
  </picture>
</h1>

<p align="center"><strong>The proving ground for AI security work.</strong></p>

<p align="center">
  Aertun checks what AI defenders produce — detection rules, triage verdicts,
  reviews — against evidence the AI did not write, and signs the result in open
  formats anybody can verify. Self-hosted, one binary, no dependencies.
</p>

<p align="center">
  <a href="https://github.com/aertun/aertun/actions/workflows/ci.yml"><img src="https://github.com/aertun/aertun/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-blue" alt="licence: Apache-2.0"></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="dependencies: 0"></a>
  <a href="https://aertun.github.io/"><img src="https://img.shields.io/badge/manual-aertun.github.io-informational" alt="manual"></a>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#why">Why</a> ·
  <a href="#proofs">Proofs</a> ·
  <a href="#the-wind-tunnel">Wind tunnel</a> ·
  <a href="#what-it-does">What it does</a> ·
  <a href="#who-may-do-what">Who may do what</a> ·
  <a href="#install">Install</a> ·
  <a href="https://aertun.github.io/">Manual</a>
</p>

---

One static binary written in Go, using the standard library only, with no
third-party dependencies. The few third-party assets it carries (a typeface,
icons, public data sets) are credited in [NOTICE](NOTICE).

## Quickstart

```bash
git clone https://github.com/aertun/aertun aertun && cd aertun
go build -o aertun ./cmd/aertun      # Go 1.27 or later, nothing to fetch

./aertun init --owner you@example.com   # a store, its Owner, and the link that adds your passkey
./aertun serve                          # the console, on http://localhost:8080
```

Open the link `init` printed and add a passkey, and you are signed in as the
store's Owner. There is no default password and no default account, and
everybody signs in with two factors.

The first screen is **Today**: what is waiting for you to decide, then what is
wrong in the parts of the estate you work in. **Get started** walks the four
things that make it useful: bring events in, decide what counts as wrong, know
the estate, and decide who else may do what.

## Why

Finding weaknesses, attacking and triaging have all been automated. Deciding
which of those outputs to believe has not: Anthropic says progress on
AI-found vulnerabilities "is now limited by how quickly we can verify,
disclose, and patch"
([May 2026](https://www.anthropic.com/research/glasswing-initial-update)),
and AI SOC vendors grade their own accuracy while independent replay
benchmarks find no model passing
([Simbian](https://simbian.ai/research/cyber-defense-benchmark)).

Aertun is the check that does not trust the author. Today it proves
detection rules, replays attacks on AI agents through your detections, and
runs on a complete security-operations core: collection, detection, triage,
response, exposure and a tamper-evident record. Proving AI analysts' verdicts
on your own closed cases comes next.

## Proofs

A proof is a claim about security work, checked by a program against
evidence the work's author did not write, and signed whatever the verdict:
**proven**, **refuted** (naming what failed), or **inconclusive** (nothing
failed, but nothing could have). It is an [in-toto](https://in-toto.io/)
statement in a [DSSE](https://github.com/secure-systems-lab/dsse) envelope,
signed with Ed25519 and ML-DSA-65; the Ed25519 half is plain DSSE, so
Sigstore and in-toto tooling read it without this program.

The first verifier is for detection rules — usually ones a model drafted:

```bash
./aertun content keygen --out root.key   # once: a signing key in the store; move root.key away
./aertun proof detection --rule rule.json --corpus corpus.jsonl \
    --key .aertun/content/release.key --public-key proof-key.json --out rule.proof.json
./aertun proof verify --key proof-key.json --subject rule.json rule.proof.json
```

It checks the rule is valid, that its own fixtures hold, and that over a
labelled corpus it fires on every entry labelled as its own and on nothing
else it reads — a false positive somebody recorded and nobody fixed still
refutes it. The proof names every input by digest and reports recall and
specificity as 95% Wilson lower bounds, so a proof over one example reads as
the weak thing it is. Without a corpus the best verdict is inconclusive:
`verify` exits non-zero on anything but proven, which makes it a CI gate.

A calibration certificate for the AI analyst's threshold (`aertun analyst
calibrate`, below) is a proof of the same shape, and `proof verify` checks
it the same way.

## The wind tunnel

`aertun windtunnel run --sigma DIR` replays scripted malicious-agent
sessions — an injection through an issue, an MCP server's rug-pull, a
read-then-exfiltrate chain, a slopsquatted install, a runaway cost loop, a
blind window in the recorder — through a recorded telemetry stream in a
scratch store, and measures whether your own Sigma rules caught them. Each
scenario is data, never code, and ships with a benign twin that must raise
nothing. The scorecard names what ran before how it went (scenario
digests, the stream's digest, your rules' digest and what the importer
refused), and reports the miss rate first as k of n with Wilson bounds.
`windtunnel diff` is the CI gate between two runs.

`--mutate N` replays N respellings of each session as well: the URLs,
tool-call paths and shell command lines the attacker types, rewritten by
equivalences their consumer applies (RFC 9110 URL normalisation, POSIX
pathname resolution, POSIX shell quoting) — never letter case alone, and
never a field the attacker does not spell. The scorecard adds the miss
rate under mutation, k of n with Wilson bounds. Variants are deterministic:
the same scenario and variant number give the same bytes.

Run without `--sigma`, it scores Aertun's own rule pack instead. The six
scenarios that ship were written beside those rules, so that result is
self-graded — a regression test of the pack, not an independent
measurement — and every screen and document that shows it says so.

The scorecard's digest covers its RFC 8785 canonical form, so any
conforming canonicaliser can recompute it. It is dual-signed (Ed25519 and
ML-DSA-65) only in CI: `--key` is refused unless `CI=true`, and the
repository's own CI job signs on pushes to main with a key held in a
secret, skipping (and saying so) when the secret is absent. `aertun windtunnel verify --key
PUBLIC-KEY CARD` checks a signed card offline.

## What it does

| | |
|---|---|
| **Collect** | Connectors that read other tools with stored credentials, scheduled collection, log files, and feeds other systems push to: an identity provider's security events (SSF, CAEP, RISC), Okta event hooks, signed webhooks, and Quilzo's audit log, checked record by record against its signed chain. Every event is mapped to one shape and kept, append-only, before anything reads it. |
| **Detect** | Detection rules written here or imported as Sigma, each with fixtures that must match and must not, and MITRE ATT&CK technique IDs. A new rule runs in a trial ring that records what it would raise until its record earns it the queue. Correlations across rules and platforms, suppressions that end, and indicators of compromise imported from STIX 2.1 bundles or plain lists. |
| **Triage** | One queue of findings, ranked by risk, with every decision kept and replayable. An AI analyst writes the first pass as a suggestion that a person agrees with or not; it has no way to record a decision itself. |
| **Respond** | Cases and incidents with the notification clocks each law starts (GDPR, NIS2, DORA, the Cyber Resilience Act, SEC, CIRCIA, HIPAA), playbooks for account compromise, phishing, malware, lost devices and exposed data, and actions on other platforms (suspend an Okta account, end its sessions) asked for by one person and approved by another. Automations that watch, ask, or act, within limits. |
| **Exposure** | Vulnerabilities of the estate ranked with CISA KEV and EPSS, decided with SSVC and published as OpenVEX; dependency scanning from CycloneDX and SPDX SBOMs against OSV; code-scanning results from SARIF; workforce and device risk from the company's own tools; vendor risk; reminders to people who have something to do; and access reviews closed by the next import. |

## AI that cannot be talked into anything

A security tool that puts a language model in front of log data hands the
model text written by attackers. Aertun is built so that the worst an AI can
do is be wrong in a suggestion:

- **The AI analyst's plan is fixed in code before anything untrusted is
  read.** Nothing a log line says can add a step.
- **Counts and quoted text are kept apart.** The model is given numbers and
  closed words the program worked out, and, separately and marked as such,
  the text somebody else wrote.
- **The output is one word from a closed set, with a confidence.** Below the
  threshold it is not even shown. The reason a person reads is assembled from
  the counts, never from what the model wrote, so a prompt injection in a log
  cannot reach the screen of whoever decides.
- **The threshold can be measured rather than declared.** `aertun analyst
  calibrate` puts the findings verified people have ruled to the configured
  model and fits the lowest threshold at which closing suggestions on
  findings people ruled real stay under a stated rate (`--epsilon`) with
  stated confidence (`--delta`): a Clopper–Pearson bound, corrected for every
  candidate threshold examined. The result is a signed certificate naming
  the model, the adapter (`AERTUN_MODEL_ADAPTER_SHA256`) and the prompt
  template by digest, with exact counts and an expiry. `aertun analyst triage
  --calibration FILE --calibration-key KEY` gates on it; a certificate that
  has expired, does not verify, or was fitted for another model, adapter or
  template is refused and every answer goes to a person, and the run says
  so; so does an answer not scored on the channel the certificate was fitted
  on. Where the endpoint returns token probabilities, they are a second
  score beside the stated confidence, and a certificate names which one it
  was fitted on.
- **A privacy guard sits in front of every model call.** Personal data and
  credentials are masked before the prompt leaves and restored in the answer,
  and invisible characters are removed first.
- **It works with any OpenAI-compatible endpoint**, hosted or local
  (`AERTUN_MODEL_URL`, `AERTUN_MODEL_KEY`, `AERTUN_MODEL`), and with none: the
  model is an aid, never a dependency.

AI agents reach Aertun through its **MCP server**: eight operations behind three
tools, which an agent loads only as it searches for them. They list and read
findings, cases, detection statistics, the vulnerability plan and the estate in
numbers, and propose a decision on a finding for a person to make. A proposal
is shown last on the finding's page, closed until opened, named for the agent
that wrote it and marked as written by a model that read attacker-controllable
evidence. Agents cannot change who may do what, approve an action or a
privileged change, or reach another platform. Every call is recorded, and what
models did reaches the same detection engine as every other platform's events.

To put the same investigation to an agent twice, `aertun twin record --out
FILE` writes what those operations would answer now to one file under its
sha256 digest, and `aertun mcp --twin FILE` answers from that file alone: the
same bytes every time, every value labelled with whether an attacker could have
written it, proposals refused, and a file that no longer matches its digest
refused outright.

## Integrations

**Connectors** (read through each tool's API, credentials kept in Aertun's
vault): Okta, Microsoft Entra ID, GitHub, EVM smart contracts through a
Blockscout explorer, KnowBe4, ManageEngine Endpoint Central, ManageEngine MDM
Plus, Vanta, and the OpenAI and Anthropic organisation audit logs.

**Log sources** mapped to one event shape: AWS CloudTrail, Microsoft Entra ID,
Microsoft Azure, Google Workspace, Google Cloud, Okta, Duo, CrowdStrike Falcon,
Jamf Pro, GitHub, Kubernetes, Cloudflare, Salesforce, Slack, Snowflake, Linux
auditd, EVM chains, the OpenAI and Anthropic audit logs, and GenAI agent
telemetry over OTLP (OpenTelemetry's HTTP/JSON trace export: agent, tool and
model calls, with prompts read for size and never stored).

**Standards**: OCSF, Sigma, MITRE ATT&CK, STIX 2.1, SSF/CAEP/RISC, CycloneDX,
SPDX, OSV, OpenVEX, SSVC, CISA KEV, EPSS, SARIF, MCP, OpenID Connect, SAML 2.0,
SCIM 2.0 and WebAuthn passkeys.

## Who may do what

A store starts with one person, its **Owner** (`aertun init --owner NAME`).
Everybody else is a collaborator: an administrator grants them a role and
sends the one-time link `aertun auth enrol NAME` prints.

| Role | May |
|---|---|
| `viewer` | read findings, cases, the vulnerability queue and the dashboards |
| `analyst` | triage findings, open cases and add notes to them, hunt through events |
| `responder` | run cases, ask for an action on another platform, approve somebody else's action, accept a risk |
| `admin` | manage people, connectors and their credentials, and settings |

Each role includes the ones above it. Beside them are jobs, for a different
kind of work rather than more of it: an `engineer` tunes detections and
automation rules, a `vuln-manager` decides vulnerabilities, and an `auditor`
reads the queue and the audit log for a set time, after which the grant ends
by itself. A grant can be limited to the security area (`--on /@security`),
can end (`--for 30d`), and a deny always wins. That is the whole model —
`aertun auth roles` prints it in full — and there are deliberately no custom
roles, because assembling permissions is how a role surface stops being
reviewable.

What stops one person, or one stolen session, acting alone is not a setting:

- The **Owner** always administers the whole store. Nobody can revoke, deny
  or expire that — not another administrator, not single sign-on
  provisioning. Ownership moves only when the Owner asks for a transfer
  (`aertun auth owner transfer NAME`) and confirms it a day later; anybody
  with an administrator's session can decline it before then.
- Making somebody an administrator, issuing an administrator's token,
  weakening a setting and moving the audit log each take a second
  administrator. **An only administrator is not blocked but slowed**: their
  own request waits an hour (a day to move the audit log), is raised by
  Aertun's detections over its own audit log, can be declined from any administrator's
  session, and only then may they approve it themselves. A stolen session can
  start a takeover; it cannot finish one before somebody has had the chance
  to see it.
- **Agents propose; people decide.** An AI agent's authority is the
  intersection of its registry entry, the live grants of the person it acts
  for, and its token's own limits. It may ask for a privileged change, never
  approve one, and never approve an action on another platform.
- An action on another platform is approved by somebody other than whoever
  asked, and whoever wrote an automation rule does not approve the runs it
  holds.
- Everybody signs in with a passkey that checks it is them (user
  verification), or through single sign-on that says it used two factors
  (NIST SP 800-63B-4). Failed sign-ins lock out the places they come from,
  not the person. Sessions end after an hour unused, and after fifteen
  minutes for administrators.

## Three ways in

Everything is reachable from the console, from the command line
(`aertun help`), and from AI agents over MCP (`aertun mcp --list`). A test
fails when a command has no screen and no written reason, or no MCP operation
and no written reason.

## Its own record

Every change is written to an append-only audit log: a hash chain, a Merkle
tree over it, tree heads signed with Ed25519 and ML-DSA (post-quantum), and the
head committed to Bitcoin through OpenTimestamps (`aertun auditlog anchor`).
The log writer can run as its own account (`aertun logd`), so the console
cannot rewrite what it recorded.

The log can also be sent to another SIEM as it is written (`siem.stream.url`):
batches of OCSF, each following the last, carrying a signed tree head and an
HTTP message signature (RFC 9421), so the receiver can prove nothing was
dropped or changed.

## Install

From source, as above, or with `make install`, which installs `aertun` and
`aertun-collector`. There is no tagged release yet. When there is, the release
workflow publishes static binaries for Linux, macOS and Windows with build
provenance, and a container image, `ghcr.io/aertun/aertun`: the binary alone
on `gcr.io/distroless/static-debian12:nonroot`, with no shell. See
[INSTALL](INSTALL).

```bash
docker build -t aertun .
docker run --rm -v aertun:/srv aertun --root /srv/store init --owner you@example.com
docker run -p 8080:8080 -v aertun:/srv aertun
```

Behind a reverse proxy, set `admin.behind_tls_proxy` and `admin.base_url`;
[deploy/](deploy/) has a systemd unit and a Caddy configuration.

## Licence

Apache-2.0. Copyright 2026 Rashik Adhikari. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Security reports: [SECURITY.md](SECURITY.md).
