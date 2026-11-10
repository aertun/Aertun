// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

// Package windtunnel is breach-and-attack simulation for a deployed agent
// stack, by replay: scripted malicious-agent sessions spliced into a recorded
// telemetry stream, measured by whether the organisation's own detections
// caught them, producing a signed scorecard. It attests test results, never
// production actions.
//
// It is not a new engine. Every part runs machinery that already runs: the
// detections are internal/detect's rules and internal/correlate's windows,
// replayed the way internal/pack's shadow replay replays them; the store is a
// scratch internal/spool; the metrics are internal/bench's; the signatures
// are internal/pack's discipline in a new context. The wind tunnel is a new
// subject for all of it.
//
// # The eleven decisions this package is built on
//
// 1. A SCENARIO IS DATA, NEVER CODE. A malicious agent session, as the SOC
// sees it, is a sequence of events — not a program. Nothing here executes:
// there is no interpreter to escape, a scenario reviews as a diff, and the
// same bytes replay against any pipeline (the content plane's whole thesis,
// applied to attacks).
//
// 2. BENIGN TWINS ARE MANDATORY. Every scenario carries the same event shape
// doing the legitimate version of the work, and nothing may fire on the twin.
// A scenario without a twin measures nothing about precision and is refused
// at load — the mirror of "a rule with no passing fixture is refused".
//
// 3. TWO CLOCKS, AND REPLAY HONOURS BOTH. Every event carries when it
// happened and when the program took delivery, and the victim's correlations
// are windowed on the first clock while their windows close on a watermark
// derived from the second. The splicer therefore synthesises arrival delay
// from the base stream's own measured distribution — never a constant — and a
// completing event that lands after its window closed is reported as a
// lateness miss, distinct from a content miss: a finding about the lateness
// budget, not about the rules.
//
// 4. MISS RATE IS PRIMARY, WITH WILSON BOUNDS. Per-scenario outcomes are
// categorical in the MITRE Evaluations tradition (never a naked percentage),
// and the aggregate is the miss rate over must-alert scenarios with a 95%
// Wilson interval — small samples are wide opinions, and dressing one as a
// point estimate is how benchmarks lie.
//
// 5. THE SCORECARD NAMES WHAT RAN BEFORE HOW IT WENT. Scenario digests, base
// stream digest, reference pack digest, mode — then the numbers. A number
// without those names is a claim rather than a measurement.
//
// 6. THREE SCORING MODES, TWO BUILT, THEIR RULES FIRST. their-Sigma mode
// is the primary one: it imports the organisation's own Sigma rules
// through the existing importer and joins at technique level, with the
// join's fidelity limit stated on every document it seals and import
// refusals counted rather than dropped. Reference mode scores against
// Aertun's own pack, whose rules the scenarios were written beside, so it
// is secondary and self-graded — a regression test of the pack — and
// every document and screen that shows its result says so. their-alerts
// mode is still refused with a
// message that says so, because a mode that half-runs would measure
// nothing while claiming to measure the org's controls. Modes are never
// pooled: a scorecard names its mode, and the diff refuses to compare
// across them.
//
// 7. THE DOCUMENT IS SEALED AND DUAL-SIGNED, IN CI. sha256 self-digest
// over the RFC 8785 canonical form, so any conforming canonicaliser
// recomputes the signed bytes, then Ed25519 and ML-DSA-65 both, in the
// context aertun/windtunnel-scorecard/v1 — a signature made for one
// purpose must never be presentable as one for another, so a scorecard
// cannot be promoted to a content-pack signature by whoever holds the
// file. The command signs only where the environment says it is CI,
// because the signing key belongs in a CI secret and a signature should
// attest a run from committed inputs, not whatever a laptop ran.
//
// 8. REPLAY IS THE SAFETY STORY, BY CONSTRUCTION. The exfiltration step is a
// log line about exfiltration, destined for a scratch spool; nothing is sent
// anywhere, nothing is spent, nothing is deleted. A synthetic-only scenario
// pointed at a live target is refused in code, not policy — the same shape
// as the OTLP boundary dropping content at parse time.
//
// 9. MTTD IS REDEFINED, AND THE CAVEAT IS STATED. A replay has no detection
// wall-clock. The scorecard reports event-time-to-attribution — the gap
// between the step that completed the pattern and the window that attributed
// it — a property of the rule windows, not of anybody's shifts.
//
// 10. THE CLI IS THE PRODUCT AND CI IS A CALLER. No subcommand opens the
// store; the corpus is embedded and synthetic; verify is offline. A benchmark
// that could not run in CI could not gate anything, and a bare word on a
// command line can neither start a live run nor spend anything.
//
// 11. THE PURPLE LOOP CLOSES, AND ONLY EVER PROPOSES. A miss whose events
// the telemetry carried — a content miss, or a session nothing alerted on —
// is drafted into a candidate rule by deterministic code, never a model: the
// narrowest predicate tree over the closed vocabulary the boundary declares
// (source, message, operation, tool, labels, disposition, issuer) that
// matches the session's separable events and refuses the twin's, proven by
// the engine's own Validate with the scenario's events as must-match
// fixtures and its twin's as must-not-match, then replayed over every spool
// the run wrote. A miss the telemetry cannot distinguish from its twin is
// declared a gap, not forced into a rule; a draft that fires on the base
// stream is refused with its count; and the proposal lands as a file a human
// promotes through the ring — the loop never writes the pack, because a
// detector that edits its own controls is the thing the ring exists to
// prevent.
package windtunnel
