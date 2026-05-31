# context.md — Build Context & Architecture

> Working name: **Quarantine** (swap freely). Tagline: *"A multi-agent guardrail that detonates every new dependency in an isolated sandbox before it touches your code."*
>
> This file is the single source of truth for the build. It is written so a human teammate OR an AI coding tool can read it and know exactly what to build, in what order, and why. Read this top-to-bottom before writing code.

---

## 0. Event constraints (do not forget)

- **Event:** Multi-Agent Orchestration Build Day — May 31, 2026, The Engine, Cambridge MA.
- **Building starts:** 11:30 AM. **Draft submission:** 7:00 PM. **Final submission:** 8:00 PM.
- **Eligibility:** public GitHub repo, built entirely at the event, in-person demo, not employed by a sponsor.
- **Prizes we target:** "Most Sophisticated Harness" (1st/2nd/3rd) AND "Best Use of Weave" ($1,000).
- **Judging criteria:** Agent Orchestration · Utility · Technical Execution · Creativity · Sponsor Usage.
- **Hard rule:** STOP CODING AT 6:30 PM. Record the <2 min demo video. Submit draft by 7:00.

---

## 1. The problem (the pitch)

Modern supply-chain attacks (e.g. the **March 2026 LiteLLM hijack**, recent npm credential stealers) fire their payload **at install/runtime**, not in source you read. A malicious `postinstall` hook runs `printenv`, scrapes `~/.aws` / `~/.ssh` / `.env`, zips it, and exfiltrates it to an attacker server — the moment you install. **Static CVE scanners miss this** because the malicious version isn't in any database yet (zero-day) and nothing looks wrong until the code *runs*.

AI coding agents make this worse: they install packages blindly and are prone to **hallucinated / typosquatted** package names that attackers pre-register as traps.

**Our solution:** intercept every `npm install`, **detonate the package in an isolated honeypot sandbox seeded with fake credentials**, and let a multi-agent system watch what the package *does*. If it reads honeytokens or tries to phone home, we block it before it ever runs in the real workspace — and hand the AI/dev a safe remediation. Every agent step is traced in **W&B Weave**.

---

## 2. Core mental model (READ THIS — common confusion)

- **We are NOT the attacker.** The **package itself** is the attacker. We are the *victim + the security camera*.
- We set a trap (fake creds), run the **real** `npm install` inside the sandbox, and **observe** whether the package springs the trap.
- A **benign** package makes zero outbound calls during install and never touches `~/.aws` etc. **Any** such behavior during install is itself the signal.
- For the demo we cannot pull live malware onto venue WiFi, so we **author our own harmless "evil" test package** (see §6) that behaves exactly like real malware against *fake* credentials. It is the attacker in our demo; our system catches it.
- **Detection happens at the OS boundary** (network egress + filesystem syscalls), **NOT** by monkey-patching `process.env` inside a single Node process. Reason: `postinstall` scripts run as separate child processes (could be bash/python/binary), so in-process JS hooks never see them.
- **Weave observes/records — it does not block.** Blocking is done by our interceptor + orchestrator verdict. Weave is the evidence layer + eval dashboard.

---

## 3. Architecture

### 3.1 High-level flow

```
AI agent / dev runs:  npm install <pkg>
        │
        ▼
[ Interceptor ]  ── pauses the install; real workspace NOT modified yet
        │  sends {pkg, version} to orchestrator over local socket/HTTP
        ▼
[ Orchestrator ]  ── dynamic decision graph (NOT a linear pipeline)
        │
        ├──▶ [ Intel Agent ]      fast/cheap: OSV/CVE, npm metadata, typosquat
        │        └─ if clearly malicious → SHORT-CIRCUIT, skip sandbox
        │
        └──▶ [ Sandbox/Detonation Agent ]   (only if inconclusive / escalated)
                 └─ spins Docker container, seeds honeytokens,
                    runs `npm install <pkg>` behind egress proxy + syscall monitor
                 └─ collects raw telemetry (network logs, file-access, install scripts)
                        │
                        ▼
              [ Telemetry / Reasoning Agent ]  (Claude)
                 └─ turns raw telemetry into a verdict + human-readable evidence
                        │
                        ▼
              [ Verdict ]  ── safe → allow install in real workspace
                              malicious → BLOCK + [ Fix Agent ] suggests safe alternative
        │
        ▼
( every agent op wrapped in Weave; eval dataset scored in Weave )
```

### 3.2 Agents (each is a `@weave.op`-wrapped unit)

| Agent | Job | Inputs | Outputs | Tools/APIs |
|---|---|---|---|---|
| **Interceptor** | Catch `npm install`, pause it, ask orchestrator, enforce verdict | shell command | allow/block decision | npm wrapper / shim binary, local socket |
| **Orchestrator** | Route dynamically, decide escalation, compile final report | pkg manifest | verdict + report | own logic; Weave tracing |
| **Intel Agent** | CVE/OSV lookup, npm registry metadata (age, version velocity, maintainer change), typosquat distance | pkg name+version | risk signals | OSV.dev API, npm registry API, edit-distance check |
| **Sandbox/Detonation Agent** | Spin isolated container, seed honeytokens, run install behind monitoring, gather telemetry | pkg name+version | raw telemetry blob | Docker (dockerode/CLI), egress proxy/firewall, strace/inotify |
| **Telemetry/Reasoning Agent** | Interpret telemetry → verdict + evidence narrative | telemetry blob | {verdict, score, evidence} | Claude API |
| **Fix Agent** | Propose safe alternative + remediation message | malicious verdict + context | structured remediation | Claude API |

### 3.3 Orchestration intelligence (this earns the "Orchestration" score)

The orchestrator must make the routing **visible and dynamic**, not run every agent every time:
- Intel says "known-malicious / typosquat" → **stop**, never spend time detonating.
- Intel says "inconclusive but ownership recently transferred / brand-new version" → **escalate** to detonation with higher priority.
- Intel says "well-established, no signals" → optionally still detonate (cheap insurance) or fast-pass.

The escalation decision itself is a logged event in Weave — "Intel flagged ownership-transfer → orchestrator escalated to detonation" is the story for judges.

---

## 4. The detonation sandbox (the hero component)

This is what makes us more than a linter. Build it carefully but minimally.

### 4.1 Setup per detonation
1. Launch a disposable container (Node base image). Network **default-deny**, all egress routed through a logging proxy we control.
2. Seed honeytoken files at expected paths, each with a **unique canary string** per run:
   - `~/.aws/credentials` (fake `AKIA...` + secret)
   - `.env` (fake `OPENAI_API_KEY`, `DATABASE_URL`)
   - `~/.ssh/id_rsa` (fake key blob)
   - container env vars too (`AWS_ACCESS_KEY_ID=CANARY_<uuid>`)
3. Run `npm install <pkg>` inside the container (lifecycle scripts ENABLED — that's the point).

### 4.2 What we monitor (OS boundary)
| Signal | How |
|---|---|
| Network exfiltration | Egress proxy / default-deny firewall logs every connection attempt. If the **canary string** appears in any outbound payload → caught. |
| Any network during install | Benign install = zero post-fetch egress. Any connection attempt during `postinstall` is suspicious by itself. |
| Sensitive file reads | `strace -f -e trace=open,openat,connect` on the install process, or `inotify` watch on honeytoken paths. |
| Credential/env access | Honeytoken canary appearing anywhere downstream (network, written files) proves the package read it. |

### 4.3 Output
A structured telemetry blob: list of network attempts (dest, payload-contains-canary?), list of sensitive file accesses, the raw `preinstall`/`postinstall` script text. This blob feeds the Reasoning Agent.

---

## 5. W&B Weave integration (the "Best Use of Weave" prize)

Treat Weave as a core primitive, not a logger.

1. **Hierarchical tracing:** wrap every agent op in `@weave.op()` so judges see a nested trace: orchestrator → intel → escalation decision → detonation → reasoning → verdict → fix.
2. **Eval harness (the differentiator):** build a small labeled dataset — ~5 malicious (our evil test pkg + a few crafted variants) + ~10 benign real packages. Run it through `weave.Evaluation` and show a live **precision / recall / F1** dashboard proving the system actually works.
3. **Cost/latency:** surface token + latency per agent from Weave in the final pitch.
4. **(Stretch) Feedback loop:** UI button to flag false positive/negative → captured into a Weave dataset = "production data flywheel" story.

---

## 6. The evil test package (demo determinism)

Author a local npm package (e.g. `evil-demo-pkg`) that, in its `postinstall`:
1. Reads the seeded honeytoken files / env vars.
2. Attempts to POST their contents to an external URL (which our firewall blocks).

It only ever sees **fake** creds and its egress is blocked, so it is harmless — but it trips every detector exactly like the real LiteLLM payload. This makes the on-stage demo deterministic and reproducible. Keep one benign package handy too (e.g. `lodash`) to show a clean PASS.

> ⚠️ Do NOT install real-world malware on venue WiFi. The evil test package is the only "malicious" thing we run.

---

## 7. Self-healing — SCOPED DOWN (do not over-build)

The flashy "silently rewrite the AI's code via AST" idea is a time-trap and looks scary to judges. For today:
- On a malicious verdict, the **Fix Agent returns a structured remediation** ("package X is malicious — evidence: canary leaked to <host>; use Y instead; here's the import change") and the AI agent/dev applies it.
- Full AST mutation = "future work" slide only.

---

## 8. Tech stack

- **Language:** Node/TypeScript for interceptor + sandbox orchestration (npm-native); Python acceptable for agent layer if the team prefers Weave's Python SDK. Pick ONE primary; don't split brain.
- **LLM:** Claude API (latest model) for Reasoning Agent + Fix Agent.
- **Intel:** OSV.dev API, npm registry API, local typosquat edit-distance check.
- **Sandbox:** Docker (via CLI or `dockerode`). Egress via mitmproxy or iptables default-deny + log. Syscall via `strace`; file watch via `inotify`.
- **Observability:** W&B Weave (`@weave.op`, `weave.Evaluation`).
- **UI:** minimal — a terminal UI (Ink) or a tiny Next.js page showing the live agent graph + verdict. UI is LAST priority.

---

## 9. Build timeline (7.5 hrs)

| Time | Milestone | Focus |
|---|---|---|
| 11:30–1:00 | Core plumbing | Interceptor stub; orchestrator skeleton; Intel agent hitting OSV/npm; parse pkg name. |
| 1:00–3:00 | Detonation + Weave | Docker container that seeds honeytokens + runs install behind egress logging. Wrap EVERY op in `@weave.op` from the start. Reasoning agent reads telemetry. |
| 3:00–5:00 | Harness upgrade | Evil test package working end-to-end (caught!). Build Weave eval dataset + first `weave.Evaluation` run. Dynamic escalation logic in orchestrator. |
| 5:00–6:30 | UI + edge cases | Minimal dashboard / TUI showing the live agent graph + verdict + Weave trace link. Benign-package clean pass. |
| 6:30–7:30 | Record + submit | STOP CODING. Record <2 min demo (catch evil pkg → Weave trace → remediation). Submit draft by 7:00. |

### Priority if short on time
1. **Must:** interception → orchestrator routing → Docker detonation w/ honeytoken + egress block → Claude reasoning → verdict → Weave trace. (Complete winning demo on its own.)
2. **Nice:** Weave eval dashboard (precision/recall).
3. **Stretch:** Fix Agent remediation applied by AI coder.
4. **Cut:** silent AST rewriting; MCP-server-per-agent unless near-free in your framework.

---

## 10. Demo script (the 3-minute stage run)

1. One sentence problem: "Static scanners missed LiteLLM because the payload only fires at runtime."
2. AI agent runs `npm install evil-demo-pkg`. Interceptor pauses it.
3. Show orchestrator routing: Intel inconclusive → escalate to detonation.
4. Sandbox detonates; show the **canary string leaving the box** getting blocked — the hero shot.
5. Reasoning agent verdict + evidence; install BLOCKED in real workspace; Fix agent suggests alternative.
6. Show the **Weave nested trace** + **eval dashboard** (precision/recall).
7. Repeat once with a benign package → clean PASS (proves no false positives).

Winning one-liner:
> "Static scanners missed LiteLLM because the payload only fired at runtime. We detonate every new dependency in an isolated sandbox seeded with fake credentials, and a multi-agent system watches what it *does* — then blocks it before it touches the real workspace. Here it is catching a zero-day-style exfiltration live."

---

## 11. Submission checklist (AGI House platform)

- [ ] Unique team name
- [ ] All member names + emails + socials (X / LinkedIn)
- [ ] <2 min screen-recording demo
- [ ] Public GitHub repo
- [ ] Project description: 2–3 sentence summary; what it does + problem solved; how it's built (orchestration protocols, frameworks, tools); **list every sponsor tool used and how** (W&B Weave!).
