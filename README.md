# 🛡️ Quarantine

> A multi-agent guardrail that **detonates every new dependency in an isolated sandbox before it touches your code.**

Built at **Multi-Agent Orchestration Build Day** — May 31, 2026, The Engine, Cambridge MA (AGI House × W&B × TNT × SundAI Club × E14).

---

## The problem

Modern supply-chain attacks fire their payload **at install/runtime**, not in source code you read. In the **March 2026 LiteLLM hijack**, a malicious release dumped environment variables, scraped `~/.aws` and `~/.ssh`, and exfiltrated them to an attacker server **the moment it was installed**. Static CVE scanners miss this because the malicious version is a zero-day — nothing looks wrong until the code *runs*.

AI coding agents make it worse: they install packages blindly and fall for **typosquatted / hallucinated** package names that attackers pre-register as traps.

## What Quarantine does

Quarantine intercepts every `npm install`, **detonates the package in an isolated honeypot sandbox seeded with fake credentials**, and lets a team of agents watch what the package actually *does*. If it reads the honeytokens or tries to phone home, Quarantine blocks the install before it ever runs in your real workspace — and hands you (or your AI agent) a safe remediation.

We are not the attacker. The **package** is the attacker. We're the victim and the security camera.

## How it works

```
npm install <pkg>
   └─ Interceptor pauses the install (real workspace untouched)
       └─ Orchestrator (dynamic routing, not a linear pipeline)
           ├─ Intel Agent     → OSV/CVE, npm metadata, typosquat check
           │                    (clearly malicious? stop here)
           └─ Sandbox Agent   → detonate in Docker w/ honeytokens,
                                 behind an egress proxy + syscall monitor
                 └─ the package itself tries to steal creds / call out
                 └─ Reasoning Agent → verdict + human-readable evidence
       └─ Verdict: safe → allow │ malicious → BLOCK + Fix Agent suggests alternative
   └─ every step traced in W&B Weave
```

### The agents

| Agent | Role |
|---|---|
| **Interceptor** | Catches `npm install`, pauses it, enforces the final verdict |
| **Orchestrator** | Routes dynamically, decides when to escalate to detonation, compiles the report |
| **Intel Agent** | OSV/CVE lookup, npm registry metadata, typosquat distance |
| **Sandbox / Detonation Agent** | Spins an isolated container, seeds honeytokens, runs the install behind network + filesystem monitoring |
| **Reasoning Agent** | Turns raw telemetry into a verdict with evidence (Claude) |
| **Fix Agent** | Proposes a safe alternative + remediation (Claude) |

### How we detect malice (at the OS boundary)

- **Honeytokens:** fake `~/.aws/credentials`, `.env`, `~/.ssh/id_rsa`, and env vars — each carrying a unique **canary string**.
- **Egress monitoring:** all container traffic routes through a default-deny logging proxy. If a canary string leaves the box → caught red-handed.
- **Syscall / file monitoring:** `strace` / `inotify` flag any package that reads sensitive paths during install.
- A benign install makes **zero** outbound calls and touches **none** of these — so any such behavior is the signal.

> We detect at the OS boundary, not by monkey-patching the JS runtime — because `postinstall` hooks run as separate child processes (bash/python/binary) that in-process JS hooks never see.

## Sponsor tools

- **W&B Weave** — every agent op is wrapped in `@weave.op()` for a full nested trace of the orchestration (routing → intel → detonation → verdict). We also ship a **`weave.Evaluation` harness** scoring the system on a labeled dataset of malicious vs. benign packages (precision / recall / F1).
- **Claude API** — powers the Reasoning Agent and Fix Agent.
- **OSV.dev / npm registry** — threat intelligence for the Intel Agent.

## Demo

The demo uses a **harmless "evil" test package** (`evil-demo-pkg`) whose `postinstall` reads the seeded honeytokens and tries to exfiltrate them — against fake credentials, with egress blocked. It trips every detector exactly like real malware, making the demo deterministic and safe to run.

> ⚠️ No real-world malware is ever installed. The evil test package only ever sees fake credentials and its network egress is blocked.

## Getting started

> _TODO: fill in once the build lands._

```bash
# install deps
# start the orchestrator + Weave
# run the demo: npm install evil-demo-pkg  (gets caught)
#               npm install lodash         (clean pass)
```

## Tech stack

Node/TypeScript · Docker · Claude API · OSV.dev + npm registry · W&B Weave · (optional) Ink / Next.js UI

## Team

> _TODO: names, emails, X / LinkedIn handles._

## License

Code is the team's own per event eligibility rules.
