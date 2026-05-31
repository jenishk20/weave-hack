# 🛡️ Package Quarantine

> A multi-agent **safety harness that detonates dependencies in an isolated sandbox before your AI coding agent can install them into your real workspace.**

Built at **Multi-Agent Orchestration Build Day** — May 31, 2026, The Engine, Cambridge MA (AGI House × W&B × TNT × SundAI Club × E14).

---

## The problem

Modern supply-chain attacks fire their payload **at install time**, not in source code you read. In the **March 2026 LiteLLM hijack** and the **`ctx` PyPI hijack**, a malicious release dumped environment variables, scraped `~/.aws` and `~/.ssh`, and exfiltrated them to an attacker server **the moment it was installed**. Static CVE scanners miss this because the malicious version is a zero-day — nothing looks wrong until the code *runs*.

AI coding agents make it worse: they run `pip install` / `npm install` blindly and fall for **typosquatted / hallucinated** package names that attackers pre-register as traps.

## What Package Quarantine does

Package Quarantine sits in front of every install. It intercepts `pip install` / `npm install`, **detonates the package in an isolated honeypot sandbox seeded with fake credentials**, and lets a team of agents watch what the package actually *does*. If it reads the honeytokens or tries to phone home, Package Quarantine blocks the install before it ever runs in your real workspace — and hands your AI agent a safe remediation.

We are not the attacker. The **package** is the attacker. We're the victim and the security camera.

## How it works

```
pip install <pkg>   (or npm install <pkg>)
   └─ Interceptor (pip/npm shim) pauses the install — real workspace untouched
       └─ Orchestrator (dynamic routing, not a linear pipeline)
           ├─ Intel Agent     → OSV/CVE, registry metadata, typosquat distance
           │                    (clearly malicious / typosquat? block here, skip detonation)
           └─ Sandbox Agent   → detonate in Docker w/ honeytokens,
                                 watched at the OS boundary (strace: file opens + connects)
                 └─ the package itself reads creds / tries to call out
                 └─ Reasoning Agent → verdict + human-readable evidence
       └─ Verdict: safe → allow + forward to real pip/npm
                   malicious → BLOCK + Fix Agent suggests a safe alternative
   └─ every step traced in W&B Weave
```

The routing is **dynamic**: a well-established package with no signals is fast-passed without detonation; a typosquat is blocked on intel alone; anything new/suspicious is escalated to the sandbox. Each routing decision is visible in the Weave trace.

### The agents

| Agent | Role |
|---|---|
| **Interceptor** | A `pip`/`npm` shim that catches the install, pauses it, and enforces the final verdict (only forwards to the real package manager on `allow`) |
| **Orchestrator** | Routes dynamically, decides when to escalate to detonation, compiles the report |
| **Intel Agent** | OSV/CVE lookup, registry metadata (age, version velocity, maintainer change), typosquat edit-distance |
| **Sandbox / Detonation Agent** | Spins an isolated Docker container, seeds honeytokens, runs the install under `strace` while watching file + network syscalls |
| **Reasoning Agent** | Turns raw telemetry into a verdict with evidence (W&B Inference) |
| **Fix Agent** | Proposes a safe alternative + remediation (W&B Inference) |

### How we detect malice (at the OS boundary)

- **Honeytokens:** fake `~/.aws/credentials`, `.env`, `~/.ssh/id_rsa`, and env vars — each carrying a unique **canary string** per run.
- **Syscall / file monitoring:** `strace -f -e trace=openat,connect` flags any package that reads sensitive paths or opens an outbound connection during install.
- A benign install makes **zero** outbound calls and touches **none** of these — so any such behavior is itself the signal.

> We detect at the OS boundary, not by monkey-patching the language runtime — because `postinstall` / `setup.py` hooks run as separate child processes (bash/python/binary) that in-process hooks never see.

## Sponsor tools

- **W&B Weave** — every agent op is wrapped in `@weave.op()` for a full nested trace of the orchestration (routing → intel → escalation → detonation → reasoning → verdict → fix). We also ship a **`weave.Evaluation` harness** scoring the system on a labeled dataset of malicious vs. benign packages (precision / recall / F1).
- **W&B Inference** — powers the Reasoning Agent and Fix Agent; because `weave.init()` is active, every inference call is auto-traced and nests under the calling agent.
- **OSV.dev / npm registry** — threat intelligence for the Intel Agent.

## Demo

The demo uses a **harmless "evil" test package** (`evil-demo-pkg`) whose install hook reads the seeded honeytokens and tries to exfiltrate them — against fake credentials. It trips every detector exactly like real malware, making the demo deterministic and safe to run. (`evil-ctx-pkg` is a harmless recreation of the real May 2022 `ctx` PyPI hijack.)

> ⚠️ No real-world malware is ever installed. The evil test package only ever sees fake credentials inside the disposable sandbox.

## Getting started

Requires Python 3.10+ and Docker.

```bash
# 1) install the CLI (into a venv)
pip install -e .

# 2) build the detonation sandbox image
docker build -t quarantine-sandbox ./sandbox

# 3) set your W&B key so traces land in Weave
export WANDB_API_KEY="...from https://wandb.ai/authorize..."

# 4) enable the pip/npm shims, then open a new terminal
quarantine enable
```

Now any install routes through Package Quarantine first:

```bash
pip install requests        # clean → allowed + installed
pip install evil-demo-pkg   # malicious → detonated, caught, BLOCKED
```

You can also check a package without installing:

```bash
quarantine check requests
quarantine check evil-demo-pkg
```

Run the Weave evaluation harness (precision / recall / F1 over the labeled set):

```bash
python -m eval.run_eval
```

## Tech stack

Python · Docker · `strace` (OS-boundary monitoring) · W&B Weave · W&B Inference · OSV.dev + npm registry · FastAPI · pip/npm shim interception

## Team

- **Yash Phalle**
- **Jenish Kothari**
- **Shubham Bhadra**
- **Sagar Satra**

## License

Code is the team's own per event eligibility rules.
</content>