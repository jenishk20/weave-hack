"""
quarantine.py — CLI entry point.

Usage:
    python quarantine.py evil-demo-pkg
    python quarantine.py install lodash
    python quarantine.py install axios@1.0.0

Scans the package through the full agent pipeline, then either blocks
or runs the real npm install.
"""
from __future__ import annotations

import os
import subprocess
import sys

from dotenv import load_dotenv

import weave_shim as W
from orchestrator import orchestrate
from contracts import Verdict, Remediation

load_dotenv()


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print("Usage: python quarantine.py <package>")
        print("   or: python quarantine.py install <package>")
        sys.exit(1)

    # Accept both "python quarantine.py lodash" and "python quarantine.py install lodash"
    if args[0] == "install" and len(args) > 1:
        args = args[1:]

    raw = args[0]
    package = raw.split("@")[0]
    version = raw.split("@")[1] if "@" in raw else "latest"

    W.init(os.getenv("WANDB_PROJECT", "quarantine"))

    print(f"\n[quarantine] Scanning {raw} ...")

    result = orchestrate(package, version)
    verdict: Verdict = result["verdict"]
    remediation: Remediation | None = result.get("remediation")

    _print_verdict(verdict, remediation)

    if verdict.decision == "allow":
        print(f"[quarantine] Running: npm install {raw}\n")
        # Windows: npm is npm.cmd, not a bare executable
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        subprocess.run([npm_cmd, "install", raw], check=False)
    else:
        sys.exit(1)


def _print_verdict(verdict: Verdict, remediation: Remediation | None) -> None:
    if verdict.decision == "block":
        print(f"\n{'='*60}")
        print(f"  BLOCKED — {verdict.package}")
        print(f"  Risk    : {verdict.risk.upper()}")
        print(f"  Score   : {verdict.score:.0%}")
        print(f"  Summary : {verdict.summary}")
        print(f"  Evidence:")
        for e in verdict.evidence:
            print(f"    • {e}")
        if remediation and remediation.safe_alternative:
            print(f"\n  Safe alternative: npm install {remediation.safe_alternative}")
            print(f"  {remediation.message_to_agent}")
        print(f"{'='*60}\n")
    else:
        print(f"[quarantine] ✓ CLEAN — {verdict.package} ({verdict.risk} risk)")


if __name__ == "__main__":
    main()
