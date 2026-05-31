"""
contracts.py — THE SHARED TRUTH.

These dataclasses are the agreed shapes passed between agents. Do NOT change a
field without telling the team — everyone builds against these.

Owner: Person B (spine), but the whole team agrees on changes.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# ----- Intel Agent output (Person C) ---------------------------------------
@dataclass
class IntelResult:
    package: str
    version: str
    clearly_malicious: bool = False          # if True, orchestrator can stop early
    typosquat_of: Optional[str] = None        # e.g. "node-fetch" if pkg looks squatted
    known_cves: list[str] = field(default_factory=list)
    package_age_days: Optional[int] = None
    recently_transferred: bool = False        # ownership/maintainer just changed
    recommend_escalate: bool = True           # should we detonate in the sandbox?
    notes: str = ""


# ----- Sandbox Agent output (Person A — YOU) -------------------------------
@dataclass
class NetworkAttempt:
    dest_host: Optional[str]
    dest_ip: Optional[str]
    port: Optional[int]
    payload_contains_canary: bool = False
    raw_snippet: str = ""


@dataclass
class FileAccess:
    path: str
    operation: str          # "open" / "read" / etc.
    is_sensitive: bool = False   # touched ~/.aws, ~/.ssh, .env, etc.


@dataclass
class TelemetryBlob:
    package: str
    version: str
    network_attempts: list[NetworkAttempt] = field(default_factory=list)
    file_accesses: list[FileAccess] = field(default_factory=list)
    install_scripts: dict[str, str] = field(default_factory=dict)  # {"postinstall": "..."}
    canary_leaked: bool = False     # the headline signal
    exit_code: int = 0
    duration_ms: int = 0


# ----- Reasoning Agent output (Person C) -----------------------------------
@dataclass
class Verdict:
    package: str
    version: str
    decision: str            # "allow" | "block"
    risk: str                # "low" | "medium" | "critical"
    score: float             # 0.0 - 1.0
    evidence: list[str] = field(default_factory=list)
    summary: str = ""


# ----- Fix Agent output (Person C) -----------------------------------------
@dataclass
class Remediation:
    blocked_package: str
    safe_alternative: Optional[str] = None
    reason: str = ""
    import_change: str = ""      # human-readable suggested change
    message_to_agent: str = ""   # what we hand back to the AI coder / dev