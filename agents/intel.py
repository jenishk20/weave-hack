"""
intel.py — INTEL AGENT (tool agent, no LLM needed).

Job: fast/cheap risk signals BEFORE we spend time detonating.
  - OSV.dev CVE lookup
  - npm registry metadata (package age, maintainer change)
  - typosquat distance vs. popular package names
"""
from __future__ import annotations

import difflib
from datetime import datetime, timezone

import requests
import weave_shim as W
from contracts import IntelResult

_POPULAR_PACKAGES = [
    "lodash", "express", "react", "chalk", "axios", "commander", "moment",
    "webpack", "typescript", "eslint", "prettier", "jest", "mocha", "nodemon",
    "dotenv", "mongoose", "passport", "socket.io", "node-fetch", "cross-env",
    "rimraf", "uuid", "debug", "underscore", "async", "request", "body-parser",
    "cors", "helmet", "jsonwebtoken", "bcrypt", "multer", "sharp",
    "postcss", "autoprefixer", "colors", "inquirer", "yargs", "minimist",
    "semver", "glob", "chokidar", "fs-extra", "mkdirp", "ncp", "tar",
]

_OSV_URL = "https://api.osv.dev/v1/query"
_NPM_URL = "https://registry.npmjs.org/{package}"
_TYPOSQUAT_THRESHOLD = 0.82


@W.op
def intel_agent(package: str, version: str = "latest") -> IntelResult:
    cves = _check_osv(package, version)
    npm_meta = _check_npm(package)
    typosquat_of = _check_typosquat(package)

    age_days = npm_meta.get("age_days")
    recently_transferred = npm_meta.get("recently_transferred", False)

    clearly_malicious = len(cves) > 0 and any(
        kw in c.lower() for c in cves for kw in ("supply-chain", "malicious", "backdoor")
    )

    not_on_npm = npm_meta == {}   # package not found on registry → unknown, escalate

    recommend_escalate = (
        not_on_npm
        or (age_days is not None and age_days < 30)
        or typosquat_of is not None
        or recently_transferred
        or len(cves) > 0
    )

    notes_parts = []
    if typosquat_of:
        notes_parts.append(f"Possible typosquat of '{typosquat_of}'.")
    if age_days is not None and age_days < 30:
        notes_parts.append(f"Package is only {age_days} days old.")
    if recently_transferred:
        notes_parts.append("Ownership/maintainer recently changed.")
    if cves:
        notes_parts.append(f"CVEs: {', '.join(cves[:3])}.")
    if not notes_parts:
        notes_parts.append("Well-established package, no signals.")

    return IntelResult(
        package=package,
        version=version,
        clearly_malicious=clearly_malicious,
        typosquat_of=typosquat_of,
        known_cves=cves,
        package_age_days=age_days,
        recently_transferred=recently_transferred,
        recommend_escalate=recommend_escalate,
        notes=" ".join(notes_parts),
    )


def _check_osv(package: str, version: str) -> list[str]:
    try:
        payload: dict = {"package": {"name": package, "ecosystem": "npm"}}
        if version and version != "latest":
            payload["version"] = version
        resp = requests.post(_OSV_URL, json=payload, timeout=10)
        if resp.status_code != 200:
            return []
        return [v.get("id", "UNKNOWN") for v in resp.json().get("vulns", [])]
    except Exception:
        return []


def _check_npm(package: str) -> dict:
    try:
        resp = requests.get(_NPM_URL.format(package=package), timeout=10)
        if resp.status_code != 200:
            return {}
        data = resp.json()

        created_str = data.get("time", {}).get("created")
        age_days = None
        if created_str:
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created).days
            except Exception:
                pass

        version_count = len(data.get("versions", {}))
        recently_transferred = age_days is not None and age_days < 7 and version_count > 3

        return {
            "age_days": age_days,
            "recently_transferred": recently_transferred,
            "maintainer_count": len(data.get("maintainers", [])),
            "version_count": version_count,
        }
    except Exception:
        return {}


def _check_typosquat(package: str) -> str | None:
    best_match, best_score = None, 0.0
    for popular in _POPULAR_PACKAGES:
        score = difflib.SequenceMatcher(None, package.lower(), popular.lower()).ratio()
        if score > best_score:
            best_score, best_match = score, popular
    if best_score >= _TYPOSQUAT_THRESHOLD and best_match and best_match.lower() != package.lower():
        return best_match
    return None
