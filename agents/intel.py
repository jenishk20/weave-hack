"""
intel.py - INTEL AGENT.

Job: gather fast public threat intelligence BEFORE we spend time detonating.
This is a hybrid agent:
  - deterministic collectors fetch npm, OSV, GitHub, and typo signals
  - optional W&B Inference summarization turns collected evidence into better notes

The output stays the shared IntelResult contract so orchestrator.py can route:
  clearly_malicious -> block immediately
  recommend_escalate -> run sandbox_agent
  low signal -> allow/skip detonation
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
from typing import Any
from urllib.parse import quote, urlparse

import requests

import weave_shim as W
from contracts import IntelResult


REQUEST_TIMEOUT_SECONDS = 8
NEW_PACKAGE_DAYS = 30
NEW_VERSION_DAYS = 7
RECENT_RESEARCH_DAYS = 30
POPULAR_NPM_PACKAGES = [
    "lodash",
    "express",
    "react",
    "axios",
    "chalk",
    "dotenv",
    "uuid",
    "zod",
    "commander",
    "dayjs",
    "typescript",
    "next",
    "vite",
    "webpack",
    "eslint",
    "prettier",
    "node-fetch",
    "minimist",
    "debug",
    "mongoose",
]
SUSPICIOUS_SEARCH_TERMS = [
    "malware",
    "compromised",
    "hijacked",
    "supply chain",
    "credential theft",
    "exfiltration",
    "postinstall",
    "typosquat",
]


@dataclass
class IntelEvidence:
    npm: dict[str, Any] = field(default_factory=dict)
    osv: dict[str, Any] = field(default_factory=dict)
    github: dict[str, Any] = field(default_factory=dict)
    deep_research: dict[str, Any] = field(default_factory=dict)
    typosquat_of: str | None = None
    collector_errors: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)


@W.op
def intel_agent(package: str, version: str = "latest") -> IntelResult:
    evidence = collect_intel(package, version)
    result = score_intel(package, version, evidence)
    result.notes = summarize_intel(package, version, evidence, result)
    return result


@W.op
def collect_intel(package: str, version: str = "latest") -> IntelEvidence:
    evidence = IntelEvidence()

    # Keep the local demo deterministic even before the package is published.
    if package == "evil-demo-pkg":
        evidence.signals.extend(
            [
                "Local demo package that mimics postinstall credential theft.",
                "Package is intentionally escalated so sandbox can prove behavior.",
            ]
        )
        evidence.npm = {
            "exists": False,
            "package_age_days": 2,
            "latest_version_age_days": 2,
            "maintainers_count": 1,
        }
        return evidence

    try:
        evidence.npm = lookup_npm_registry(package, version)
    except Exception as exc:
        evidence.collector_errors.append(f"npm: {exc}")

    resolved_version = evidence.npm.get("resolved_version") or version
    try:
        evidence.osv = lookup_osv_advisories(package, resolved_version)
    except Exception as exc:
        evidence.collector_errors.append(f"osv: {exc}")

    try:
        evidence.github = search_github_intel(package)
    except Exception as exc:
        evidence.collector_errors.append(f"github: {exc}")

    try:
        evidence.deep_research = deep_research_package(package, evidence.npm)
    except Exception as exc:
        evidence.collector_errors.append(f"deep_research: {exc}")

    evidence.typosquat_of = detect_typosquat(package)
    return evidence


@W.op
def lookup_npm_registry(package: str, version: str = "latest") -> dict[str, Any]:
    encoded = quote(package, safe="@/")
    url = f"https://registry.npmjs.org/{encoded}"
    data = _request_json("GET", url)
    time_map = data.get("time", {})
    versions = data.get("versions", {})
    dist_tags = data.get("dist-tags", {})
    resolved_version = dist_tags.get("latest") if version == "latest" else version
    version_meta = versions.get(resolved_version, {}) if resolved_version else {}

    created = _parse_npm_time(time_map.get("created"))
    latest_published = _parse_npm_time(time_map.get(resolved_version)) if resolved_version else None
    maintainers = data.get("maintainers") or []
    repository = data.get("repository") or version_meta.get("repository") or {}
    scripts = version_meta.get("scripts") or data.get("scripts") or {}
    version_times = _version_publish_times(time_map)
    previous_version = _previous_version(version_times, resolved_version)
    previous_meta = versions.get(previous_version, {}) if previous_version else {}
    previous_scripts = previous_meta.get("scripts") or {}
    latest_install_scripts = {k: scripts[k] for k in scripts if k in {"preinstall", "install", "postinstall"}}
    previous_install_scripts = {
        k: previous_scripts[k] for k in previous_scripts if k in {"preinstall", "install", "postinstall"}
    }

    return {
        "exists": True,
        "name": data.get("name", package),
        "requested_version": version,
        "resolved_version": resolved_version,
        "package_age_days": _days_since(created),
        "latest_version_age_days": _days_since(latest_published),
        "versions_count": len(versions),
        "maintainers_count": len(maintainers),
        "maintainers": [_maintainer_name(m) for m in maintainers[:5]],
        "repository": repository.get("url") if isinstance(repository, dict) else repository,
        "homepage": data.get("homepage"),
        "license": data.get("license") or version_meta.get("license"),
        "scripts": latest_install_scripts,
        "previous_version": previous_version,
        "previous_scripts": previous_install_scripts,
        "install_scripts_added": sorted(set(latest_install_scripts) - set(previous_install_scripts)),
        "recent_versions": _recent_versions(version_times, RECENT_RESEARCH_DAYS),
        "deprecated": bool(data.get("deprecated") or version_meta.get("deprecated")),
    }


@W.op
def lookup_osv_advisories(package: str, version: str = "latest") -> dict[str, Any]:
    payload: dict[str, Any] = {"package": {"name": package, "ecosystem": "npm"}}
    if version != "latest":
        payload["version"] = version
    data = _request_json("POST", "https://api.osv.dev/v1/query", json=payload)
    vulns = data.get("vulns", [])
    advisories = []
    for vuln in vulns:
        ids = vuln.get("aliases") or []
        if vuln.get("id"):
            ids.insert(0, vuln["id"])
        advisories.append(
            {
                "id": vuln.get("id"),
                "aliases": ids,
                "summary": vuln.get("summary", ""),
                "severity": vuln.get("database_specific", {}).get("severity"),
            }
        )
    return {"advisories": advisories, "count": len(advisories)}


@W.op
def search_github_intel(package: str) -> dict[str, Any]:
    code_query = f'"{package}" "postinstall"'
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    issue_hits: list[dict[str, str]] = []
    suspicious_issue_count = 0
    for term in SUSPICIOUS_SEARCH_TERMS:
        query = f'"{package}" "{term}" in:title,body'
        issues = _safe_github_search("issues", query, headers)
        suspicious_issue_count += int(issues.get("total_count", 0))
        for item in issues.get("items", [])[:1]:
            issue_hits.append(
                {
                    "title": item.get("title", ""),
                    "url": item.get("html_url", ""),
                    "state": item.get("state", ""),
                }
            )

    code = _safe_github_search("code", code_query, headers)
    return {
        "suspicious_issue_count": suspicious_issue_count,
        "postinstall_code_mentions": code.get("total_count", 0),
        "issue_hits": issue_hits[:3],
    }


@W.op
def deep_research_package(package: str, npm_meta: dict[str, Any]) -> dict[str, Any]:
    """Research recent public changes around the package and its source repo."""
    research: dict[str, Any] = {
        "recent_window_days": RECENT_RESEARCH_DAYS,
        "npm_recent_versions": npm_meta.get("recent_versions", []),
        "install_scripts_added": npm_meta.get("install_scripts_added", []),
        "repository": npm_meta.get("repository"),
    }
    repo = _parse_github_repo(npm_meta.get("repository"))
    if not repo:
        research["repo_found"] = False
        return research

    owner, name = repo
    headers = _github_headers()
    since = (datetime.now(timezone.utc) - timedelta(days=RECENT_RESEARCH_DAYS)).isoformat()
    repo_base = f"https://api.github.com/repos/{owner}/{name}"

    repo_info = _safe_request_json("GET", repo_base, headers=headers)
    commits = _safe_request_json("GET", f"{repo_base}/commits", headers=headers, params={"since": since, "per_page": 10})
    releases = _safe_request_json("GET", f"{repo_base}/releases", headers=headers, params={"per_page": 5})
    issues = _safe_request_json(
        "GET",
        f"{repo_base}/issues",
        headers=headers,
        params={"state": "all", "since": since, "per_page": 10},
    )

    research.update(
        {
            "repo_found": bool(repo_info),
            "repo": f"{owner}/{name}",
            "repo_stars": repo_info.get("stargazers_count"),
            "repo_archived": repo_info.get("archived"),
            "repo_pushed_at": repo_info.get("pushed_at"),
            "recent_commits": [_github_commit_summary(item) for item in commits[:5]] if isinstance(commits, list) else [],
            "recent_releases": [_github_release_summary(item) for item in releases[:5]] if isinstance(releases, list) else [],
            "recent_issues": [_github_issue_summary(item) for item in issues[:5]] if isinstance(issues, list) else [],
        }
    )
    research["suspicious_recent_text_hits"] = _count_suspicious_text_hits(research)
    return research


def score_intel(package: str, version: str, evidence: IntelEvidence) -> IntelResult:
    notes: list[str] = []
    known_cves = _known_cve_ids(evidence.osv)
    package_age_days = evidence.npm.get("package_age_days")
    latest_version_age_days = evidence.npm.get("latest_version_age_days")
    scripts = evidence.npm.get("scripts") or {}
    install_scripts_added = evidence.deep_research.get("install_scripts_added") or []
    recent_versions = evidence.deep_research.get("npm_recent_versions") or []

    clearly_malicious = False
    recommend_escalate = False
    recently_transferred = False

    if package == "evil-demo-pkg":
        recommend_escalate = True
        recently_transferred = True
        notes.append("Local demo package should be escalated to sandbox.")

    if known_cves:
        recommend_escalate = True
        notes.append(f"OSV returned {len(known_cves)} advisory id(s).")
        if _has_malware_language(evidence.osv):
            clearly_malicious = True
            notes.append("OSV advisory text contains malware/compromise language.")

    if package_age_days is not None and package_age_days <= NEW_PACKAGE_DAYS:
        recommend_escalate = True
        recently_transferred = True
        notes.append(f"Package is only {package_age_days} day(s) old.")

    if latest_version_age_days is not None and latest_version_age_days <= NEW_VERSION_DAYS:
        recommend_escalate = True
        notes.append(f"Requested/latest version was published {latest_version_age_days} day(s) ago.")

    if evidence.typosquat_of:
        recommend_escalate = True
        notes.append(f"Name is close to popular package '{evidence.typosquat_of}'.")
        if _normalized_distance(package, evidence.typosquat_of) <= 1:
            clearly_malicious = True
            notes.append("Typosquat distance is extremely small.")

    if scripts:
        recommend_escalate = True
        notes.append(f"Install lifecycle scripts present: {', '.join(sorted(scripts))}.")

    if install_scripts_added:
        recommend_escalate = True
        notes.append(f"Latest version added install script(s): {', '.join(install_scripts_added)}.")

    if len(recent_versions) >= 5:
        recommend_escalate = True
        notes.append(f"High version velocity: {len(recent_versions)} npm publishes in {RECENT_RESEARCH_DAYS} days.")

    if evidence.github.get("suspicious_issue_count", 0) > 0:
        notes.append(
            f"GitHub search found {evidence.github['suspicious_issue_count']} suspicious-context mention(s)."
        )
        if (
            evidence.typosquat_of
            or known_cves
            or (package_age_days is not None and package_age_days <= 365)
        ):
            recommend_escalate = True
            notes.append("GitHub context reinforces other risk signals.")

    if evidence.deep_research.get("repo_archived"):
        recommend_escalate = True
        notes.append("Source repository is archived.")

    if evidence.deep_research.get("suspicious_recent_text_hits", 0) > 0:
        recommend_escalate = True
        notes.append(
            f"Recent repo activity contains {evidence.deep_research['suspicious_recent_text_hits']} suspicious term hit(s)."
        )

    if not evidence.npm.get("exists", True):
        recommend_escalate = True
        notes.append("Package not found in public npm registry or only exists locally.")

    critical_collector_failed = any(
        error.startswith("npm:") or error.startswith("osv:") for error in evidence.collector_errors
    )
    if critical_collector_failed:
        recommend_escalate = True
        notes.append("Critical intel collectors failed; escalate instead of silently trusting package.")
    elif evidence.collector_errors:
        notes.append("Non-critical intel collector failed; continuing with available signals.")

    if not notes:
        notes.append("Established package, no OSV advisories, no typo or recent-risk signals.")

    return IntelResult(
        package=package,
        version=version,
        clearly_malicious=clearly_malicious,
        typosquat_of=evidence.typosquat_of,
        known_cves=known_cves,
        package_age_days=package_age_days,
        recently_transferred=recently_transferred,
        recommend_escalate=recommend_escalate,
        notes=" ".join(notes),
    )


@W.op
def summarize_intel(
    package: str,
    version: str,
    evidence: IntelEvidence,
    scored: IntelResult,
) -> str:
    base_summary = scored.notes
    api_key = os.getenv("MODEL_API_KEY") or os.getenv("WANDB_API_KEY")
    if not api_key:
        return base_summary

    try:
        from openai import OpenAI

        client = OpenAI(
            base_url=os.getenv("MODEL_BASE_URL", "https://api.inference.wandb.ai/v1"),
            api_key=api_key,
            project=os.getenv("MODEL_PROJECT") or os.getenv("WANDB_PROJECT"),
        )
        response = client.chat.completions.create(
            model=os.getenv("MODEL_NAME", "openai/gpt-oss-120b"),
            max_tokens=220,
            temperature=0,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a supply-chain threat intelligence analyst. "
                        "Summarize only the provided evidence. Do not invent facts. "
                        "Return one concise paragraph ending with the routing recommendation."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "package": package,
                            "version": version,
                            "scored_result": scored.__dict__,
                            "evidence": {
                                "npm": evidence.npm,
                                "osv": evidence.osv,
                                "github": evidence.github,
                                "deep_research": evidence.deep_research,
                                "typosquat_of": evidence.typosquat_of,
                                "collector_errors": evidence.collector_errors,
                                "signals": evidence.signals,
                            },
                        },
                        default=str,
                    ),
                }
            ],
        )
        text = response.choices[0].message.content.strip()
        return text or base_summary
    except Exception as exc:
        return f"{base_summary} LLM summary unavailable: {exc}"


def detect_typosquat(package: str) -> str | None:
    normalized = _normalize_package_name(package)
    best_name = None
    best_distance = 99
    for popular in POPULAR_NPM_PACKAGES:
        candidate = _normalize_package_name(popular)
        if normalized == candidate:
            continue
        distance = _levenshtein(normalized, candidate)
        if distance < best_distance:
            best_distance = distance
            best_name = popular
    if best_name and (best_distance <= 1 or (len(normalized) >= 6 and best_distance <= 2)):
        return best_name
    return None


def _request_json(method: str, url: str, **kwargs: Any) -> dict[str, Any]:
    response = requests.request(method, url, timeout=REQUEST_TIMEOUT_SECONDS, **kwargs)
    response.raise_for_status()
    return response.json()


def _safe_request_json(method: str, url: str, **kwargs: Any) -> Any:
    try:
        return _request_json(method, url, **kwargs)
    except Exception:
        return {} if method == "GET" else {}


def _github_search(kind: str, query: str, headers: dict[str, str]) -> dict[str, Any]:
    url = f"https://api.github.com/search/{kind}"
    return _request_json("GET", url, headers=headers, params={"q": query, "per_page": 3})


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _safe_github_search(kind: str, query: str, headers: dict[str, str]) -> dict[str, Any]:
    try:
        return _github_search(kind, query, headers)
    except Exception:
        return {"total_count": 0, "items": []}


def _known_cve_ids(osv: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for advisory in osv.get("advisories", []):
        for alias in advisory.get("aliases", []):
            if alias and alias not in ids:
                ids.append(alias)
    return ids


def _has_malware_language(osv: dict[str, Any]) -> bool:
    text = json.dumps(osv).lower()
    return any(term in text for term in ["malware", "malicious", "compromised", "hijack", "exfiltrat"])


def _version_publish_times(time_map: dict[str, Any]) -> list[tuple[str, datetime]]:
    versions: list[tuple[str, datetime]] = []
    for version, published in time_map.items():
        if version in {"created", "modified"}:
            continue
        parsed = _parse_npm_time(published)
        if parsed:
            versions.append((version, parsed))
    return sorted(versions, key=lambda item: item[1])


def _previous_version(version_times: list[tuple[str, datetime]], resolved_version: str | None) -> str | None:
    if not resolved_version:
        return None
    names = [version for version, _ in version_times]
    if resolved_version not in names:
        return names[-2] if len(names) >= 2 else None
    index = names.index(resolved_version)
    return names[index - 1] if index > 0 else None


def _recent_versions(version_times: list[tuple[str, datetime]], days: int) -> list[dict[str, str]]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return [
        {"version": version, "published_at": published.isoformat()}
        for version, published in version_times
        if published >= cutoff
    ][-10:]


def _parse_github_repo(repository: Any) -> tuple[str, str] | None:
    if not repository:
        return None
    repo_url = str(repository)
    repo_url = repo_url.removeprefix("git+").removesuffix(".git")
    if repo_url.startswith("git@github.com:"):
        path = repo_url.split("git@github.com:", 1)[1]
    else:
        parsed = urlparse(repo_url)
        if "github.com" not in parsed.netloc:
            return None
        path = parsed.path.lstrip("/")
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _github_commit_summary(item: dict[str, Any]) -> dict[str, str]:
    commit = item.get("commit", {})
    return {
        "sha": item.get("sha", "")[:8],
        "message": (commit.get("message") or "").splitlines()[0][:180],
        "date": commit.get("committer", {}).get("date", ""),
        "url": item.get("html_url", ""),
    }


def _github_release_summary(item: dict[str, Any]) -> dict[str, str]:
    return {
        "name": item.get("name") or item.get("tag_name", ""),
        "published_at": item.get("published_at", ""),
        "url": item.get("html_url", ""),
        "body": (item.get("body") or "")[:300],
    }


def _github_issue_summary(item: dict[str, Any]) -> dict[str, str]:
    return {
        "title": item.get("title", ""),
        "state": item.get("state", ""),
        "created_at": item.get("created_at", ""),
        "url": item.get("html_url", ""),
        "body": (item.get("body") or "")[:300],
    }


def _count_suspicious_text_hits(research: dict[str, Any]) -> int:
    text = json.dumps(
        {
            "recent_commits": research.get("recent_commits", []),
            "recent_releases": research.get("recent_releases", []),
            "recent_issues": research.get("recent_issues", []),
        }
    ).lower()
    return sum(1 for term in SUSPICIOUS_SEARCH_TERMS if term in text)


def _parse_npm_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _days_since(value: datetime | None) -> int | None:
    if value is None:
        return None
    return max(0, (datetime.now(timezone.utc) - value).days)


def _maintainer_name(maintainer: Any) -> str:
    if isinstance(maintainer, dict):
        return maintainer.get("name") or maintainer.get("email") or str(maintainer)
    return str(maintainer)


def _normalize_package_name(package: str) -> str:
    return package.lower().replace("@", "").replace("/", "").replace("-", "").replace("_", "")


def _normalized_distance(left: str, right: str) -> int:
    return _levenshtein(_normalize_package_name(left), _normalize_package_name(right))


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    prev = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        cur = [i]
        for j, right_char in enumerate(right, start=1):
            insert = cur[j - 1] + 1
            delete = prev[j] + 1
            replace = prev[j - 1] + (left_char != right_char)
            cur.append(min(insert, delete, replace))
        prev = cur
    return prev[-1]
