from __future__ import annotations

import argparse
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


PROJECT_NAME = "quarantine"
DEFAULT_HOME = Path.home() / ".quarantine"
OPTIONS_WITH_VALUES = {
    "--cache",
    "--prefix",
    "--registry",
    "--tag",
    "--workspace",
    "-w",
}
PIP_OPTIONS_WITH_VALUES = {
    "--constraint",
    "-c",
    "--requirement",
    "-r",
    "--index-url",
    "-i",
    "--extra-index-url",
    "--find-links",
    "-f",
    "--target",
    "-t",
    "--platform",
    "--python-version",
    "--implementation",
    "--abi",
    "--prefix",
    "--root",
    "--src",
}


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "npm-shim":
        _load_env()
        return _cmd_npm_shim(argv[1:])
    if argv and argv[0] == "pip-shim":
        _load_env()
        return _cmd_pip_shim(argv[1:])

    parser = argparse.ArgumentParser(prog="quarantine")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Run Quarantine on one package.")
    check.add_argument("package")
    check.add_argument("--version", default="latest")
    check.add_argument("--json", action="store_true")

    sub.add_parser("doctor", help="Check local Docker/npm/pip/PATH setup.")

    enable = sub.add_parser("enable", help="Install npm and pip shims into ~/.quarantine/bin.")
    enable.add_argument("--home", default=os.getenv("QUARANTINE_HOME", str(DEFAULT_HOME)))
    enable.add_argument("--print-shell-init", action="store_true")
    enable.add_argument("--profile", default=None, help="Shell profile to update, defaults to the active Linux/macOS profile.")
    enable.add_argument("--no-profile", action="store_true", help="Do not update a shell profile.")
    enable.add_argument("--no-shell-prompt", action="store_true", help="Do not offer to start a protected shell now.")

    disable = sub.add_parser("disable", help="Remove installed npm and pip shims.")
    disable.add_argument("--home", default=os.getenv("QUARANTINE_HOME", str(DEFAULT_HOME)))

    sub.add_parser("shell-init", help="Print shell code that enables Quarantine for this session.")

    shim = sub.add_parser("npm-shim", help=argparse.SUPPRESS)
    shim.add_argument("npm_args", nargs=argparse.REMAINDER)
    pip_shim = sub.add_parser("pip-shim", help=argparse.SUPPRESS)
    pip_shim.add_argument("pip_args", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    _load_env()

    if args.command == "check":
        return _cmd_check(args.package, args.version, args.json)
    if args.command == "doctor":
        return _cmd_doctor()
    if args.command == "enable":
        profile = Path(args.profile).expanduser() if args.profile else None
        return _cmd_enable(
            Path(args.home),
            args.print_shell_init,
            profile,
            args.no_profile,
            args.no_shell_prompt,
        )
    if args.command == "disable":
        return _cmd_disable(Path(args.home))
    if args.command == "shell-init":
        print(_shell_init(_quarantine_home()))
        return 0
    if args.command == "npm-shim":
        return _cmd_npm_shim(args.npm_args)
    if args.command == "pip-shim":
        return _cmd_pip_shim(args.pip_args)
    return 2


def _cmd_check(package: str, version: str, as_json: bool) -> int:
    result = _run_quarantine(package, version)
    verdict = result["verdict"]
    if as_json:
        print(json.dumps(_result_to_dict(result), default=str))
    else:
        _print_result(package, result)
    return 0 if verdict.decision == "allow" else 1


def _cmd_doctor() -> int:
    home = _quarantine_home()
    shim_dir = _shim_dir(home)
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    detected_profile = _detect_shell_profile()
    checks = {
        "platform": platform.system(),
        "shell": os.getenv("SHELL"),
        "python": sys.executable,
        "quarantine_home": str(home),
        "detected_profile": str(detected_profile) if detected_profile else None,
        "shim_dir_exists": shim_dir.exists(),
        "shim_dir_first_in_path": bool(path_dirs and Path(path_dirs[0]).resolve() == shim_dir),
        "npm_shim_exists": (_npm_shim_path(home)).exists(),
        "pip_shim_exists": (_pip_shim_path(home)).exists(),
        "real_npm": _real_npm(),
        "real_pip": _real_pip(),
        "docker": shutil.which("docker"),
    }
    for key, value in checks.items():
        print(f"{key}: {value}")
    if not checks["docker"]:
        print("warning: docker was not found on PATH; sandbox detonation will fail closed.")
    if not checks["real_npm"]:
        print("warning: real npm was not found; allowed installs cannot be forwarded.")
    if not checks["real_pip"]:
        print("warning: real pip was not found; allowed installs cannot be forwarded.")
    return 0


def _cmd_enable(
    home: Path,
    print_shell_init: bool,
    profile: Path | None,
    no_profile: bool,
    no_shell_prompt: bool,
) -> int:
    bin_dir = _shim_dir(home)
    bin_dir.mkdir(parents=True, exist_ok=True)
    for tool, shim_path in {
        "npm": _npm_shim_path(home),
        "pip": _pip_shim_path(home),
    }.items():
        shim_path.write_text(_shim_script(tool), encoding="utf-8")
        shim_path.chmod(0o755)
    print("🟢 Quarantine guard enabled")
    print(f"npm shim: {_npm_shim_path(home)}")
    print(f"pip shim: {_pip_shim_path(home)}")
    if no_profile:
        print(_shell_init(home))
    else:
        profile_path = profile or _detect_shell_profile()
        if profile_path:
            _persist_shell_init(profile_path, home)
            print(f"shell profile: {profile_path}")
            print('current terminal: eval "$(quarantine shell-init)"')
            print("new terminals will use the guard automatically")
        else:
            print(_shell_init(home))
    if print_shell_init:
        print(_shell_init(home))
    if not no_shell_prompt:
        _offer_protected_shell(home)
    return 0


def _cmd_disable(home: Path) -> int:
    for tool, shim_path in {
        "npm": _npm_shim_path(home),
        "pip": _pip_shim_path(home),
    }.items():
        if shim_path.exists():
            shim_path.unlink()
            print(f"Removed {tool} shim: {shim_path}")
        else:
            print(f"No {tool} shim found at: {shim_path}")
    return 0


def _cmd_npm_shim(npm_args: list[str]) -> int:
    packages = _package_args(["npm", *npm_args])
    for package in packages:
        result = _run_quarantine(package)
        _print_result(package, result)
        if result["verdict"].decision != "allow":
            print(f"QUARANTINE_RED package={package} decision=block")
            return 1

    if packages:
        print("QUARANTINE_GREEN all requested packages allowed")
    if os.getenv("QUARANTINE_DRY_RUN") == "1" and packages:
        print("Quarantine dry run: real npm was not invoked.")
        return 0

    real_npm = _real_npm()
    if not real_npm:
        print("quarantine: could not find real npm on PATH", file=sys.stderr)
        return 127
    return subprocess.call([real_npm, *npm_args])


def _cmd_pip_shim(pip_args: list[str]) -> int:
    packages = _pip_package_args(["pip", *pip_args])
    for package in packages:
        result = _run_quarantine(package)
        _print_result(package, result)
        if result["verdict"].decision != "allow":
            print(f"QUARANTINE_RED package={package} decision=block")
            return 1

    if packages:
        print("QUARANTINE_GREEN all requested Python packages allowed")
    if os.getenv("QUARANTINE_DRY_RUN") == "1" and packages:
        print("Quarantine dry run: real pip was not invoked.")
        return 0

    real_pip = _real_pip()
    if not real_pip:
        print("quarantine: could not find real pip on PATH", file=sys.stderr)
        return 127
    return subprocess.call([real_pip, *pip_args])


def _run_quarantine(package: str, version: str = "latest") -> dict[str, Any]:
    import weave_shim as W
    from orchestrator import quarantine_install_trace

    W.init(os.getenv("WEAVE_PROJECT", PROJECT_NAME))
    return quarantine_install_trace(package, version)


def _print_result(package: str, result: dict[str, Any]) -> None:
    verdict = result["verdict"]
    prefix = "QUARANTINE_GREEN" if verdict.decision == "allow" else "QUARANTINE_RED"
    print(f"{prefix} package={package} decision={verdict.decision} risk={verdict.risk} score={verdict.score}")
    print(f"summary={verdict.summary}")
    for evidence in verdict.evidence:
        print(f"evidence=- {evidence}")
    remediation = result.get("remediation")
    if remediation:
        print(f"fix={remediation.message_to_agent}")


def _result_to_dict(result: dict[str, Any]) -> dict[str, Any]:
    verdict = result["verdict"]
    remediation = result.get("remediation")
    return {
        "verdict": verdict.__dict__,
        "remediation": remediation.__dict__ if remediation else None,
    }


def _package_args(argv: list[str]) -> list[str]:
    if len(argv) < 2 or argv[1] not in {"install", "i", "add"}:
        return []

    packages: list[str] = []
    skip_next = False
    for arg in argv[2:]:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            continue
        if arg in OPTIONS_WITH_VALUES:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        packages.append(_package_name_from_spec(arg))
    return [package for package in packages if package]


def _pip_package_args(argv: list[str]) -> list[str]:
    if len(argv) < 2 or argv[1] != "install":
        return []

    packages: list[str] = []
    skip_next = False
    for arg in argv[2:]:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            continue
        if arg in PIP_OPTIONS_WITH_VALUES:
            skip_next = True
            continue
        if arg in {"--editable", "-e"}:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        packages.append(_python_package_name_from_spec(arg))
    return [package for package in packages if package]


def _package_name_from_spec(spec: str) -> str:
    if spec.startswith(("file:", "git+", "http:", "https:")):
        return spec
    if spec.startswith("@"):
        scope_and_name = spec.split("/", 1)
        if len(scope_and_name) != 2:
            return spec
        scope, rest = scope_and_name
        return f"{scope}/{rest.split('@', 1)[0]}"
    return spec.split("@", 1)[0]


def _python_package_name_from_spec(spec: str) -> str:
    if spec.startswith(("git+", "http:", "https:", "file:")):
        return ""
    name = spec
    for marker in ["==", ">=", "<=", "~=", "!=", ">", "<", ";", "["]:
        if marker in name:
            name = name.split(marker, 1)[0]
    return name.strip()


def _real_npm() -> str | None:
    return _real_tool("npm")


def _real_pip() -> str | None:
    return _real_tool("pip")


def _real_tool(tool: str) -> str | None:
    # Only the actual shim locations are excluded (to stop the shim calling
    # itself). We must NOT exclude the dir holding the `quarantine` console
    # script (e.g. a venv's bin), because the real pip/npm usually lives there.
    ignored = {
        str(_shim_dir(_quarantine_home()).resolve()),
        str((Path.cwd() / "interceptor" / "bin").resolve()),
    }
    path = os.pathsep.join(
        entry
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry and str(Path(entry).resolve()) not in ignored
    )
    return shutil.which(tool, path=path)


def _load_env() -> None:
    for env_path in [Path.cwd() / ".env", _repo_root() / ".env"]:
        if not env_path.exists():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _shim_dir(home: Path) -> Path:
    return home.expanduser().resolve() / "bin"


def _quarantine_home() -> Path:
    return Path(os.getenv("QUARANTINE_HOME", str(DEFAULT_HOME))).expanduser().resolve()


def _npm_shim_path(home: Path) -> Path:
    return _shim_dir(home) / "npm"


def _pip_shim_path(home: Path) -> Path:
    return _shim_dir(home) / "pip"


def _shell_init(home: Path) -> str:
    shim_dir = _shim_dir(home)
    return f'case ":$PATH:" in *":{shim_dir}:"*) ;; *) export PATH="{shim_dir}:$PATH" ;; esac'


def _shell_profile_block(home: Path) -> str:
    return "\n".join(
        [
            _shell_init(home),
            "quarantine() {",
            '  command quarantine "$@"',
            '  ret="$?"',
            '  if [ "${1:-}" = "enable" ] && [ "$ret" -eq 0 ]; then',
            '    eval "$(command quarantine shell-init)"',
            "  fi",
            '  return "$ret"',
            "}",
        ]
    )


def _detect_shell_profile() -> Path | None:
    shell = os.getenv("SHELL", "")
    home = Path.home()
    if shell.endswith("zsh"):
        return home / ".zshrc"
    if shell.endswith("bash"):
        if platform.system() == "Darwin":
            for candidate in [home / ".bash_profile", home / ".bashrc", home / ".profile"]:
                if candidate.exists():
                    return candidate
            return home / ".bash_profile"
        return home / ".bashrc"
    for candidate in [home / ".zshrc", home / ".bashrc", home / ".bash_profile", home / ".profile"]:
        if candidate.exists():
            return candidate
    return home / ".zshrc" if platform.system() == "Darwin" else home / ".profile"


def _persist_shell_init(profile: Path, home: Path) -> None:
    profile.parent.mkdir(parents=True, exist_ok=True)
    existing = profile.read_text(encoding="utf-8") if profile.exists() else ""
    start = "# >>> quarantine guard >>>"
    end = "# <<< quarantine guard <<<"
    block = f"{start}\n{_shell_profile_block(home)}\n{end}\n"
    if start in existing and end in existing:
        before, rest = existing.split(start, 1)
        _, after = rest.split(end, 1)
        profile.write_text(before.rstrip() + "\n" + block + after.lstrip(), encoding="utf-8")
        return
    suffix = "" if not existing or existing.endswith("\n") else "\n"
    profile.write_text(existing + suffix + block, encoding="utf-8")


def _offer_protected_shell(home: Path) -> None:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    shell = os.getenv("SHELL") or "/bin/sh"
    answer = input("Press Enter to start a protected shell now, or type n to skip: ").strip().lower()
    if answer in {"n", "no", "q", "quit"}:
        return
    env = os.environ.copy()
    shim_dir = str(_shim_dir(home))
    path_parts = env.get("PATH", "").split(os.pathsep)
    if shim_dir not in path_parts:
        env["PATH"] = shim_dir + os.pathsep + env.get("PATH", "")
    print("Starting protected shell. Type `exit` to return.")
    subprocess.call([shell], env=env)


def _shim_script(tool: str) -> str:
    return f"""#!/usr/bin/env sh
exec quarantine {tool}-shim "$@"
"""


if __name__ == "__main__":
    raise SystemExit(main())
