# Interceptor (npm shim)

Owner: Person B (spine).

Catches `npm install <pkg>`, pauses it, asks the orchestrator for a verdict, and
only lets the real install proceed if the verdict is `allow`.

## Package-based shim

Supported today: Linux and macOS shells (`bash` / `zsh`). Windows needs
separate `.cmd` / PowerShell shims.

Install the CLI, then enable the npm shim:

```
cd /home/yash/Github/weave-hack
pip install -e .
quarantine enable
```

Open a new terminal. Now any command like `npm install <pkg>` or
`pip install <pkg>` hits Quarantine before the real package manager:

```
npm install evil-demo-pkg
pip install requests
```

For this repo's development checkout, the local shim also works:

```
export PATH="$PWD/interceptor/bin:$PATH"
npm install evil-demo-pkg
pip install requests
```

If Docker still needs explicit group access, run the whole command under
`sg docker`:

```
sg docker -c "bash -lc 'cd /home/yash/Github/weave-hack && set -a && source .env && set +a && eval \"$(quarantine shell-init)\" && npm install evil-demo-pkg'"
```

For a demo that checks the package but does not run real npm after an allow:

```
QUARANTINE_DRY_RUN=1 npm install lodash
QUARANTINE_DRY_RUN=1 pip install requests
```

The shim loads `.env`, calls `quarantine_install_trace()`, prints the verdict,
and only invokes the real package manager if every requested package is allowed.

Note: npm has the full current detection path. pip interception is wired and
fires the same pipeline, but PyPI-specific intel and pip detonation are the next
backend upgrade.

## TODO
- [x] PATH-based npm shim for LLM-agent shells
- [x] PATH-based pip shim for LLM-agent shells
- [ ] FastAPI/Flask wrapper around `orchestrate()` on :8000
- [ ] (stretch) intercept package managers beyond npm
