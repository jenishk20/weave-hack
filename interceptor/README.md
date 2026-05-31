# Interceptor (npm shim)

Owner: Person B (spine).

Catches `npm install <pkg>`, pauses it, asks the orchestrator for a verdict, and
only lets the real install proceed if the verdict is `allow`.

## Simplest version for the demo
A tiny shell function / alias that forwards the package name to the orchestrator
over local HTTP and blocks on the response:

```
npm() {
  if [ "$1" = "install" ] || [ "$1" = "i" ]; then
    verdict=$(curl -s "localhost:8000/check?pkg=$2")
    if [ "$verdict" = "block" ]; then
      echo "🛡️  Quarantine BLOCKED $2"; return 1
    fi
  fi
  command npm "$@"
}
```

(Requires the orchestrator exposed via a tiny FastAPI/Flask endpoint — wrap
`orchestrate()` in one route. Build the function-call version first; add HTTP
only when wiring the live demo.)

## TODO
- [ ] FastAPI/Flask wrapper around `orchestrate()` on :8000
- [ ] shell shim above, sourced into the demo shell
- [ ] (stretch) intercept the AI coder's bash tool instead of a shell alias