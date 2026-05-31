"""
weave_shim.py — import `op` and `init` from here, NOT from weave directly.

This lets the skeleton run end-to-end even before anyone has logged into W&B.
If weave is installed + configured, you get real tracing. If not, ops become
no-ops so nobody is blocked.

Owner: Person B (spine).
"""
from __future__ import annotations

try:
    import weave  # type: ignore

    _HAS_WEAVE = True
except Exception:  # weave not installed yet
    weave = None
    _HAS_WEAVE = False


def init(project: str = "quarantine") -> None:
    if _HAS_WEAVE:
        try:
            weave.init(project)
            print(f"[weave] tracing to project '{project}'")
            return
        except Exception as e:
            print(f"[weave] init failed ({e}); running without tracing")
    else:
        print("[weave] not installed; running without tracing (pip install weave)")


def op(fn=None):
    """Decorator: real @weave.op if available, else a no-op passthrough."""
    if _HAS_WEAVE:
        return weave.op()(fn) if fn is not None else weave.op()
    if fn is not None:
        return fn

    def _wrap(f):
        return f

    return _wrap