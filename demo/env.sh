# demo/env.sh — source this before a demo install so `pip`/`npm` route through
# Package Quarantine and the verdict traces into W&B Weave.
#
#   source demo/env.sh && pip install <package>
#
# Order matters: activate the venv first, THEN put the Quarantine shim dir at the
# front of PATH so `pip`/`npm` resolve to the shim (while `quarantine` itself
# still resolves to the venv binary).

cd /Users/jenishkothari/Northeastern/Projects/weave-hack
source myenv/bin/activate
export PATH="$HOME/.quarantine/bin:$PATH"
set -a; source .env 2>/dev/null; set +a
# Unbuffered so the Quarantine verdict prints BEFORE the real pip output
# (otherwise Python buffers and 'Successfully installed' can appear first).
export PYTHONUNBUFFERED=1