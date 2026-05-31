# interceptor.ps1 — PowerShell npm interceptor for Quarantine
#
# Activate for this terminal session:
#   . .\interceptor.ps1
#
# Now just type:  npm install <package>
# Quarantine scans it first. Blocks if malicious, installs if clean.

# Resolve root directory robustly — works whether dot-sourced by relative or absolute path
$QuarantineRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent (Resolve-Path ".\interceptor.ps1") }
$QuarantinePython = "$QuarantineRoot\.venv\Scripts\python.exe"

function npm {
    $subcmd = $args[0]

    # Only intercept: npm install <pkg> or npm i <pkg>
    if (($subcmd -eq "install" -or $subcmd -eq "i") -and $args.Count -gt 1) {

        # Find first non-flag argument — that's the package name
        $package = $null
        for ($i = 1; $i -lt $args.Count; $i++) {
            if (-not ($args[$i] -like "-*")) {
                $package = $args[$i]
                break
            }
        }

        if ($package) {
            # quarantine.py scans and either blocks or runs real npm install
            & $QuarantinePython "$QuarantineRoot\quarantine.py" $package
            return
        }
    }

    # Everything else passes through to real npm
    & npm.cmd @args
}

Write-Host "[quarantine] Interceptor active — all npm installs will be scanned."
