# Runs EVERY WEWAF fuzz target for a bounded time using Go's built-in fuzzing.
# No external dependencies, no CI minutes required — meant to be run locally
# (or in a nightly job once spare CI capacity exists).
#
# Targets are AUTO-DISCOVERED (`go test -list`) so a newly-added FuzzXxx is run
# automatically — the previous hand-maintained list silently skipped most of
# them.
#
# Usage:
#   ./scripts/fuzz.ps1 [seconds-per-target] [name-regex]
#   $env:WEWAF_GO = "D:\path\to\go.exe"; ./scripts/fuzz.ps1 30
#   ./scripts/fuzz.ps1 45 'Canonicalize|Harden'   # only matching targets
#
# Exits non-zero if any target finds a crash (the reproducer is written under
# the package's testdata/fuzz/<Target>/ directory and becomes a permanent
# regression corpus entry — commit it).
param([int]$Seconds = 30, [string]$Filter = ".")

$ErrorActionPreference = "Stop"
$go = if ($env:WEWAF_GO) { $env:WEWAF_GO } else { "go" }
$root = Split-Path $PSScriptRoot -Parent

$failed = @()
$count = 0

# Discover packages, then list each package's fuzz targets. `go test -list`
# prints matching function names one per line; keep only fuzz-target names.
$pkgs = & $go -C $root list ./...
foreach ($pkg in $pkgs) {
    $names = & $go -C $root test -list '^Fuzz' $pkg 2>$null | Where-Object { $_ -match '^Fuzz' }
    foreach ($fn in $names) {
        if ($fn -notmatch $Filter) { continue }
        $count++
        Write-Host "==== $pkg :: $fn  ($Seconds s) ===="
        & $go -C $root test -run='^$' -fuzz="^$fn`$" -fuzztime="$($Seconds)s" $pkg
        if ($LASTEXITCODE -ne 0) { $failed += "$pkg::$fn" }
    }
}

Write-Host ""
Write-Host "ran $count fuzz target(s)"
if ($failed.Count -gt 0) {
    Write-Host "FUZZ FAILURES: $($failed -join ', ')" -ForegroundColor Red
    Write-Host "repro(s) under each package's testdata/fuzz/<Target>/ — commit them as regression corpus." -ForegroundColor Yellow
    exit 1
}
Write-Host "all $count fuzz targets passed" -ForegroundColor Green
