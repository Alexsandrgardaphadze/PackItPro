# ============================================
# PackItPro Automated Release Builder
# ============================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==== PackItPro Release Build ====" -ForegroundColor Cyan

$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# ------------------------------------------------
# STEP 1 — Build StubInstaller (self-contained)
# ------------------------------------------------
Write-Host ""
Write-Host "Building StubInstaller..." -ForegroundColor Yellow

Set-Location "$root\StubInstaller"

dotnet clean

dotnet publish `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:DebugType=None `
    -p:DebugSymbols=false

Write-Host "StubInstaller build complete." -ForegroundColor Green

# ------------------------------------------------
# STEP 2 — Build PackItPro
# ------------------------------------------------
Write-Host ""
Write-Host "Building PackItPro..." -ForegroundColor Yellow

Set-Location "$root\PackItPro"

dotnet clean
dotnet build -c Release

Write-Host "PackItPro build complete." -ForegroundColor Green

# ------------------------------------------------
# STEP 3 — Done
# ------------------------------------------------
Set-Location $root

Write-Host ""
Write-Host "==== BUILD SUCCESSFUL ====" -ForegroundColor Cyan
