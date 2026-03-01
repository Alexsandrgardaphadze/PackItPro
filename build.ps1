# build.ps1 — PackItPro Build Automation
# Drop this file in your solution root: C:\...\PackItPro-repo\
#
# Usage:
#   .\build.ps1                      # Full build (stub + PackItPro)
#   .\build.ps1 -SkipPackItPro       # Only rebuild StubInstaller and copy
#   .\build.ps1 -SkipStub            # Only rebuild PackItPro
#   .\build.ps1 -Configuration Debug # Use Debug instead of Release
#   .\build.ps1 -Verify              # Check that the last build is valid (no compile)
#   .\build.ps1 -NoPause             # Don't wait for keypress at the end (for CI)

param(
    [string]$Configuration = "Release",
    [switch]$SkipStub,
    [switch]$SkipPackItPro,
    [switch]$Verify,
    [switch]$NoPause
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

$SolutionRoot   = "C:\Users\Alex\Desktop\Visual Studio 2022 Projects\PackItPro-repo"
$StubProject    = Join-Path $SolutionRoot "StubInstaller\StubInstaller.csproj"
$StubPublish    = Join-Path $SolutionRoot "StubInstaller\publish"
$StubExe        = Join-Path $StubPublish  "StubInstaller.exe"
$ResourcesDir   = Join-Path $SolutionRoot "PackItPro\Resources"
$ResourceTarget = Join-Path $ResourcesDir "StubInstaller.exe"
$PackItProProj  = Join-Path $SolutionRoot "PackItPro\PackItPro.csproj"

# Where dotnet puts the PackItPro build output
$PackItProBin   = Join-Path $SolutionRoot "PackItPro\bin\$Configuration\net8.0-windows\PackItPro.exe"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

$script:Errors = @()

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Ok([string]$msg)   { Write-Host "  ✓  $msg" -ForegroundColor Green }
function Write-Info([string]$msg) { Write-Host "  →  $msg" -ForegroundColor Gray }
function Write-Warn([string]$msg) { Write-Host "  ⚠  $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) {
    Write-Host "  ✗  $msg" -ForegroundColor Red
    $script:Errors += $msg
}

function Invoke-Cmd {
    param([string]$Exe, [string[]]$Arguments)
    Write-Info "$Exe $($Arguments -join ' ')"
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed (exit $LASTEXITCODE): $Exe $($Arguments -join ' ')"
    }
}

function Format-Bytes([long]$bytes) {
    if ($bytes -ge 1MB) { return "{0:0.##} MB" -f ($bytes / 1MB) }
    if ($bytes -ge 1KB) { return "{0:0.##} KB" -f ($bytes / 1KB) }
    return "$bytes B"
}

# ─────────────────────────────────────────────────────────────────────────────
# VERIFY MODE — just checks the current state, no compilation
# ─────────────────────────────────────────────────────────────────────────────

if ($Verify) {
    Write-Step "Verifying build outputs"

    # 1. StubInstaller in Resources
    if (Test-Path $ResourceTarget) {
        $stubAge  = (Get-Date) - (Get-Item $ResourceTarget).LastWriteTime
        $stubSize = (Get-Item $ResourceTarget).Length
        Write-Ok "StubInstaller.exe  $(Format-Bytes $stubSize)  (modified $([int]$stubAge.TotalMinutes) min ago)"
    } else {
        Write-Fail "StubInstaller.exe NOT FOUND at: $ResourceTarget"
        Write-Info "Fix: .\build.ps1 -SkipPackItPro"
    }

    # 2. PackItPro binary
    if (Test-Path $PackItProBin) {
        $appAge  = (Get-Date) - (Get-Item $PackItProBin).LastWriteTime
        $appSize = (Get-Item $PackItProBin).Length
        Write-Ok "PackItPro.exe      $(Format-Bytes $appSize)  (modified $([int]$appAge.TotalMinutes) min ago)"
    } else {
        Write-Fail "PackItPro.exe NOT FOUND at: $PackItProBin"
        Write-Info "Fix: .\build.ps1 -SkipStub"
    }

    # 3. Stub age vs PackItPro age — warn if stub is older than the app
    if ((Test-Path $ResourceTarget) -and (Test-Path $PackItProBin)) {
        $stubWriteTime = (Get-Item $ResourceTarget).LastWriteTime
        $appWriteTime  = (Get-Item $PackItProBin).LastWriteTime
        if ($stubWriteTime -lt $appWriteTime) {
            Write-Warn "StubInstaller.exe is older than PackItPro.exe — consider running .\build.ps1"
        } else {
            Write-Ok "Stub is up to date relative to PackItPro"
        }
    }

    Write-Host ""
    if ($script:Errors.Count -gt 0) {
        Write-Host "  VERIFY FAILED — $($script:Errors.Count) issue(s) found:" -ForegroundColor Red
        $script:Errors | ForEach-Object { Write-Host "    • $_" -ForegroundColor Red }
        if (-not $NoPause) { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
        exit 1
    } else {
        Write-Host "  All checks passed." -ForegroundColor Green
        if (-not $NoPause) { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
        exit 0
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────

Write-Step "Pre-flight checks"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet CLI not found. Install .NET 8 SDK: https://dotnet.microsoft.com/download"
}
Write-Ok "dotnet $(dotnet --version)"

if (-not (Test-Path $SolutionRoot)) {
    throw "Solution root not found: $SolutionRoot"
}
Write-Ok "Solution root found"

if (-not $SkipStub -and -not (Test-Path $StubProject)) {
    throw "StubInstaller.csproj not found: $StubProject"
}
if (-not $SkipPackItPro -and -not (Test-Path $PackItProProj)) {
    throw "PackItPro.csproj not found: $PackItProProj"
}

if (-not (Test-Path $ResourcesDir)) {
    Write-Warn "Resources directory missing — creating it"
    New-Item -ItemType Directory -Path $ResourcesDir -Force | Out-Null
}
Write-Ok "Pre-flight passed"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Clean StubInstaller
# ─────────────────────────────────────────────────────────────────────────────

if (-not $SkipStub) {
    Write-Step "Step 1: Cleaning StubInstaller"

    if (Test-Path $StubPublish) {
        Remove-Item -Path $StubPublish -Recurse -Force
        Write-Ok "Deleted old publish directory"
    }

    Invoke-Cmd dotnet @("clean", $StubProject, "--configuration", $Configuration, "--nologo", "-v", "minimal")
    Write-Ok "dotnet clean complete"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Publish StubInstaller
# ─────────────────────────────────────────────────────────────────────────────

if (-not $SkipStub) {
    Write-Step "Step 2: Publishing StubInstaller ($Configuration)"

    Invoke-Cmd dotnet @(
        "publish", $StubProject,
        "--configuration", $Configuration,
        "--runtime", "win-x64",
        "--self-contained", "true",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "--output", $StubPublish,
        "--nologo",
        "-v", "minimal"
    )

    # Verify the output exists and has reasonable size
    if (-not (Test-Path $StubExe)) {
        throw "Publish claimed success but StubInstaller.exe not found at: $StubExe"
    }
    $stubSize = (Get-Item $StubExe).Length
    if ($stubSize -lt 100KB) {
        throw "StubInstaller.exe exists but is suspiciously small ($(Format-Bytes $stubSize)) — publish may have failed"
    }
    Write-Ok "StubInstaller.exe published ($(Format-Bytes $stubSize))"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Copy to Resources
# ─────────────────────────────────────────────────────────────────────────────

if (-not $SkipStub) {
    Write-Step "Step 3: Copying stub to PackItPro\Resources"

    if (Test-Path $ResourceTarget) {
        $old = Get-Item $ResourceTarget
        Write-Info "Replacing: $(Format-Bytes $old.Length) from $($old.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    }

    Copy-Item -Path $StubExe -Destination $ResourceTarget -Force

    # Verify copy
    if (-not (Test-Path $ResourceTarget)) {
        throw "Copy command returned no error but ResourceTarget not found: $ResourceTarget"
    }
    $copiedSize  = (Get-Item $ResourceTarget).Length
    $originalSize = (Get-Item $StubExe).Length
    if ($copiedSize -ne $originalSize) {
        throw "Copy size mismatch: source=$(Format-Bytes $originalSize), dest=$(Format-Bytes $copiedSize)"
    }
    Write-Ok "StubInstaller.exe → Resources\ ($(Format-Bytes $copiedSize))"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Build PackItPro
# ─────────────────────────────────────────────────────────────────────────────

if (-not $SkipPackItPro) {
    Write-Step "Step 4: Building PackItPro ($Configuration)"

    Invoke-Cmd dotnet @(
        "build", $PackItProProj,
        "--configuration", $Configuration,
        "--nologo",
        "-v", "minimal"
    )

    # Verify the output binary exists
    if (-not (Test-Path $PackItProBin)) {
        Write-Warn "PackItPro.exe not found at expected path: $PackItProBin"
        Write-Info "Build may have succeeded to a different output path — check bin\ folder"
    } else {
        $appSize = (Get-Item $PackItProBin).Length
        Write-Ok "PackItPro.exe built ($(Format-Bytes $appSize))"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

Write-Step "Build complete"

$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

if (-not $SkipStub -and (Test-Path $ResourceTarget)) {
    Write-Ok "StubInstaller.exe  $(Format-Bytes (Get-Item $ResourceTarget).Length)  [$ts]"
}
if (-not $SkipPackItPro) {
    Write-Ok "PackItPro          built successfully  [$ts]"
}

if ($script:Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "  Warnings during build:" -ForegroundColor Yellow
    $script:Errors | ForEach-Object { Write-Host "    • $_" -ForegroundColor Yellow }
}

Write-Host ""
Write-Host "  Next step: run .\build.ps1 -Verify to confirm all outputs are present" -ForegroundColor DarkGray
Write-Host ""

if (-not $NoPause) {
    Write-Host "Press any key to exit..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

exit 0