# build.ps1 - PackItPro Build Automation
# Drop this file in your solution root (same folder as PackItPro.sln).
# It locates itself via $PSScriptRoot  -  works on any machine, any username.
#
# Usage:
#   .\build.ps1                        # Full build (stub -> Resources -> PackItPro)
#   .\build.ps1 -SkipStub              # Only republish PackItPro (stub already built)
#   .\build.ps1 -SkipPackItPro         # Only rebuild StubInstaller and copy to Resources
#   .\build.ps1 -Configuration Debug   # Debug build
#   .\build.ps1 -Verify                # Check last build outputs without recompiling
#   .\build.ps1 -Clean                 # Delete all publish\ and bin\obj dirs, then exit
#   .\build.ps1 -NoPause               # Skip keypress prompt (for CI / automated runs)
#   .\build.ps1 -WhatIf                # Show what would run without running it

param(
    [string]$Configuration = "Release",
    [switch]$SkipStub,
    [switch]$SkipPackItPro,
    [switch]$Verify,
    [switch]$Clean,
    [switch]$NoPause,
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# PATH RESOLUTION
# All paths are derived from $PSScriptRoot (the folder that contains build.ps1).
# This means the script works on any machine as long as the repo structure
# matches  -  no hardcoded usernames or drive letters.
# -----------------------------------------------------------------------------

$SolutionRoot   = $PSScriptRoot

$StubProject    = Join-Path $SolutionRoot "StubInstaller\StubInstaller.csproj"
$StubPublish    = Join-Path $SolutionRoot "StubInstaller\publish"
$StubExe        = Join-Path $StubPublish  "StubInstaller.exe"
$ResourcesDir   = Join-Path $SolutionRoot "PackItPro\Resources"
$ResourceTarget = Join-Path $ResourcesDir "StubInstaller.exe"

$PackItProProj    = Join-Path $SolutionRoot "PackItPro\PackItPro.csproj"
$PackItProPublish = Join-Path $SolutionRoot "PackItPro\publish"
$PackItProBin     = Join-Path $PackItProPublish "PackItPro.exe"

# Temp dirs for atomic publish (we publish here, then replace the real output
# only on success  -  so a failed publish never destroys the last known-good build)
$StubPublishTmp      = "$StubPublish.tmp"
$PackItProPublishTmp = "$PackItProPublish.tmp"

# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------

$script:FailList = @()

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "===========================================" -ForegroundColor Cyan
}

function Write-Ok([string]$msg)   { Write-Host "  [OK]   $msg" -ForegroundColor Green  }
function Write-Info([string]$msg) { Write-Host "  [....] $msg" -ForegroundColor Gray   }
function Write-Warn([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    $script:FailList += $msg
}

function Format-Bytes([long]$bytes) {
    if ($bytes -ge 1MB) { return "{0:0.##} MB" -f ($bytes / 1MB) }
    if ($bytes -ge 1KB) { return "{0:0.##} KB" -f ($bytes / 1KB) }
    return "$bytes B"
}

# Runs a command and streams its output live.
# On non-zero exit code, throws with the full command string so you can see
# exactly what failed instead of just "exit code N".
function Invoke-Cmd {
    param([string]$Exe, [string[]]$Arguments)
    $display = "$Exe $($Arguments -join ' ')"
    Write-Info $display
    if ($WhatIf) {
        Write-Host "  [WHAT-IF] Would run: $display" -ForegroundColor DarkYellow
        return
    }
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed (exit $LASTEXITCODE)`n  $display"
    }
}

# Reads the FileVersion from a PE's version resource using .NET's own reader.
# Falls back to "?" if the file doesn't have a version block (e.g. AOT builds).
function Get-ExeVersion([string]$path) {
    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        if ($vi.FileVersion) { return $vi.FileVersion.TrimEnd('.0') }
    } catch { }
    return "?"
}

# Atomic publish:
#   1. Publish into a .tmp folder
#   2. Only on success, remove the real folder and rename .tmp into place
# If the publish command fails, the real folder is untouched.
function Invoke-AtomicPublish {
    param(
        [string]$ProjectPath,
        [string]$TmpDir,
        [string]$FinalDir,
        [string[]]$ExtraArgs = @()
    )
    # Clean any leftover temp from a previous crashed build
    if (Test-Path $TmpDir) { Remove-Item $TmpDir -Recurse -Force }

    $publishArgs = @(
        "publish", $ProjectPath,
        "--configuration", $Configuration,
        "--runtime", "win-x64",
        "--self-contained", "true",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "--output", $TmpDir,
        "--nologo", "-v", "minimal"
    ) + $ExtraArgs

    Invoke-Cmd dotnet $publishArgs

    if (-not $WhatIf) {
        if (Test-Path $FinalDir) { Remove-Item $FinalDir -Recurse -Force }
        Rename-Item $TmpDir $FinalDir
    }
}

function Exit-Script([int]$code) {
    Write-Host ""
    if (-not $NoPause) {
        Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit $code
}

# -----------------------------------------------------------------------------
# CLEAN MODE
# -----------------------------------------------------------------------------

if ($Clean) {
    Write-Step "Clean"

    $dirsToRemove = @(
        $StubPublish, $StubPublishTmp,
        $PackItProPublish, $PackItProPublishTmp,
        (Join-Path $SolutionRoot "StubInstaller\bin"),
        (Join-Path $SolutionRoot "StubInstaller\obj"),
        (Join-Path $SolutionRoot "PackItPro\bin"),
        (Join-Path $SolutionRoot "PackItPro\obj")
    )

    foreach ($d in $dirsToRemove) {
        if (Test-Path $d) {
            Remove-Item $d -Recurse -Force
            Write-Ok "Removed: $d"
        } else {
            Write-Info "Already clean: $d"
        }
    }

    Write-Host ""
    Write-Host "  Clean complete." -ForegroundColor Green
    Exit-Script 0
}

# -----------------------------------------------------------------------------
# VERIFY MODE
# -----------------------------------------------------------------------------

if ($Verify) {
    Write-Step "Verifying build outputs"

    if (Test-Path $ResourceTarget) {
        $f      = Get-Item $ResourceTarget
        $ageMin = [int]((Get-Date) - $f.LastWriteTime).TotalMinutes
        $ver    = Get-ExeVersion $f.FullName
        Write-Ok "StubInstaller.exe   $(Format-Bytes $f.Length)   v$ver   (modified ${ageMin}m ago)"
        if ($f.Length -lt 100KB) {
            Write-Warn "StubInstaller.exe looks too small  -  may be framework-dependent (not self-contained)"
        }
    } else {
        Write-Fail "StubInstaller.exe NOT FOUND at: $ResourceTarget"
        Write-Info "Fix: .\build.ps1 -SkipPackItPro"
    }

    if (Test-Path $PackItProBin) {
        $f      = Get-Item $PackItProBin
        $ageMin = [int]((Get-Date) - $f.LastWriteTime).TotalMinutes
        $ver    = Get-ExeVersion $f.FullName
        Write-Ok "PackItPro.exe       $(Format-Bytes $f.Length)   v$ver   (modified ${ageMin}m ago)"
        if ($f.Length -lt 1MB) {
            Write-Warn "PackItPro.exe looks too small for a self-contained build"
        }
    } else {
        Write-Fail "PackItPro.exe NOT FOUND at: $PackItProBin"
        Write-Info "Fix: .\build.ps1 -SkipStub"
    }

    if ((Test-Path $ResourceTarget) -and (Test-Path $PackItProBin)) {
        $stubTime = (Get-Item $ResourceTarget).LastWriteTime
        $appTime  = (Get-Item $PackItProBin).LastWriteTime
        if ($stubTime -lt $appTime.AddMinutes(-5)) {
            Write-Warn "StubInstaller is older than PackItPro.exe  -  run .\build.ps1 to sync"
        } else {
            Write-Ok "Stub timestamp is in sync with PackItPro.exe"
        }
    }

    Write-Host ""
    if ($script:FailList.Count -gt 0) {
        Write-Host "  VERIFY FAILED  -  $($script:FailList.Count) issue(s):" -ForegroundColor Red
        $script:FailList | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
        Exit-Script 1
    }

    Write-Host "  All checks passed." -ForegroundColor Green
    Exit-Script 0
}

# -----------------------------------------------------------------------------
# GUARD: -SkipStub + -SkipPackItPro together is a no-op
# -----------------------------------------------------------------------------

if ($SkipStub -and $SkipPackItPro) {
    Write-Host ""
    Write-Warn "Both -SkipStub and -SkipPackItPro are set  -  nothing to do."
    Write-Host "  Use -Verify to check existing outputs, or -Clean to wipe them." -ForegroundColor DarkGray
    Exit-Script 0
}

# -----------------------------------------------------------------------------
# PRE-FLIGHT
# -----------------------------------------------------------------------------

Write-Step "Pre-flight checks"

# dotnet SDK on PATH
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Fail "dotnet CLI not found on PATH."
    Write-Host "  Install .NET 8 SDK: https://dotnet.microsoft.com/download" -ForegroundColor DarkGray
    Exit-Script 1
}
$dotnetVer = dotnet --version
Write-Ok "dotnet $dotnetVer"

# Warn if not .NET 8
if ($dotnetVer -notmatch "^8\.") {
    Write-Warn "Expected .NET 8 SDK  -  found $dotnetVer. Build may fail if net8.0 workload is missing."
}

# Solution root (PSScriptRoot self-check)
if (-not (Test-Path $SolutionRoot)) {
    Write-Fail "Solution root not found: $SolutionRoot"
    Write-Host "  Make sure build.ps1 is in the solution root (same folder as PackItPro.sln)." -ForegroundColor DarkGray
    Exit-Script 1
}
Write-Ok "Solution root: $SolutionRoot"

# Project files exist
if (-not $SkipStub -and -not (Test-Path $StubProject)) {
    Write-Fail "StubInstaller.csproj not found: $StubProject"
    Exit-Script 1
}
if (-not $SkipPackItPro -and -not (Test-Path $PackItProProj)) {
    Write-Fail "PackItPro.csproj not found: $PackItProProj"
    Exit-Script 1
}

# Resources dir  -  create if missing (fresh clone)
if (-not (Test-Path $ResourcesDir)) {
    Write-Warn "PackItPro\Resources\ not found  -  creating it"
    if (-not $WhatIf) { New-Item -ItemType Directory -Path $ResourcesDir -Force | Out-Null }
}

Write-Ok "Pre-flight passed"

# -----------------------------------------------------------------------------
# STEP 1  -  Publish StubInstaller (self-contained, single-file, win-x64)
# -----------------------------------------------------------------------------

if (-not $SkipStub) {
    Write-Step "Step 1: Publish StubInstaller ($Configuration)"

    try {
        Invoke-AtomicPublish `
            -ProjectPath $StubProject `
            -TmpDir      $StubPublishTmp `
            -FinalDir    $StubPublish

        if (-not $WhatIf) {
            if (-not (Test-Path $StubExe)) {
                throw "StubInstaller.exe not found after publish: $StubExe"
            }
            $sz = (Get-Item $StubExe).Length
            if ($sz -lt 100KB) {
                throw "StubInstaller.exe too small ($(Format-Bytes $sz))  -  is this a framework-dependent build?"
            }
            $ver = Get-ExeVersion $StubExe
            Write-Ok "StubInstaller.exe published  -  $(Format-Bytes $sz) v$ver"
        }
    } catch {
        Write-Fail "StubInstaller publish failed:`n  $_"
        Exit-Script 1
    }
}

# -----------------------------------------------------------------------------
# STEP 2  -  Copy StubInstaller.exe to PackItPro\Resources\
# -----------------------------------------------------------------------------

if (-not $SkipStub) {
    Write-Step "Step 2: Copy stub -> PackItPro\Resources\"

    if ($WhatIf) {
        Write-Host "  [WHAT-IF] Would copy: $StubExe" -ForegroundColor DarkYellow
        Write-Host "            -> $ResourceTarget" -ForegroundColor DarkYellow
    } else {
        if (Test-Path $ResourceTarget) {
            $old = Get-Item $ResourceTarget
            Write-Info "Replacing $(Format-Bytes $old.Length) from $($old.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))"
        }

        Copy-Item -Path $StubExe -Destination $ResourceTarget -Force

        $copiedSz   = (Get-Item $ResourceTarget).Length
        $originalSz = (Get-Item $StubExe).Length
        if ($copiedSz -ne $originalSz) {
            Write-Fail "Size mismatch after copy: src=$(Format-Bytes $originalSz) dest=$(Format-Bytes $copiedSz)"
            Exit-Script 1
        }
        Write-Ok "Copied $(Format-Bytes $copiedSz) -> Resources\StubInstaller.exe"
    }
}

# -----------------------------------------------------------------------------
# STEP 3  -  Publish PackItPro (self-contained, single-file, win-x64)
# -----------------------------------------------------------------------------

if (-not $SkipPackItPro) {
    Write-Step "Step 3: Publish PackItPro ($Configuration)"

    try {
        Invoke-AtomicPublish `
            -ProjectPath $PackItProProj `
            -TmpDir      $PackItProPublishTmp `
            -FinalDir    $PackItProPublish

        if (-not $WhatIf) {
            if (-not (Test-Path $PackItProBin)) {
                throw "PackItPro.exe not found after publish: $PackItProBin"
            }
            $sz = (Get-Item $PackItProBin).Length
            if ($sz -lt 1MB) {
                throw "PackItPro.exe too small ($(Format-Bytes $sz))  -  self-contained publish may have failed silently"
            }
            $ver = Get-ExeVersion $PackItProBin
            Write-Ok "PackItPro.exe published  -  $(Format-Bytes $sz) v$ver"
            Write-Info "Output: $PackItProBin"
        }
    } catch {
        Write-Fail "PackItPro publish failed:`n  $_"
        Exit-Script 1
    }
}

# -----------------------------------------------------------------------------
# SUMMARY TABLE
# -----------------------------------------------------------------------------

Write-Step "Build complete"

if ($WhatIf) {
    Write-Host "  [WHAT-IF] No files were written." -ForegroundColor DarkYellow
    Exit-Script 0
}

$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host ""
Write-Host ("  {0,-24} {1,-10} {2,-12} {3}" -f "File", "Size", "Version", "Built") -ForegroundColor DarkGray
Write-Host ("  {0,-24} {1,-10} {2,-12} {3}" -f "--------------------", "------", "--------", "-------------------") -ForegroundColor DarkGray

if (-not $SkipStub -and (Test-Path $ResourceTarget)) {
    $f   = Get-Item $ResourceTarget
    $ver = Get-ExeVersion $f.FullName
    Write-Host ("  {0,-24} {1,-10} {2,-12} {3}" -f "StubInstaller.exe", (Format-Bytes $f.Length), "v$ver", $ts) -ForegroundColor Green
}
if (-not $SkipPackItPro -and (Test-Path $PackItProBin)) {
    $f   = Get-Item $PackItProBin
    $ver = Get-ExeVersion $f.FullName
    Write-Host ("  {0,-24} {1,-10} {2,-12} {3}" -f "PackItPro.exe", (Format-Bytes $f.Length), "v$ver", $ts) -ForegroundColor Green
}

Write-Host ""
Write-Host "  Run .\build.ps1 -Verify to confirm outputs at any time." -ForegroundColor DarkGray

Exit-Script 0