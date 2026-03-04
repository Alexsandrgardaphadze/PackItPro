# build.ps1 - PackItPro Build Automation
# Drop this file in your solution root: C:\...\PackItPro-repo\
#
# Usage:
#   .\build.ps1                      # Full build (stub + PackItPro publish)
#   .\build.ps1 -SkipPackItPro       # Only rebuild StubInstaller and copy to Resources
#   .\build.ps1 -SkipStub            # Only republish PackItPro
#   .\build.ps1 -Configuration Debug # Debug build
#   .\build.ps1 -Verify              # Check last build outputs without recompiling
#   .\build.ps1 -NoPause             # Skip keypress prompt (for CI)

param(
    [string]$Configuration = "Release",
    [switch]$SkipStub,
    [switch]$SkipPackItPro,
    [switch]$Verify,
    [switch]$NoPause
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------

$SolutionRoot     = "C:\Users\Alex\Desktop\Visual Studio 2022 Projects\PackItPro-repo"
$StubProject      = Join-Path $SolutionRoot "StubInstaller\StubInstaller.csproj"
$StubPublish      = Join-Path $SolutionRoot "StubInstaller\publish"
$StubExe          = Join-Path $StubPublish  "StubInstaller.exe"
$ResourcesDir     = Join-Path $SolutionRoot "PackItPro\Resources"
$ResourceTarget   = Join-Path $ResourcesDir "StubInstaller.exe"
$PackItProProj    = Join-Path $SolutionRoot "PackItPro\PackItPro.csproj"

# PackItPro publish output - single self-contained exe goes here
$PackItProPublish = Join-Path $SolutionRoot "PackItPro\publish"
$PackItProBin     = Join-Path $PackItProPublish "PackItPro.exe"

# -----------------------------------------------------------------------------
# Helpers - ASCII only, no emoji (they corrupt on copy-paste through GitHub)
# -----------------------------------------------------------------------------

$script:FailList = @()

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
}

function Write-Ok([string]$msg)   { Write-Host "  [OK]   $msg" -ForegroundColor Green  }
function Write-Info([string]$msg) { Write-Host "  [....] $msg" -ForegroundColor Gray   }
function Write-Warn([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    $script:FailList += $msg
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

function Exit-Script([int]$code) {
    Write-Host ""
    if (-not $NoPause) {
        Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit $code
}

# -----------------------------------------------------------------------------
# VERIFY MODE - checks outputs without building
# -----------------------------------------------------------------------------

if ($Verify) {
    Write-Step "Verifying build outputs"

    if (Test-Path $ResourceTarget) {
        $f = Get-Item $ResourceTarget
        $ageMin = [int]((Get-Date) - $f.LastWriteTime).TotalMinutes
        Write-Ok "StubInstaller.exe   $(Format-Bytes $f.Length)   (modified ${ageMin}m ago)"
        if ($f.Length -lt 100KB) { Write-Warn "StubInstaller.exe looks too small - may be corrupt or framework-dependent" }
    } else {
        Write-Fail "StubInstaller.exe NOT FOUND at: $ResourceTarget"
        Write-Info "Fix: .\build.ps1 -SkipPackItPro"
    }

    if (Test-Path $PackItProBin) {
        $f = Get-Item $PackItProBin
        $ageMin = [int]((Get-Date) - $f.LastWriteTime).TotalMinutes
        Write-Ok "PackItPro.exe       $(Format-Bytes $f.Length)   (modified ${ageMin}m ago)"
        if ($f.Length -lt 1MB) { Write-Warn "PackItPro.exe looks too small for a self-contained build" }
    } else {
        Write-Fail "PackItPro.exe NOT FOUND at: $PackItProBin"
        Write-Info "Fix: .\build.ps1 -SkipStub"
    }

    if ((Test-Path $ResourceTarget) -and (Test-Path $PackItProBin)) {
        $stubTime = (Get-Item $ResourceTarget).LastWriteTime
        $appTime  = (Get-Item $PackItProBin).LastWriteTime
        if ($stubTime -lt $appTime.AddMinutes(-5)) {
            Write-Warn "StubInstaller is older than PackItPro.exe - run .\build.ps1 to sync"
        } else {
            Write-Ok "Stub is up to date relative to PackItPro.exe"
        }
    }

    Write-Host ""
    if ($script:FailList.Count -gt 0) {
        Write-Host "  VERIFY FAILED - $($script:FailList.Count) issue(s):" -ForegroundColor Red
        $script:FailList | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
        Exit-Script 1
    } else {
        Write-Host "  All checks passed. Ready to ship." -ForegroundColor Green
        Exit-Script 0
    }
}

# -----------------------------------------------------------------------------
# PRE-FLIGHT
# -----------------------------------------------------------------------------

Write-Step "Pre-flight checks"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet CLI not found. Install .NET 8 SDK: https://dotnet.microsoft.com/download"
}
Write-Ok "dotnet $(dotnet --version)"

if (-not (Test-Path $SolutionRoot))  { throw "Solution root not found: $SolutionRoot" }
Write-Ok "Solution root found"

if (-not $SkipStub      -and -not (Test-Path $StubProject))   { throw "StubInstaller.csproj not found: $StubProject" }
if (-not $SkipPackItPro -and -not (Test-Path $PackItProProj)) { throw "PackItPro.csproj not found: $PackItProProj" }

if (-not (Test-Path $ResourcesDir)) {
    Write-Warn "Resources\ missing - creating it"
    New-Item -ItemType Directory -Path $ResourcesDir -Force | Out-Null
}
Write-Ok "Pre-flight passed"

# -----------------------------------------------------------------------------
# STEP 1 - Clean + Publish StubInstaller
# -----------------------------------------------------------------------------

if (-not $SkipStub) {
    Write-Step "Step 1: Clean + Publish StubInstaller ($Configuration)"

    if (Test-Path $StubPublish) {
        Remove-Item -Path $StubPublish -Recurse -Force
        Write-Ok "Cleaned StubInstaller\publish\"
    }

    Invoke-Cmd dotnet @("clean", $StubProject, "--configuration", $Configuration, "--nologo", "-v", "minimal")

    Invoke-Cmd dotnet @(
        "publish", $StubProject,
        "--configuration", $Configuration,
        "--runtime", "win-x64",
        "--self-contained", "true",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "--output", $StubPublish,
        "--nologo", "-v", "minimal"
    )

    if (-not (Test-Path $StubExe)) { throw "StubInstaller.exe not found after publish: $StubExe" }
    $sz = (Get-Item $StubExe).Length
    if ($sz -lt 100KB) { throw "StubInstaller.exe too small ($(Format-Bytes $sz)) - publish failed silently" }
    Write-Ok "StubInstaller.exe published ($(Format-Bytes $sz))"
}

# -----------------------------------------------------------------------------
# STEP 2 - Copy StubInstaller to Resources
# -----------------------------------------------------------------------------

if (-not $SkipStub) {
    Write-Step "Step 2: Copy stub to PackItPro\Resources\"

    if (Test-Path $ResourceTarget) {
        $old = Get-Item $ResourceTarget
        Write-Info "Replacing $(Format-Bytes $old.Length) from $($old.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))"
    }

    Copy-Item -Path $StubExe -Destination $ResourceTarget -Force

    if (-not (Test-Path $ResourceTarget)) { throw "Copy succeeded but file not found: $ResourceTarget" }
    $copiedSz   = (Get-Item $ResourceTarget).Length
    $originalSz = (Get-Item $StubExe).Length
    if ($copiedSz -ne $originalSz) { throw "Copy size mismatch: src=$(Format-Bytes $originalSz) dest=$(Format-Bytes $copiedSz)" }
    Write-Ok "StubInstaller.exe -> Resources\ ($(Format-Bytes $copiedSz))"
}

# -----------------------------------------------------------------------------
# STEP 3 - Publish PackItPro (self-contained single exe)
# -----------------------------------------------------------------------------

if (-not $SkipPackItPro) {
    Write-Step "Step 3: Publish PackItPro ($Configuration)"

    if (Test-Path $PackItProPublish) {
        Remove-Item -Path $PackItProPublish -Recurse -Force
        Write-Ok "Cleaned PackItPro\publish\"
    }

    Invoke-Cmd dotnet @(
        "publish", $PackItProProj,
        "--configuration", $Configuration,
        "--runtime", "win-x64",
        "--self-contained", "true",
        "--output", $PackItProPublish,
        "--nologo", "-v", "minimal"
    )

    if (-not (Test-Path $PackItProBin)) { throw "PackItPro.exe not found after publish: $PackItProBin" }
    $sz = (Get-Item $PackItProBin).Length
    if ($sz -lt 1MB) { throw "PackItPro.exe too small ($(Format-Bytes $sz)) - self-contained publish failed" }
    Write-Ok "PackItPro.exe published ($(Format-Bytes $sz))"
    Write-Info "Output: $PackItProBin"
}

# -----------------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------------

Write-Step "Build complete"
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

if (-not $SkipStub -and (Test-Path $ResourceTarget)) {
    Write-Ok "StubInstaller.exe   $(Format-Bytes (Get-Item $ResourceTarget).Length)   [$ts]"
}
if (-not $SkipPackItPro -and (Test-Path $PackItProBin)) {
    Write-Ok "PackItPro.exe       $(Format-Bytes (Get-Item $PackItProBin).Length)   [$ts]"
}

Write-Host ""
Write-Host "  Run .\build.ps1 -Verify to confirm all outputs" -ForegroundColor DarkGray

Exit-Script 0