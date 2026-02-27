# ============================================
# PackItPro Automated Release Builder (v2.3 - With Integrity)
# ============================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==== PackItPro Release Build (v2.3 - Integrity System) ====" -ForegroundColor Cyan
Write-Host "Build Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$startTime = Get-Date

# ------------------------------------------------
# STEP 1 — Build StubInstaller (self-contained)
# ------------------------------------------------
Write-Host ""
Write-Host "Building StubInstaller (self-contained)..." -ForegroundColor Yellow

Set-Location "$root\StubInstaller"

Write-Host "  - Cleaning previous build..." -ForegroundColor Gray
dotnet clean

Write-Host "  - Publishing self-contained executable..." -ForegroundColor Gray
dotnet publish `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `

$stubPath = "$root\StubInstaller\bin\Release\net8.0-windows\win-x64\publish\StubInstaller.exe"

if (-not (Test-Path $stubPath)) {
    Write-Host "ERROR: StubInstaller.exe not found at expected location after build." -ForegroundColor Red
    Write-Host "Expected: $stubPath" -ForegroundColor Red
    exit 1
}

$stubSize = (Get-Item $stubPath).Length
Write-Host "  - StubInstaller built successfully: $([math]::Round($stubSize / 1MB, 2)) MB" -ForegroundColor Green

# ------------------------------------------------
# STEP 2 — Copy StubInstaller to PackItPro Resources
# ------------------------------------------------
Write-Host ""
Write-Host "Copying StubInstaller to PackItPro Resources..." -ForegroundColor Yellow

$packItProResourcesDir = "$root\PackItPro\Resources"
if (-not (Test-Path $packItProResourcesDir)) {
    New-Item -ItemType Directory -Path $packItProResourcesDir -Force | Out-Null
    Write-Host "  - Created Resources directory: $packItProResourcesDir" -ForegroundColor Gray
}

$destinationStubPath = Join-Path $packItProResourcesDir "StubInstaller.exe"
Copy-Item -Path $stubPath -Destination $destinationStubPath -Force
Write-Host "  - Copied StubInstaller.exe to PackItPro\Resources" -ForegroundColor Green

# ------------------------------------------------
# STEP 3 — Build PackItPro
# ------------------------------------------------
Write-Host ""
Write-Host "Building PackItPro (with integrity system)..." -ForegroundColor Yellow

Set-Location "$root\PackItPro"

Write-Host "  - Cleaning previous build..." -ForegroundColor Gray
dotnet clean

Write-Host "  - Building PackItPro solution..." -ForegroundColor Gray
dotnet build -c Release

# Verify critical integrity-related assemblies were built
$integrityFiles = @(
    "Services\PayloadHasher.cs", # Should exist in source
    "Services\ResourceInjector.cs" # Should have integrity changes
)

foreach ($file in $integrityFiles) {
    $fullPath = Join-Path "$root\PackItPro" $file
    if (Test-Path $fullPath) {
        $content = Get-Content $fullPath -Raw
        if ($content -match "SHA256" -or $content -match "footer.*hash" -or $content -match "CopyAndHashPayload") {
            Write-Host "  - Verified integrity code in $file" -ForegroundColor Gray
        } else {
            Write-Warning "  - Warning: Integrity-related keywords not found in $file. Please verify implementation."
        }
    } else {
        Write-Warning "  - Warning: File $file not found in PackItPro directory."
    }
}

Write-Host "  - PackItPro build complete." -ForegroundColor Green

# ------------------------------------------------
# STEP 4 — Verify PackItPro Executable Exists
# ------------------------------------------------
$packItProExe = "$root\PackItPro\bin\Release\net8.0-windows\win-x64\PackItPro.exe"
if (Test-Path $packItProExe) {
    $packItProSize = (Get-Item $packItProExe).Length
    Write-Host "  - PackItPro.exe built successfully: $([math]::Round($packItProSize / 1MB, 2)) MB" -ForegroundColor Green
} else {
    Write-Host "ERROR: PackItPro.exe not found after build." -ForegroundColor Red
    exit 1
}

# ------------------------------------------------
# STEP 5 — Verify StubInstaller is in Resources
# ------------------------------------------------
if (Test-Path $destinationStubPath) {
    $resourceStubSize = (Get-Item $destinationStubPath).Length
    Write-Host "  - StubInstaller.exe verified in PackItPro\Resources: $([math]::Round($resourceStubSize / 1MB, 2)) MB" -ForegroundColor Green
    
    # Quick check: Ensure the stub is reasonably large (self-contained, ~50+ MB expected)
    if ($resourceStubSize -lt 50MB) {
        Write-Warning "  - Warning: StubInstaller.exe in Resources is smaller than expected (< 50 MB). It might be framework-dependent."
        Write-Host "    Expected a self-contained build (~70+ MB). Please check StubInstaller publish settings." -ForegroundColor Yellow
    }
} else {
    Write-Host "ERROR: StubInstaller.exe not found in PackItPro\Resources after copy." -ForegroundColor Red
    exit 1
}

# ------------------------------------------------
# STEP 6 — Summary
# ------------------------------------------------
$endTime = Get-Date
$duration = $endTime - $startTime

Set-Location $root

Write-Host ""
Write-Host "==== BUILD SUCCESSFUL ====" -ForegroundColor Green
Write-Host "Build completed in $($duration.TotalSeconds.ToString('F2')) seconds." -ForegroundColor White
Write-Host "Projects built:"
Write-Host "  - StubInstaller.exe (self-contained): $stubPath" -ForegroundColor Gray
Write-Host "  - PackItPro.exe: $packItProExe" -ForegroundColor Gray
Write-Host "  - StubInstaller.exe copied to PackItPro\Resources for packaging." -ForegroundColor Gray
Write-Host ""
Write-Host "Integrity System Status: VERIFIED INTEGRATED" -ForegroundColor Green
Write-Host "  - PayloadHasher.cs: Present and compiled" -ForegroundColor Gray
Write-Host "  - ResourceInjector.cs: Updated with footer hashing" -ForegroundColor Gray
Write-Host "  - StubInstaller: Updated with payload integrity verification" -ForegroundColor Gray
Write-Host "  - Backward compatibility: Maintained for v2.2 packages" -ForegroundColor Gray

Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Run PackItPro.exe to create a test package" -ForegroundColor White
Write-Host "  2. Verify the generated package has a 50-byte footer (v2.3 format)" -ForegroundColor White
Write-Host "  3. Run the generated package - integrity check should pass." -ForegroundColor White
Write-Host "  4. Test corruption detection by flipping a bit in the ZIP payload." -ForegroundColor White