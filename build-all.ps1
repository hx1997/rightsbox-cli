param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [string]$OutputRoot = "dist",

    [switch]$SkipConfigure
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found in PATH."
    }
}

function Invoke-CMake {
    param([string[]]$CMakeArgs)
    & cmake @CMakeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cmake $($CMakeArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Copy-IfExists {
    param(
        [string]$Source,
        [string]$Destination,
        [switch]$Required
    )

    if (Test-Path -LiteralPath $Source) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
        return
    }

    if ($Required) {
        throw "Expected build artifact not found: $Source"
    }

    Write-Host "[WARN] Optional artifact not found: $Source"
}

Require-Command -Name "cmake"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $repoRoot

$x64Preset = "vs2022-x64"
$x86Preset = "vs2022-x86"
$x64BuildDir = Join-Path $repoRoot "cmake-build-vs2022"
$x86BuildDir = Join-Path $repoRoot "cmake-build-vs2022-x86"

if (-not $SkipConfigure) {
    Write-Host "[INFO] Configuring $x64Preset"
    Invoke-CMake -CMakeArgs @("--preset", $x64Preset)

    Write-Host "[INFO] Configuring $x86Preset"
    Invoke-CMake -CMakeArgs @("--preset", $x86Preset)
}

Write-Host "[INFO] Building x64 ($Configuration)"
Invoke-CMake -CMakeArgs @("--build", $x64BuildDir, "--config", $Configuration)

Write-Host "[INFO] Building x86 ($Configuration)"
Invoke-CMake -CMakeArgs @("--build", $x86BuildDir, "--config", $Configuration)

$outputDir = Join-Path $repoRoot (Join-Path $OutputRoot $Configuration)
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$x64Out = Join-Path $x64BuildDir $Configuration
$x86Out = Join-Path $x86BuildDir $Configuration

Write-Host "[INFO] Staging artifacts into $outputDir"

# Primary runtime payload from x64 build
Copy-IfExists -Source (Join-Path $x64Out "RightsBox.exe") -Destination (Join-Path $outputDir "RightsBox.exe") -Required
Copy-IfExists -Source (Join-Path $x64Out "RBoxRunner.exe") -Destination (Join-Path $outputDir "RBoxRunner.exe") -Required
Copy-IfExists -Source (Join-Path $x64Out "RBoxHook64.dll") -Destination (Join-Path $outputDir "RBoxHook64.dll") -Required
Copy-IfExists -Source (Join-Path $x64Out "RBoxInject64.exe") -Destination (Join-Path $outputDir "RBoxInject64.exe") -Required

# Cross-arch payload from x86 build
Copy-IfExists -Source (Join-Path $x86Out "RBoxHook32.dll") -Destination (Join-Path $outputDir "RBoxHook32.dll") -Required
Copy-IfExists -Source (Join-Path $x86Out "RBoxInject32.exe") -Destination (Join-Path $outputDir "RBoxInject32.exe") -Required

# Preserve x86 launcher/runtime with collision-safe names
Copy-IfExists -Source (Join-Path $x86Out "RightsBox.exe") -Destination (Join-Path $outputDir "RightsBox32.exe") -Required
Copy-IfExists -Source (Join-Path $x86Out "RBoxRunner.exe") -Destination (Join-Path $outputDir "RBoxRunner32.exe") -Required

# Optional policy file next to final binaries
$policyFile = Join-Path $repoRoot "policy.conf"
if (Test-Path -LiteralPath $policyFile) {
    Copy-Item -LiteralPath $policyFile -Destination (Join-Path $outputDir "policy.conf") -Force
}

Write-Host "[DONE] Unified build output is ready at: $outputDir"