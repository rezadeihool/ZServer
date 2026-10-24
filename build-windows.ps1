param(
    [string] $MsysRoot = 'C:\msys64',
    [string] $BuildType = 'Release',
    [switch] $SkipDependencyInstall
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$Bash = Join-Path $MsysRoot 'usr\bin\bash.exe'
$UcrtBin = Join-Path $MsysRoot 'ucrt64\bin'
$Cmake = Join-Path $UcrtBin 'cmake.exe'
$Ninja = Join-Path $UcrtBin 'ninja.exe'
$Gcc = Join-Path $UcrtBin 'gcc.exe'
$ZstdInclude = Join-Path $MsysRoot 'ucrt64\include'
$ZstdLibDir = Join-Path $MsysRoot 'ucrt64\lib'

function Stop-Build([string] $Message, [int] $Code = 1) {
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit $Code
}

if (-not (Test-Path -LiteralPath $Bash)) {
    Stop-Build "MSYS2 was not found at '$MsysRoot'. Install MSYS2 UCRT64, or pass -MsysRoot <path>."
}

if (-not $SkipDependencyInstall) {
    Write-Host 'Installing/checking MSYS2 UCRT64 build dependencies...' -ForegroundColor Cyan
    $packages = 'mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja mingw-w64-ucrt-x86_64-zstd'
    $bashCommand = "pacman -S --needed --noconfirm $packages"
    & $Bash -lc $bashCommand
    if ($LASTEXITCODE -ne 0) {
        Stop-Build 'pacman failed. Open the MSYS2 UCRT64 shell, update/install the listed packages, then rerun with -SkipDependencyInstall.' $LASTEXITCODE
    }
}

foreach ($required in @($Cmake, $Ninja, $Gcc)) {
    if (-not (Test-Path -LiteralPath $required)) {
        Stop-Build "Required tool missing: $required. Run without -SkipDependencyInstall to install dependencies."
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $ZstdInclude 'zstd.h'))) {
    Stop-Build "zstd.h not found under '$ZstdInclude'. Install mingw-w64-ucrt-x86_64-zstd."
}

$ZstdLib = Get-ChildItem -LiteralPath $ZstdLibDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^libzstd.*\.(dll\.a|a|lib)$' } |
    Sort-Object @{ Expression = { if ($_.Name -match '\.dll\.a$') { 0 } elseif ($_.Name -match '\.a$') { 1 } else { 2 } } } |
    Select-Object -First 1
if (-not $ZstdLib) {
    Stop-Build "Could not find the Zstandard linker library under '$ZstdLibDir'."
}

$BuildDir = Join-Path $ProjectRoot 'build\windows-ucrt64'
$DistDir = Join-Path $ProjectRoot 'dist\windows-x64'
New-Item -ItemType Directory -Force -Path $BuildDir, $DistDir | Out-Null
$env:PATH = "$UcrtBin;$env:PATH"

Write-Host '== ZVPN Windows x64 build ==' -ForegroundColor Cyan
Write-Host "Source: $ProjectRoot"
Write-Host "Build:  $BuildDir"
Write-Host "Zstd:   $($ZstdLib.FullName)"

& $Cmake -S $ProjectRoot -B $BuildDir -G Ninja `
    "-DCMAKE_BUILD_TYPE=$BuildType" `
    "-DCMAKE_C_COMPILER=$Gcc" `
    "-DZSTD_INCLUDE_DIR=$ZstdInclude" `
    "-DZSTD_LIBRARY=$($ZstdLib.FullName)"
if ($LASTEXITCODE -ne 0) { Stop-Build 'CMake configure failed.' $LASTEXITCODE }

& $Cmake --build $BuildDir --parallel
if ($LASTEXITCODE -ne 0) { Stop-Build 'Compilation failed.' $LASTEXITCODE }

$Exe = Join-Path $BuildDir 'zvpn-server.exe'
if (-not (Test-Path -LiteralPath $Exe)) {
    Stop-Build "Build command returned success but executable was not found at '$Exe'."
}
Copy-Item -LiteralPath $Exe -Destination (Join-Path $DistDir 'zvpn-server.exe') -Force

# Copy common dynamically linked MSYS2 runtime libraries beside the executable.
$runtimePatterns = @('libzstd*.dll', 'libgcc_s_*.dll', 'libwinpthread-1.dll')
foreach ($pattern in $runtimePatterns) {
    Get-ChildItem -LiteralPath $UcrtBin -Filter $pattern -File -ErrorAction SilentlyContinue |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $DistDir -Force }
}

# Wintun is distributed separately. Copy it automatically if it is already in the project tree.
$Wintun = Get-ChildItem -LiteralPath $ProjectRoot -Filter 'wintun.dll' -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike "$(Join-Path $ProjectRoot 'build')*" -and $_.FullName -notlike "$(Join-Path $ProjectRoot 'dist')*" } |
    Select-Object -First 1
if ($Wintun) {
    Copy-Item -LiteralPath $Wintun.FullName -Destination (Join-Path $DistDir 'wintun.dll') -Force
} else {
    Write-Host 'NOTE: wintun.dll was not found in the project. Copy the x64 Wintun DLL beside zvpn-server.exe before running.' -ForegroundColor Yellow
}

Write-Host "`nBUILD SUCCEEDED" -ForegroundColor Green
Write-Host "Output: $DistDir"
Write-Host 'Run from an Administrator PowerShell: .\zvpn-server.exe --verbose'
