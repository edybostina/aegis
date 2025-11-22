# PowerShell build script for Windows
param(
    [string]$BuildDir = "build",
    [string]$BuildType = "Release"
)

$ErrorActionPreference = "Stop"

Write-Host "Building Aegis for Windows..." -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
Set-Location $BuildDir

if ($env:VCPKG_ROOT) {
    Write-Host "Using vcpkg from: $env:VCPKG_ROOT" -ForegroundColor Green
    $VcpkgToolchain = "$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
} elseif (Test-Path "$env:VCPKG_INSTALLATION_ROOT") {
    Write-Host "Using vcpkg from: $env:VCPKG_INSTALLATION_ROOT" -ForegroundColor Green
    $VcpkgToolchain = "$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake"
} else {
    Write-Host "Warning: vcpkg not found. Make sure libsodium and zlib are available." -ForegroundColor Yellow
    $VcpkgToolchain = $null
}

Write-Host "`nConfiguring CMake..." -ForegroundColor Cyan
if ($VcpkgToolchain) {
    cmake .. -DCMAKE_BUILD_TYPE=$BuildType -DCMAKE_TOOLCHAIN_FILE=$VcpkgToolchain -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
} else {
    cmake .. -DCMAKE_BUILD_TYPE=$BuildType -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "CMake configuration failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`nBuilding ($BuildType)..." -ForegroundColor Cyan
cmake --build . --config $BuildType --parallel

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

if ($env:RUN_TESTS -eq "1") {
    Write-Host "`nRunning tests..." -ForegroundColor Cyan
    ctest --output-on-failure -C $BuildType
}

Write-Host "`nBuild completed successfully!" -ForegroundColor Green
Write-Host "Executable: $BuildDir\$BuildType\aegis.exe" -ForegroundColor Green
