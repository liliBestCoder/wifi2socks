@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo             wifi2socks Build Script
echo ===================================================

cd /d "%~dp0"

:: 1. Find MSBuild
set "MSBUILD="
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
        set "MSBUILD=%%i"
    )
)

if not defined MSBUILD (
    where msbuild.exe >nul 2>&1
    if !errorlevel! equ 0 (
        set "MSBUILD=msbuild.exe"
    ) else (
        echo [ERROR] MSBuild.exe not found! Please install Visual Studio 2022 / Build Tools with C++ workload.
        exit /b 1
    )
)

echo [INFO] Using MSBuild: "!MSBUILD!"

:: 2. Find or download nuget.exe
set "NUGET="
if exist "D:\tools\nuget.exe" (
    set "NUGET=D:\tools\nuget.exe"
) else (
    where nuget.exe >nul 2>&1
    if !errorlevel! equ 0 (
        set "NUGET=nuget.exe"
    ) else if exist "%~dp0nuget.exe" (
        set "NUGET=%~dp0nuget.exe"
    ) else (
        echo [INFO] Downloading nuget.exe...
        curl.exe -sSL https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -o "%~dp0nuget.exe"
        if exist "%~dp0nuget.exe" set "NUGET=%~dp0nuget.exe"
    )
)

:: 3. Restore NuGet packages
if defined NUGET (
    echo [INFO] Restoring NuGet dependencies...
    "!NUGET!" restore wifi2socks.sln -PackagesDirectory "%~dp0packages"
) else (
    echo [WARN] nuget.exe not available, skipping restore. Ensure packages exist in .\packages
)

:: 4. Ensure geoip.dat & geosite.dat exist
if not exist "%~dp0geoip.dat" (
    echo [INFO] Downloading geoip.dat from upstream...
    curl.exe -sSL "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" -o "%~dp0geoip.dat"
)
if not exist "%~dp0geosite.dat" (
    echo [INFO] Downloading geosite.dat from upstream...
    curl.exe -sSL "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" -o "%~dp0geosite.dat"
)

:: 5. Build Configuration
set "CONFIG=Release"
set "PLATFORM=x64"

if not "%1"=="" set "CONFIG=%1"
if not "%2"=="" set "PLATFORM=%2"

echo [INFO] Building wifi2socks.sln (%CONFIG%^|%PLATFORM%)...
"!MSBUILD!" wifi2socks.sln /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /m
if !errorlevel! neq 0 (
    echo [ERROR] Build failed!
    exit /b !errorlevel!
)

:: 6. Copy runtime data files to output directory
set "OUT_DIR=%~dp0%PLATFORM%\%CONFIG%"
if exist "%OUT_DIR%" (
    if exist "%~dp0geoip.dat" copy /y "%~dp0geoip.dat" "%OUT_DIR%\" >nul
    if exist "%~dp0geosite.dat" copy /y "%~dp0geosite.dat" "%OUT_DIR%\" >nul
    if exist "%~dp0config.ini" copy /y "%~dp0config.ini" "%OUT_DIR%\" >nul
    if exist "%~dp0src\driver\ndisapidll.dll" copy /y "%~dp0src\driver\ndisapidll.dll" "%OUT_DIR%\" >nul
)

echo.
echo ===================================================
echo [SUCCESS] Build succeeded!
echo Output files located at: %OUT_DIR%\
echo   - wifi2socks.exe
echo   - diag_tool.exe
echo   - ndisapidll.dll
echo   - geoip.dat / geosite.dat / config.ini
echo ===================================================

exit /b 0
