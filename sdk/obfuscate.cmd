@echo off
echo === Obfuscate LicenseSDK.dll ===
set SDK_DIR=%~dp0
set RELEASE_DIR=%SDK_DIR%LicenseSDK\bin\Release\net10.0-windows
set INPUT_DLL=%RELEASE_DIR%\LicenseSDK.dll

if not exist "%INPUT_DLL%" (
    echo [ERROR] Release build not found at %INPUT_DLL%
    exit /b 1
)

echo === Step 1/2: Obfuscar renaming ===
where obfuscar.console >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] Obfuscar not installed. Run: dotnet tool install -g Obfuscar.GlobalTool
) else (
    pushd "%SDK_DIR%"
    obfuscar.console obfuscar.xml
    if %errorlevel% neq 0 (
        popd
        exit /b 1
    )
    popd
    echo [OK] Obfuscar renaming done.
)

set OBFUSCATED_DLL=%SDK_DIR%obfuscated\LicenseSDK.dll
if not exist "%OBFUSCATED_DLL%" set OBFUSCATED_DLL=%INPUT_DLL%

echo === Step 2/2: BitMono CallToCalli + packing ===
where bitmono.console >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] BitMono not installed. Run: dotnet tool install -g BitMono.GlobalTool
) else (
    bitmono.console -f "%OBFUSCATED_DLL%" -l "%RELEASE_DIR%" -o "%SDK_DIR%obfuscated" --protections-file "%SDK_DIR%obfuscation\protections.json" --criticals-file "%SDK_DIR%obfuscation\criticals.json" --obfuscation-file "%SDK_DIR%obfuscation\obfuscation.json"
    if %errorlevel% neq 0 (
        exit /b 1
    )
    echo [OK] BitMono done.
)

echo === Done ===
echo Final DLL: %SDK_DIR%obfuscated\LicenseSDK.dll
