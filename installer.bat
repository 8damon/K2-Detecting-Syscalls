@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "DRIVER_NAME=K2"
set "SOURCE_PATH=%SCRIPT_DIR%K2.sys"
set "TARGET_PATH=%SystemRoot%\System32\drivers\K2.sys"
set "PFX_PATH=%SCRIPT_DIR%TITAN Softwork Solutions.pfx"
set "SIGNTOOL=%ProgramFiles(x86)%\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
set "PFX_PASSWORD=%~1"

if "%PFX_PASSWORD%"=="" set "PFX_PASSWORD=%K2_PFX_PASSWORD%"

if not exist "%SOURCE_PATH%" (
    echo [K2] Driver not found: "%SOURCE_PATH%"
    echo [K2] Build the driver first.
    exit /b 1
)

if exist "%PFX_PATH%" (
    if exist "%SIGNTOOL%" (
        if "%PFX_PASSWORD%"=="" (
            echo [K2] PFX found but no password supplied. Skipping signing.
            echo [K2] Pass the password as the first arg or set K2_PFX_PASSWORD.
        ) else (
            echo [K2] Signing "%SOURCE_PATH%".
            "%SIGNTOOL%" sign /q /fd sha256 /f "%PFX_PATH%" /p "%PFX_PASSWORD%" "%SOURCE_PATH%"
            if errorlevel 1 (
                echo [K2] Signing failed.
                exit /b 1
            )
        )
    ) else (
        echo [K2] signtool.exe not found. Skipping signing.
    )
) else (
    echo [K2] PFX not found. Skipping signing.
)

echo [K2] Copying driver to "%TARGET_PATH%".
copy /Y "%SOURCE_PATH%" "%TARGET_PATH%" >nul
if errorlevel 1 (
    echo [K2] Driver copy failed.
    exit /b 1
)

sc.exe query "%DRIVER_NAME%" >nul 2>&1
if %errorlevel%==0 (
    echo [K2] Service already exists. Updating binary path.
    sc.exe stop "%DRIVER_NAME%" >nul 2>&1
    sc.exe config "%DRIVER_NAME%" type= kernel start= demand binPath= "%TARGET_PATH%"
) else (
    echo [K2] Creating service "%DRIVER_NAME%".
    sc.exe create "%DRIVER_NAME%" type= kernel start= demand binPath= "%TARGET_PATH%"
)

if errorlevel 1 (
    echo [K2] Service create/config failed.
    exit /b 1
)

echo [K2] Starting "%DRIVER_NAME%".
sc.exe start "%DRIVER_NAME%"
if errorlevel 1 (
    echo [K2] Start failed.
    exit /b 1
)

echo [K2] Installed and started.
exit /b 0
