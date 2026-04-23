@echo off
setlocal

set "DRIVER_NAME=K2"
set "TARGET_PATH=%SystemRoot%\System32\drivers\K2.sys"

echo [K2] Stopping "%DRIVER_NAME%".
sc.exe stop "%DRIVER_NAME%" >nul 2>&1

echo [K2] Deleting "%DRIVER_NAME%".
sc.exe delete "%DRIVER_NAME%"
if errorlevel 1 (
    echo [K2] Delete failed. The service may not exist.
    exit /b 1
)

if exist "%TARGET_PATH%" (
    echo [K2] Removing "%TARGET_PATH%".
    del /F /Q "%TARGET_PATH%"
    if errorlevel 1 (
        echo [K2] Driver file delete failed.
        exit /b 1
    )
)

echo [K2] Removed.
exit /b 0
