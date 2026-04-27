@echo off
REM Quick build script for service only - minimal checks

cd /d "%~dp0"

echo ========================================
echo Quick Service Build
echo ========================================
echo.

if not exist "nethawk_service.py" (
    echo ERROR: nethawk_service.py not found
    echo Current directory: %CD%
    pause
    exit /b 1
)

if not exist "NetHawkService.spec" (
    echo ERROR: NetHawkService.spec not found
    echo Current directory: %CD%
    pause
    exit /b 1
)

echo Building NetHawkService.exe...
echo.

python -m PyInstaller --clean NetHawkService.spec

echo.
if exist "dist\NetHawkService.exe" (
    echo.
    echo ========================================
    echo SUCCESS!
    echo ========================================
    echo.
    echo NetHawkService.exe created in dist folder
    for %%A in ("dist\NetHawkService.exe") do (
        echo Size: %%~zA bytes
    )
) else (
    echo.
    echo ========================================
    echo FAILED!
    echo ========================================
    echo.
    echo NetHawkService.exe was not created
    echo Check the error messages above
)

echo.
pause

