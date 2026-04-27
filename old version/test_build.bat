@echo off
echo ========================================
echo Testing Build Process
echo ========================================
echo.

echo Checking for executables...
if exist "dist\Nethawk.exe" (
    echo [OK] Nethawk.exe exists
    for %%A in ("dist\Nethawk.exe") do echo     Size: %%~zA bytes
) else (
    echo [MISSING] Nethawk.exe not found
)

if exist "dist\NetHawkService.exe" (
    echo [OK] NetHawkService.exe exists
    for %%A in ("dist\NetHawkService.exe") do echo     Size: %%~zA bytes
) else (
    echo [MISSING] NetHawkService.exe not found
    echo.
    echo To build the service, run:
    echo   build_service.bat
)

echo.
echo ========================================
pause

