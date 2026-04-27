@echo off
echo Testing installer script...
echo.
echo Current directory: %CD%
echo.
echo Checking for executable...
if exist "dist\NetHawkService.exe" (
    echo SUCCESS: NetHawkService.exe found
) else (
    echo ERROR: NetHawkService.exe NOT found
)
echo.
echo Checking administrator privileges...
net session >nul 2>&1
if %errorLevel% equ 0 (
    echo SUCCESS: Running as Administrator
) else (
    echo ERROR: NOT running as Administrator
    echo You must run this as Administrator!
)
echo.
echo Checking for existing service...
sc query NetHawkCaptureService >nul 2>&1
if %errorLevel% equ 0 (
    echo Service already exists
    sc query NetHawkCaptureService | find "STATE"
) else (
    echo Service does not exist
)
echo.
pause

