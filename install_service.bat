@echo off
REM NetHawk Service Installer
REM This script installs and configures the NetHawk Remote Capture Service

setlocal enabledelayedexpansion

REM Change to the directory where this batch file is located
cd /d "%~dp0"

echo ========================================
echo NetHawk Remote Capture Service Installer
echo ========================================
echo.
echo Starting installation process...
echo Current directory: %CD%
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo ========================================
    echo ERROR: Administrator Privileges Required
    echo ========================================
    echo.
    echo This script must be run as Administrator.
    echo.
    echo To fix this:
    echo   1. Right-click on install_service.bat
    echo   2. Select "Run as administrator"
    echo   3. Click "Yes" when prompted
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

REM Check if service executable exists
if not exist "dist\NetHawkService.exe" (
    echo.
    echo ========================================
    echo ERROR: Service Executable Not Found
    echo ========================================
    echo.
    echo NetHawkService.exe not found in dist folder.
    echo.
    echo Please build the service first:
    echo   1. Run: build_service.bat
    echo   2. Wait for build to complete
    echo   3. Then run this installer again
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

echo [1/5] Checking for existing service...
sc query NetHawkCaptureService >nul 2>&1
if %errorLevel% equ 0 (
    echo Service already exists. Stopping and removing...
    net stop NetHawkCaptureService >nul 2>&1
    timeout /t 2 >nul
    if exist "dist\NetHawkService.exe" (
        dist\NetHawkService.exe remove
        if %errorLevel% neq 0 (
            echo WARNING: Failed to uninstall existing service via executable
            echo Attempting manual removal...
            sc delete NetHawkCaptureService
            timeout /t 2 >nul
        ) else (
            timeout /t 2 >nul
        )
    ) else (
        echo WARNING: NetHawkService.exe not found, attempting manual removal...
        sc delete NetHawkCaptureService
        timeout /t 2 >nul
    )
)

echo [2/5] Installing service...
dist\NetHawkService.exe --install
set INSTALL_RESULT=%ERRORLEVEL%

REM Check if service was actually installed (more reliable than error code)
timeout /t 2 >nul
sc query NetHawkCaptureService >nul 2>&1
if %errorLevel% equ 0 (
    echo.
    echo ========================================
    echo SUCCESS: Service Installed!
    echo ========================================
    echo.
    echo The NetHawk Remote Capture Service has been installed successfully.
    echo.
    echo Service name: NetHawkCaptureService
    echo.
    echo You can now:
    echo   - Start service: net start NetHawkCaptureService
    echo   - Stop service: net stop NetHawkCaptureService
    echo   - View in Services: services.msc
    echo.
    set INSTALL_RESULT=0
) else (
    if %INSTALL_RESULT% neq 0 (
        echo.
        echo ========================================
        echo ERROR: Service Installation Failed
        echo ========================================
        echo.
        echo Failed to install the service.
        echo.
        echo Possible causes:
        echo   - Service is already installed (will be removed automatically)
        echo   - Missing dependencies (pywin32 may not be bundled)
        echo   - Permission issues
        echo.
        echo Press any key to exit...
        pause >nul
        exit /b 1
    )
)

echo [3/5] Configuring service...
REM Set service to start automatically
sc config NetHawkCaptureService start= auto
if %errorLevel% neq 0 (
    echo WARNING: Failed to set service to auto-start
    echo You may need to configure this manually in Services.msc
)

REM Set service description
sc description NetHawkCaptureService "Provides remote packet capture for NetHawk application"
if %errorLevel% neq 0 (
    echo WARNING: Failed to set service description
)

echo [4/5] Starting service...
net start NetHawkCaptureService
if %errorLevel% neq 0 (
    echo WARNING: Failed to start service automatically
    echo.
    echo You can start it manually with:
    echo   net start NetHawkCaptureService
    echo.
    echo Or check the Windows Event Viewer for error details.
) else (
    echo Service started successfully!
)

echo [5/5] Verifying installation...
timeout /t 2 >nul
sc query NetHawkCaptureService >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo ========================================
    echo Installation FAILED!
    echo ========================================
    echo.
    echo The service was not installed successfully.
    echo Check the error messages above for details.
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

sc query NetHawkCaptureService | find "RUNNING" >nul
if %errorLevel% equ 0 (
    echo.
    echo ========================================
    echo Installation completed successfully!
    echo ========================================
    echo.
    echo Service Status: RUNNING
    echo Service Name: NetHawkCaptureService
    echo Default Port: 2002
    echo.
    echo To manage the service:
    echo   Start:   net start NetHawkCaptureService
    echo   Stop:    net stop NetHawkCaptureService
    echo   Status:  sc query NetHawkCaptureService
    echo.
    echo Log file: C:\ProgramData\NetHawk\nethawk_service.log
    echo.
) else (
    echo.
    echo ========================================
    echo Installation completed with warnings
    echo ========================================
    echo.
    echo Service installed but not running.
    echo.
    echo Try starting manually:
    echo   net start NetHawkCaptureService
    echo.
    echo Check the log file for errors:
    echo   C:\ProgramData\NetHawk\nethawk_service.log
    echo.
)

echo.
echo Press any key to exit...
pause >nul

