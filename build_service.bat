@echo off
REM Build NetHawk Remote Capture Service as executable

REM Change to the directory where this batch file is located
cd /d "%~dp0" 2>nul
if errorlevel 1 (
    echo ERROR: Could not change to script directory
    echo Script path: %~dp0
    pause
    exit /b 1
)

echo ========================================
echo NetHawk Service Builder
echo ========================================
echo.
echo Script started successfully!
echo Current directory: %CD%
echo.
timeout /t 1 >nul 2>&1

REM Check if Python is available
echo Testing Python availability...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ========================================
    echo ERROR: Python not found in PATH
    echo ========================================
    echo Please ensure Python is installed and in your PATH
    echo.
    echo Press any key to close...
    pause >nul
    pause
    exit /b 1
)

echo [1/4] Checking Python installation...
python --version
if %errorLevel% neq 0 (
    echo ERROR: Failed to run Python
    echo.
    echo Press any key to close...
    pause
    exit /b 1
)

echo [2/4] Checking PyInstaller...
python -c "import PyInstaller" 2>nul
if %errorLevel% neq 0 (
    echo ERROR: PyInstaller not found
    echo.
    echo Installing PyInstaller...
    pip install pyinstaller
    if %errorLevel% neq 0 (
        echo ERROR: Failed to install PyInstaller
        echo Please run manually: pip install pyinstaller
        echo.
        echo Press any key to close...
        pause
        exit /b 1
    )
    echo PyInstaller installed successfully!
)

echo [3/4] Checking service source file...
echo Current directory: %CD%
if not exist "nethawk_service.py" (
    echo ERROR: nethawk_service.py not found in current directory
    echo Current directory: %CD%
    echo Please ensure you're running this from the project root directory
    echo The file should be in the same directory as build_service.bat
    echo.
    echo Press any key to close...
    pause
    exit /b 1
)
echo Service source file found: nethawk_service.py

echo [4/4] Building executable...
echo This may take a few minutes...
echo.
echo IMPORTANT: Do not close this window until the build completes!
echo PyInstaller output will be shown below...
echo.
echo ========================================
echo PyInstaller Output:
echo ========================================
echo.

REM Initialize error level variable
set BUILD_ERRORLEVEL=1

REM Always use python -m PyInstaller (most reliable)
echo Using: python -m PyInstaller
echo.

REM Use optimized spec file if it exists (excludes GUI components)
if exist "NetHawkService.spec" goto :build_spec
goto :build_cli

:build_spec
echo Using optimized spec file: NetHawkService.spec
echo (excludes GUI components for smaller size)...
echo.
python -m PyInstaller --clean NetHawkService.spec 2>&1
set BUILD_ERRORLEVEL=%ERRORLEVEL%
goto :check_build_result

:build_cli
echo Using command-line build...
echo NOTE: For smaller service size, use NetHawkService.spec
echo.
python -m PyInstaller --name=NetHawkService --onefile --console --exclude-module PyQt5 --exclude-module matplotlib --exclude-module numpy --exclude-module pandas --exclude-module PIL --exclude-module tkinter --hidden-import=pcap --hidden-import=scapy --hidden-import=scapy.all --hidden-import=scapy.layers.inet --hidden-import=scapy.layers.l2 --hidden-import=win32service --hidden-import=win32serviceutil --hidden-import=servicemanager --hidden-import=win32api --hidden-import=win32con --hidden-import=win32event --hidden-import=win32security --hidden-import=win32timezone --hidden-import=win32pipe --hidden-import=win32file --hidden-import=win32process --hidden-import=pywintypes --hidden-import=pythoncom --hidden-import=json --hidden-import=select --hidden-import=logging --hidden-import=logging.handlers --collect-all pywintypes --collect-binaries pywintypes nethawk_service.py 2>&1
set BUILD_ERRORLEVEL=%ERRORLEVEL%
goto :check_build_result

:check_build_result

REM Wait a moment for file system to catch up
timeout /t 2 >nul

set BUILD_RESULT=%BUILD_ERRORLEVEL%

REM Check if executable was created (more reliable than error level)
echo.
echo Checking build result...
if exist "dist\NetHawkService.exe" (
    echo.
    echo ========================================
    echo Build successful!
    echo ========================================
    echo.
    echo Executable location: dist\NetHawkService.exe
    for %%A in ("dist\NetHawkService.exe") do (
        echo    Size: %%~zA bytes
    )
    echo.
    echo Next steps:
    echo   1. Install service: install_service.bat (run as Administrator)
    echo   2. Or manually: dist\NetHawkService.exe --install
    echo   3. Start service: net start NetHawkCaptureService
    echo.
    echo ========================================
    echo Press any key to close this window...
    echo ========================================
    pause
    exit /b 0
)
echo.
echo ========================================
echo Build failed!
echo ========================================
echo.
echo Build process exit code: %BUILD_RESULT%
echo.
echo Checking what files exist:
if exist "dist" (
    echo Contents of dist folder:
    dir /b dist
) else (
    echo dist folder does not exist!
)
echo.
echo Troubleshooting:
echo   1. Check PyInstaller output above for error messages
echo   2. Verify nethawk_service.py syntax:
echo      python -m py_compile nethawk_service.py
echo   3. Check if NetHawkService.spec is valid:
echo      python -c "exec(open('NetHawkService.spec').read())"
echo   4. Verify all dependencies are installed:
echo      pip install -r requirements.txt
echo   5. Try a clean build:
echo      rmdir /s /q build dist
echo      python -m PyInstaller --clean-cache
echo.
echo.
echo ========================================
echo IMPORTANT: Review error messages above!
echo ========================================
echo.
echo ========================================
echo Press any key to close this window...
echo ========================================
pause
exit /b 1

REM Exit with appropriate code - only reach here if successful
echo.
echo ========================================
echo Press any key to close this window...
echo ========================================
pause
exit /b 0

:error_exit
echo.
echo ========================================
echo Script encountered an error!
echo ========================================
echo.
echo Press any key to close this window...
pause
exit /b 1
