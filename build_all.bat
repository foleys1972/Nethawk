@echo off
setlocal enabledelayedexpansion
REM Unified Build Script for NetHawk
REM Builds both Nethawk.exe and NetHawkService.exe

REM Change to the directory where this batch file is located FIRST
cd /d "%~dp0"

echo ========================================
echo NetHawk Unified Builder
echo ========================================
echo.
echo This will build:
echo   1. Nethawk.exe (Main Application)
echo   2. NetHawkService.exe (Remote Capture Service)
echo.
echo Current directory: %CD%
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    pause
    exit /b 1
)

REM Check if PyInstaller is installed
echo [1/5] Checking PyInstaller...
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    python -m pip install pyinstaller
    if errorlevel 1 (
        echo ERROR: Failed to install PyInstaller
        pause
        exit /b 1
    )
    echo PyInstaller installed successfully!
) else (
    echo PyInstaller found!
)

REM Check required files
echo.
echo [2/5] Checking required files...
echo Current directory: %CD%
echo.
if not exist "nethawk2_2.py" (
    echo ERROR: nethawk2_2.py not found in current directory!
    echo Current directory: %CD%
    echo Please ensure you're running build_all.bat from the project root directory
    pause
    exit /b 1
)
echo ✓ nethawk2_2.py found
if not exist "nethawk_service.py" (
    echo ERROR: nethawk_service.py not found in current directory!
    echo Current directory: %CD%
    echo Please ensure you're running build_all.bat from the project root directory
    pause
    exit /b 1
)
echo ✓ nethawk_service.py found
if not exist "nethawk2_2.spec" (
    echo WARNING: nethawk2_2.spec not found!
    echo Generating spec file automatically...
    python -m PyInstaller --name Nethawk --onefile --windowed --icon=nethawk.ico nethawk2_2.py --specpath . --clean
    if errorlevel 1 (
        echo ERROR: Failed to generate spec file
        pause
        exit /b 1
    )
) else (
    echo Spec file found: nethawk2_2.spec
)

REM Clean previous builds
echo.
echo [3/5] Cleaning previous builds...
if exist "build" rmdir /s /q build
REM Clean dist folder (PyInstaller will recreate it)
if exist "dist" rmdir /s /q dist
python -m PyInstaller --clean-cache >nul 2>&1
echo Clean complete!

REM Build Main Application (Nethawk.exe)
echo.
echo [4/5] Building Nethawk.exe (Main Application)...
echo This may take several minutes...
echo.
python -m PyInstaller --clean nethawk2_2.spec
set BUILD_MAIN_RESULT=%ERRORLEVEL%

REM Check if main executable was created (more reliable than error level)
if exist "dist\Nethawk.exe" (
    echo.
    echo ✓ Nethawk.exe built successfully!
    set BUILD_MAIN_RESULT=0
) else (
    echo.
    echo ERROR: Nethawk.exe was not created!
    if %BUILD_MAIN_RESULT% neq 0 (
        echo Build process returned error code: %BUILD_MAIN_RESULT%
    )
    echo.
    echo Continuing with service build anyway...
    echo (You can rebuild the main app separately later)
    set BUILD_MAIN_RESULT=1
)

REM Build Service (NetHawkService.exe) - Optimized, no GUI
echo.
echo [5/5] Building NetHawkService.exe (Remote Service - No GUI)...
echo This may take a few minutes...
echo.

REM Check if optimized spec file exists
if exist "NetHawkService.spec" (
    echo Using optimized spec file: NetHawkService.spec
    echo (excludes GUI components for smaller size)...
    echo.
    python -m PyInstaller --clean NetHawkService.spec
    set BUILD_SERVICE_ERRORLEVEL=%ERRORLEVEL%
) else (
    echo WARNING: NetHawkService.spec not found!
    echo Using command-line build (will create optimized spec)...
    echo.
    python -m PyInstaller --clean --onefile ^
        --name=NetHawkService ^
        --console ^
        --icon=nethawk.ico ^
        --exclude-module PyQt5 ^
        --exclude-module PyQt5.QtCore ^
        --exclude-module PyQt5.QtGui ^
        --exclude-module PyQt5.QtWidgets ^
        --exclude-module matplotlib ^
        --exclude-module numpy ^
        --exclude-module pandas ^
        --exclude-module PIL ^
        --exclude-module tkinter ^
        --hidden-import=pcap ^
        --hidden-import=scapy ^
        --hidden-import=scapy.all ^
        --hidden-import=scapy.layers.inet ^
        --hidden-import=scapy.layers.l2 ^
        --hidden-import=win32service ^
        --hidden-import=win32serviceutil ^
        --hidden-import=servicemanager ^
        --hidden-import=win32api ^
        --hidden-import=win32con ^
        --hidden-import=win32event ^
        --hidden-import=win32security ^
        --hidden-import=win32timezone ^
        --hidden-import=win32pipe ^
        --hidden-import=win32file ^
        --hidden-import=win32process ^
        --hidden-import=pythoncom ^
        --hidden-import=json ^
        --hidden-import=select ^
        --hidden-import=logging ^
        --hidden-import=logging.handlers ^
        --collect-all pywintypes ^
        --collect-binaries pywintypes ^
        nethawk_service.py
    set BUILD_SERVICE_ERRORLEVEL=%ERRORLEVEL%
)

REM Wait a moment for file system to catch up
timeout /t 3 >nul

REM Check if service executable was created (more reliable than error level)
echo.
echo Checking if NetHawkService.exe was created...
if exist "dist\NetHawkService.exe" (
    echo ✓ NetHawkService.exe built successfully!
    for %%A in ("dist\NetHawkService.exe") do (
        echo    Location: %%~fA
        echo    Size: %%~zA bytes
    )
    set BUILD_SERVICE_RESULT=0
) else (
    echo ✗ ERROR: NetHawkService.exe was not created!
    echo.
    echo Build process exit code: %BUILD_SERVICE_ERRORLEVEL%
    echo.
    echo Checking what files exist in dist folder:
    if exist "dist" (
        dir /b dist
    ) else (
        echo dist folder does not exist!
    )
    echo.
    echo Troubleshooting steps:
    echo   1. Check PyInstaller output above for errors
    echo   2. Verify nethawk_service.py has no syntax errors:
    echo      python -m py_compile nethawk_service.py
    echo   3. Try building service separately:
    echo      build_service.bat
    echo   4. Check if NetHawkService.spec exists and is valid
    echo   5. Verify dist folder exists and is writable
    echo.
    if %BUILD_MAIN_RESULT% equ 0 (
        echo NOTE: Nethawk.exe was built successfully.
        echo Only the service build failed.
    )
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

REM Show results
echo.
echo ========================================
echo Build Complete!
echo ========================================
echo.

echo Executables created:
echo   - dist\Nethawk.exe
for %%A in ("dist\Nethawk.exe") do (
    set /a SIZE_MB=%%~zA/1048576
    echo      Size: %%~zA bytes (~!SIZE_MB! MB)
)
echo   - dist\NetHawkService.exe
for %%A in ("dist\NetHawkService.exe") do (
    set /a SIZE_MB=%%~zA/1048576
    echo      Size: %%~zA bytes (~!SIZE_MB! MB)
)
echo.

echo Next steps:
echo   1. Test Nethawk.exe: dist\Nethawk.exe
echo   2. Install service: install_service.bat (run as Administrator)
echo   3. Or manually: dist\NetHawkService.exe --install
echo.

pause

