@echo off
REM Build NetHawk Main Application (Nethawk.exe)

REM Prevent window from closing on error - MUST be first line after @echo off
setlocal

REM Change to the directory where this batch file is located
cd /d "%~dp0" 2>nul
if errorlevel 1 (
    echo ERROR: Could not change to script directory
    echo Script path: %~dp0
    pause
    exit /b 1
)

echo ========================================
echo NetHawk Main Application Builder
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

echo [3/4] Checking application source file...
echo Current directory: %CD%
if not exist "nethawk2_2.py" (
    echo ERROR: nethawk2_2.py not found in current directory
    echo Current directory: %CD%
    echo Please ensure you're running this from the project root directory
    echo The file should be in the same directory as build_exe.bat
    echo.
    echo Press any key to close...
    pause
    exit /b 1
)
echo Application source file found: nethawk2_2.py

REM Check if spec file exists
if not exist "nethawk2_2.spec" (
    echo WARNING: nethawk2_2.spec not found!
    echo Generating spec file automatically...
    python -m PyInstaller --name Nethawk --onefile --windowed --icon=nethawk.ico nethawk2_2.py --specpath . --clean
    if %errorLevel% neq 0 (
        echo ERROR: Failed to generate spec file
        echo.
        echo Press any key to close...
        pause
        exit /b 1
    )
) else (
    echo Spec file found: nethawk2_2.spec
)

echo [4/4] Building executable...
echo This may take several minutes (GUI application is large)...
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

REM Use spec file if it exists (recommended)
if exist "nethawk2_2.spec" (
    echo Using spec file: nethawk2_2.spec
    echo.
    python -m PyInstaller --clean nethawk2_2.spec 2>&1
    set BUILD_ERRORLEVEL=%ERRORLEVEL%
) else (
    echo Using command-line build...
    echo.
    python -m PyInstaller --clean --onefile --windowed --name=Nethawk --icon=nethawk.ico nethawk2_2.py 2>&1
    set BUILD_ERRORLEVEL=%ERRORLEVEL%
)

REM Wait a moment for file system to catch up
timeout /t 2 >nul

set BUILD_RESULT=%BUILD_ERRORLEVEL%

REM Check if executable was created (more reliable than error level)
echo.
echo Checking build result...
if exist "dist\Nethawk.exe" (
    echo.
    echo ========================================
    echo Build successful!
    echo ========================================
    echo.
    echo Executable location: dist\Nethawk.exe
    for %%A in ("dist\Nethawk.exe") do (
        set /a SIZE_MB=%%~zA/1048576
        echo    Size: %%~zA bytes (~!SIZE_MB! MB)
    )
    echo.
    echo Next steps:
    echo   1. Test application: dist\Nethawk.exe
    echo   2. Build service: build_service.bat
    echo   3. Or build both: build_all.bat
    echo.
    echo ========================================
    echo Press any key to close this window...
    echo ========================================
    pause
    exit /b 0
) else (
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
    echo   2. Verify nethawk2_2.py syntax:
    echo      python -m py_compile nethawk2_2.py
    echo   3. Check if nethawk2_2.spec is valid:
    echo      python -c "exec(open('nethawk2_2.spec').read())"
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
)

