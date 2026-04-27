@echo off
REM Build NetHawk Pro as Windows Executable
echo ========================================
echo Building NetHawk Pro Executable
echo ========================================
echo.

REM Change to the directory where this batch file is located
cd /d "%~dp0"
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
echo Checking for PyInstaller...
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

REM Check if spec file exists (with better error message)
if not exist "nethawk2_2.spec" (
    echo ERROR: nethawk2_2.spec not found in current directory!
    echo Current directory: %CD%
    echo.
    echo Please ensure you are running build_exe.bat from the project root directory.
    echo The spec file should be in the same directory as nethawk2_2.py
    echo.
    echo Attempting to generate spec file automatically...
    echo.
    python -m PyInstaller --name Nethawk --onefile --windowed --icon=nethawk.ico nethawk2_2.py --specpath . --clean
    if errorlevel 1 (
        echo.
        echo ERROR: Failed to generate spec file
        echo Please ensure nethawk2_2.py exists in the current directory
        pause
        exit /b 1
    )
    echo.
    echo Spec file generated successfully!
    echo.
) else (
    echo Spec file found: nethawk2_2.spec
)

REM Check if icon file exists
if not exist "nethawk.ico" (
    echo WARNING: nethawk.ico not found!
    echo The executable will be built without a custom icon
    echo.
) else (
    echo Icon file found: nethawk.ico
)

REM Check if version file exists
if not exist "version_info.txt" (
    echo WARNING: version_info.txt not found!
    echo The executable will be built without version information
    echo.
) else (
    echo Version file found: version_info.txt
)

REM Clean previous builds and PyInstaller cache
echo.
echo Cleaning previous builds...
if exist "build" rmdir /s /q build
if exist "dist" rmdir /s /q dist
REM Clear PyInstaller cache to avoid stale options
python -m PyInstaller --clean-cache >nul 2>&1

REM Build the executable
echo.
echo Building executable...
echo This may take several minutes...
echo.
REM Build the executable (icon is specified in the spec file)
python -m PyInstaller --clean nethawk2_2.spec

if errorlevel 1 (
    echo.
    echo ========================================
    echo Build failed!
    echo ========================================
    echo Check the error messages above for details
    pause
    exit /b 1
)

REM Check if executable was created
if not exist "dist\Nethawk.exe" (
    echo.
    echo ========================================
    echo Build completed but executable not found!
    echo ========================================
    echo Check dist\ folder for output
    pause
    exit /b 1
)

echo.
echo ========================================
echo Build Complete!
echo ========================================
echo Executable location: dist\Nethawk.exe
for %%A in ("dist\Nethawk.exe") do echo Size: %%~zA bytes
echo.
echo NOTE: If the icon doesn't appear immediately:
echo   1. Windows may cache icons - try refreshing Explorer (F5)
echo   2. Move the .exe to a different location
echo   3. Clear icon cache: ie4uinit.exe -show
echo   4. Restart Windows Explorer or reboot
echo.
echo You can now run: dist\Nethawk.exe
echo.
pause

