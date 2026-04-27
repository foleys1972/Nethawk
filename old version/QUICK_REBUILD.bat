@echo off
echo ========================================
echo Quick Rebuild - NetHawk Service
echo ========================================
echo.
echo This will rebuild the service with pywin32 support.
echo.
echo Cleaning old build files...
if exist "dist\NetHawkService.exe" del /f "dist\NetHawkService.exe"
if exist "build" rmdir /s /q "build"
if exist "NetHawkService.spec" del /f "NetHawkService.spec"
echo.
echo Starting rebuild...
echo This will take a few minutes...
echo.
call build_service.bat
echo.
echo Rebuild complete!
echo.
pause

