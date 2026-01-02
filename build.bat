@echo off
title Build DREParser EXE
cd /d "%~dp0"

echo =====================================
echo        Building DREParser Executable
echo =====================================
echo.

echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH!
    echo.
    echo Please install Python from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo Installing required dependencies...
pip install pyinstaller pywebview pywin32 psutil requests termcolor rich

if errorlevel 1 (
    echo ERROR: Failed to install dependencies!
    echo You may need to run as administrator or use: pip install --user
    pause
    exit /b 1
)

echo Installing additional cryptography dependencies...
pip install cryptography pyasn1 pyasn1-modules winsign

if errorlevel 1 (
    echo WARNING: Some optional dependencies failed to install!
    echo The application may have limited functionality.
    echo Continuing with build...
)

echo Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist __pycache__ rmdir /s /q __pycache__
if exist *.spec del *.spec

echo.
echo =====================================
echo     Building DREParser Executable...
echo =====================================

echo Checking for icon file...
if not exist "dre.ico" (
    echo WARNING: dre.ico not found!
    echo Building without custom icon...
    set ICON_CMD=
) else (
    echo Found dre.ico - applying custom icon...
    set ICON_CMD=--icon "dre.ico"
)

echo Checking for web directory...
if not exist "web" (
    echo ERROR: web directory not found!
    echo Please create a 'web' folder with UI.html and style.css
    pause
    exit /b 1
)

if not exist "web\UI.html" (
    echo ERROR: web\UI.html not found!
    echo Please make sure UI.html is in the web directory
    pause
    exit /b 1
)

if not exist "web\style.css" (
    echo ERROR: web\style.css not found!
    echo Please make sure style.css is in the web directory
    pause
    exit /b 1
)

echo Building DREParser executable with PyInstaller...
python -m PyInstaller --onefile --windowed --name "DREParser" %ICON_CMD% ^
--add-data "web;web" ^
--hidden-import="webview" ^
--hidden-import="webview.platforms.win32" ^
--hidden-import="webview.platforms.wince" ^
--hidden-import="json" ^
--hidden-import="threading" ^
--hidden-import="datetime" ^
--hidden-import="pathlib" ^
--hidden-import="re" ^
--hidden-import="csv" ^
--hidden-import="ctypes" ^
--hidden-import="ctypes.wintypes" ^
--hidden-import="string" ^
--hidden-import="win32api" ^
--hidden-import="win32file" ^
--hidden-import="win32con" ^
--hidden-import="pywintypes" ^
--hidden-import="win32timezone" ^
--hidden-import="psutil" ^
--hidden-import="psutil._psutil_windows" ^
--hidden-import="psutil._psutil_common" ^
--hidden-import="requests" ^
--hidden-import="urllib3" ^
--hidden-import="chardet" ^
--hidden-import="idna" ^
--hidden-import="certifi" ^
--hidden-import="cryptography" ^
--hidden-import="cryptography.hazmat" ^
--hidden-import="cryptography.hazmat.primitives" ^
--hidden-import="pyasn1" ^
--hidden-import="pyasn1_modules" ^
--hidden-import="termcolor" ^
--hidden-import="rich" ^
--hidden-import="rich.console" ^
--hidden-import="winsign" ^
--hidden-import="winsign.pefile" ^
--hidden-import="winsign.asn1" ^
--hidden-import="itertools" ^
--hidden-import="collections" ^
--hidden-import="struct" ^
--hidden-import="tempfile" ^
--hidden-import="subprocess" ^
--hidden-import="os" ^
--hidden-import="sys" ^
--hidden-import="time" ^
--hidden-import="platform" ^
--hidden-import="webbrowser" ^
--hidden-import="itertools" ^
--hidden-import="glob" ^
--hidden-import="timeit" ^
--collect-all="webview" ^
--collect-all="pywin32" ^
--collect-all="psutil" ^
--collect-all="requests" ^
--collect-all="cryptography" ^
--collect-all="termcolor" ^
--collect-all="rich" ^
DREParser.py

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    echo Please check the error messages above.
    pause
    exit /b 1
)

if exist dist\DREParser.exe (
    echo.
    echo =====================================
    echo      BUILD SUCCESSFUL!
    echo =====================================
    echo.
    echo Executable created: dist\DREParser.exe
    echo File size: 
    for %%F in (dist\DREParser.exe) do echo   %%~zF bytes
    echo.
    echo DREParser Forensic Features:
    echo - USN Journal dumping and parsing
    echo - Explorer process memory analysis
    echo - Recycle Bin forensic scanning
    echo - File extension correlation (executable/suspicious files)
    echo - Renamed/Replaced/Deleted file tracking
    echo - Beautiful glass-morphism UI with virtual scrolling
    echo - Real-time progress monitoring
    echo - Export functionality
    echo.
    echo IMPORTANT: Run as Administrator for full functionality!
    echo The application requires admin rights for USN Journal access.
    echo.
    echo The executable is completely standalone!
    echo No Python or dependencies required to run.
    echo.
    echo You can now distribute dist\DREParser.exe
    echo.
    echo Note: First run may be slower due to signature verification.
    echo.
    echo Build process completed successfully!
    pause
) else (
    echo ERROR: Build completed but executable not found!
    pause
    exit /b 1
)