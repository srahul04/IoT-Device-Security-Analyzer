@echo off
:: launch.bat - IDSA portable launcher
:: Double-click this file to start the tool on any Windows machine.

setlocal

:: Resolve USB root (directory of this script)
set "USB=%~dp0"

:: Add bundled Node and Python to PATH if they exist on the USB
if exist "%USB%tools\node\node.exe" set "PATH=%USB%tools\node;%PATH%"
if exist "%USB%tools\python\python.exe" set "PATH=%USB%tools\python;%PATH%"

:: Load .env variables
if exist "%USB%.env" (
    for /f "usebackq tokens=1,2 delims==" %%A in ("%USB%.env") do (
        set "%%A=%%B"
    )
)

:: Verify Node is available
where node >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js not found. Install Node 18+ or place it in %USB%tools\node\
    pause
    exit /b 1
)

:: Verify Python is available
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ or place it in %USB%tools\python\
    pause
    exit /b 1
)

:: Install backend dependencies if node_modules is missing
if not exist "%USB%backend\node_modules" (
    echo Installing backend dependencies...
    pushd "%USB%backend"
    call npm install --silent
    popd
)

:: Start backend
pushd "%USB%backend"
start "IDSA Backend" /min cmd /c "node server.js"
popd

:: Wait for server to be ready
timeout /t 3 /nobreak >nul

:: Open browser
start "" "http://localhost:5000"

echo IDSA is running at http://localhost:5000
echo Close the IDSA Backend window to stop the server.

endlocal

