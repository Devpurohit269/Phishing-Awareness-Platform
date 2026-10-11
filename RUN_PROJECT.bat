@echo off
setlocal
cd /d "%~dp0"

echo ==============================================
echo     PhishGuard - Project Startup
 echo ==============================================

if not exist ".venv\Scripts\python.exe" (
    echo Creating Python virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo.
        echo ERROR: Python was not found or could not create the virtual environment.
        echo Install Python 3.10+ and make sure Python is added to PATH.
        pause
        exit /b 1
    )
)

echo Installing/checking required packages...
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo ERROR: Package installation failed.
    pause
    exit /b 1
)

echo.
echo Starting PhishGuard...
echo Open: http://127.0.0.1:5000
 echo Login: admin / admin123
 echo.
.venv\Scripts\python.exe app.py
pause
