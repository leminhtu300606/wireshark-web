@echo off
setlocal

set PROJECT_DIR=%~dp0

REM Kiểm tra .venv
if not exist "%PROJECT_DIR%.venv" (
    echo [ERROR] .venv not found. Run install.bat first.
    pause
    exit /b
)

REM Activate venv
echo [INFO] Activating environment...
call "%PROJECT_DIR%.venv\Scripts\activate.bat"

REM Run app
echo [INFO] Running python -m pcapqt ...
python -m pcapqt

endlocal
pause
