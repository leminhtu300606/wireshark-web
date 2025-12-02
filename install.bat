@echo off
setlocal

echo === Installing PcapQt environment ===

set PROJECT_DIR=%~dp0

REM Kiểm tra .venv
if exist "%PROJECT_DIR%.venv" (
    echo [INFO] .venv found.
) else (
    echo [INFO] .venv not found. Creating...
    python -m venv "%PROJECT_DIR%.venv"
)

REM Activate venv
echo [INFO] Activating virtual environment...
call "%PROJECT_DIR%.venv\Scripts\activate.bat"

REM Install project
echo [INFO] Installing project locally...
pip install --upgrade pip >nul
pip install .

echo [INFO] Install completed.
endlocal
pause
