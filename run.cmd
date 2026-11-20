@echo off
rem Launch Cypher AI Port Scanner.
rem Usage (from the project folder): .\run      (PowerShell)
rem                                  run        (Command Prompt)
rem Prefers the project's .venv, then the Windows "py" launcher, then python.
setlocal
set "ROOT=%~dp0"
set "SCRIPT=%ROOT%ai_port_scanner.py"

if exist "%ROOT%.venv\Scripts\python.exe" (
    "%ROOT%.venv\Scripts\python.exe" "%SCRIPT%" %*
    exit /b
)

where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%SCRIPT%" %*
    exit /b
)

where python >nul 2>nul
if not errorlevel 1 (
    python "%SCRIPT%" %*
    exit /b
)

echo Python 3.10+ was not found. Install it or create a .venv - see the README.
exit /b 1
