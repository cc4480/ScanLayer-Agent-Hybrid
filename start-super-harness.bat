@echo off
REM Deepseek super - start script (Windows). Delegates to start-super-harness.ps1 so both
REM launchers set the same environment (API key, DATABASE_URL, tsx loader for the scan engines).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-super-harness.ps1" %*
