@echo off
set "SCRIPT_DIR=%~dp0"
start "" /b "%SystemRoot%\System32\wscript.exe" "%SCRIPT_DIR%start_login_guard_hidden.vbs"
exit /b 0
