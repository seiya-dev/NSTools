@echo off
set squirrel=%~dp0../py/verify_folder.py

py "%squirrel%" -i "%~1"

pause
