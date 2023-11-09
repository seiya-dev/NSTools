@echo off
set app=%~dp0../nstools/ns_verify_folder.py

py "%app%" -i "%~1"

pause
