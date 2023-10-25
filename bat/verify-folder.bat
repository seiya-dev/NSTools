@echo off
set app=%~dp0../py/ns_verify_folder.py

py "%app%" -i "%~1" --save-log

pause
