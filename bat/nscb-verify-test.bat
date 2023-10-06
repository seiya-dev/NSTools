@echo off
set squirrel=%~dp0../py/verif_folder.py

py "%squirrel%" -i "%~1"

pause
