@echo off
set squirrel=%~dp0../py/squirrel.py

py "%squirrel%" -o "%~dp1." --decompress "%~1"

pause
