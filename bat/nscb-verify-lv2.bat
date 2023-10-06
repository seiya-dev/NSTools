@echo off
set squirrel=%~dp0../py/squirrel.py

py "%squirrel%" -v "%~1" -vt lv2 -o "%~dp1." --saveverifylog 1

pause
