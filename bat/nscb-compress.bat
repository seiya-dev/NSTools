@echo off
set squirrel=%~dp0../py/ztools/squirrel.py

py "%squirrel%" -o "%~dp1." --nodelta "true" --compress "%~1" 22

pause
