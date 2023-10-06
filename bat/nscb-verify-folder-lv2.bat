@echo off
set squirrel=%~dp0../py/squirrel.py

for %%a in ("*.xci", "*.xcz", "*.nsp", "*.nsz") do (
    py "%squirrel%" -v "%%~dpnxa" -vt lv2 -o "%%~dpa." --saveverifylog 1
)

pause
