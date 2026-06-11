@echo off

set wd=%cd%
cd /d %~dp0../py

pip install --force-reinstall -r "requirements.txt"

cd /d %wd%

pause
