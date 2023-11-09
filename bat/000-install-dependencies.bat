@echo off

set wd=%cd%
cd /d %~dp0../py

pip install -r "requirements.txt"

cd /d %wd%

pause
