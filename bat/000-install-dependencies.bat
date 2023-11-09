@echo off

set wd=%cd%
cd /d %~dp0../nstools

pip install -r "requirements.txt"

cd /d %wd%

pause
