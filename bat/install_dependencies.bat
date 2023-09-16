@echo off

set wd=%cd%
cd /d %~dp0../py

pip install --upgrade pip
pip install wheel

pip install -r "requirements.txt"
pip install --upgrade google-api-python-client

cd /d %wd%

pause
