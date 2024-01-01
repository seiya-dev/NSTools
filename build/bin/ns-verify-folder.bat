@echo off

set SCRIPTPATH=%~dp0
py "%SCRIPTPATH%ns_verify_folder.py" -i %1
