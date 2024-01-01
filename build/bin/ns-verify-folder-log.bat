@echo off

set SCRIPTPATH=%~dp0
py "%SCRIPTPATH%ns_verify_folder.py" --save-log -i %1
