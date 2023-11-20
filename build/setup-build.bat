@echo off

set wdir=%cd%
cd /d %~dp0..

xcopy "py" "build" /I /E /Q /Y
xcopy "LICENSE.md" "build/LICENSE.md*" /Q /Y
xcopy "README.md" "build/README.md*" /Q /Y
python -m build build

cd /d %wdir%
pause
