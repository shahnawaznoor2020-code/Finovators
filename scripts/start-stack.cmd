@echo off
setlocal
set REPO=C:\Users\Hemant\Desktop\Projects\GigBit
if not exist "%REPO%\scripts\start-stack.ps1" (
  for %%I in ("%~dp0..") do set REPO=%%~fI
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%REPO%\scripts\start-stack.ps1"
endlocal
