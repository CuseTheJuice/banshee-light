@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-banshee-usb.ps1" -Watch %*
pause
