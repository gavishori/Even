@echo off
rem Starts go2rtc so the camera page can play the NVR streams. Keep this window open.
cd /d "%~dp0go2rtc"
go2rtc.exe -c go2rtc.yaml
pause
