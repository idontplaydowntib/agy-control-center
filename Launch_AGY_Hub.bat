@echo off
title AGY Control Center Launcher
cd /d "%~dp0"
start "" wscript.exe "%~dp0Launch_AGY_Hub.vbs"
exit /b 0
