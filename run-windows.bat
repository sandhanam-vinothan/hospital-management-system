@echo off
cd /d "%~dp0"
title MediCare HMS Server - DO NOT CLOSE
where node >nul 2>nul || (echo Install Node.js from https://nodejs.org & pause & exit /b)
start "" cmd /c "timeout /t 2 >nul & start http://localhost:3100"
node server.js
pause
