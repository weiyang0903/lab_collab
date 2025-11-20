@echo off
cd /d "%~dp0"
call myenv\Scripts\activate
python covid-19.py
pause
