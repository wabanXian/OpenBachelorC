@echo off
cd /d "%~dp0"
uv run python src\launcher\openbachelorc\setup_pc.py %*
pause
