@echo off
cd /d "%~dp0"
set "ATTACH_PC="
for %%A in (%*) do if /i "%%~A"=="--attach_pc" set "ATTACH_PC=1"
if defined ATTACH_PC if not exist "ak_exe_filepath.txt" (
    echo PC setup is incomplete: ak_exe_filepath.txt was not found.
    echo Run setup-pc-uv.cmd with the full path to Arknights.exe first.
    pause
    exit /b 1
)
uv run main %*
pause
