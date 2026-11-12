@echo off
setlocal
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
py -3 -m repoguard %*
exit /b %ERRORLEVEL%
