@echo off
chcp 65001 >nul
setlocal
set "ROOT_DIR=C:\Users\Dev Arora\Desktop\firewall"

set "choice=8"

echo.

:start_all

echo [1/5] Starting Advanced Backend (Port 3100)...
start "Advanced Backend" ^
/D "%ROOT_DIR%\backend" ^
cmd /k "python advanced_backend.py"

echo [2/5] Starting Fixed Backend (Port 5000)...
start "Fixed Backend" ^
/D "%ROOT_DIR%\backend" ^
cmd /k "python server_simple_no_emoji.py"

echo [3/5] Starting Local Engine API (Port 7000)...
start "Local Engine" ^
/D "%ROOT_DIR%\local_engine" ^
cmd /k "python api_server.py"

echo [4/5] Starting Extension Server (Port 6000)...
start "Extension Server" ^
/D "%ROOT_DIR%\extension_server" ^
cmd /k "python server.py"

echo [5/5] Starting Search Engine (Port 4000, local only)...
start "Search Engine" ^
/D "%ROOT_DIR%\search" ^
cmd /k "python search.py --host localhost"

echo.
echo Waiting for servers to start...
timeout /t 5 >nul
echo.
echo Available Services:
echo  - Advanced Backend: http://localhost:3100
echo  - Fixed Backend: http://localhost:5000
echo  - Search Engine: http://localhost:4000 (local only)
echo  - Admin Page: http://localhost:3800 (local only)
echo  - Local Engine: http://localhost:7000
echo  - Extension Server: http://localhost:6000
echo.
pause
exit
