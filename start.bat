@echo off
echo Starting CYBERGUARD AI Setup...

echo Installing backend dependencies...
cd backend
call npm install

echo Starting Backend Server...
start cmd /k "npm start"

echo.
echo ===========================================
echo   🛡️ CYBERGUARD AI IS STARTING!
echo ===========================================
echo.
echo 1. Backend is starting in a new window (Port 5000)
echo 2. Opening the Frontend in your browser...
echo.

timeout /t 3
start ..\frontend\index.html

echo Done! Keep the backend window open while using the app.
pause
