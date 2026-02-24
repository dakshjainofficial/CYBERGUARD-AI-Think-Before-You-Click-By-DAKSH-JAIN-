@echo off
echo Cleaning project for GitHub upload...

echo Deleting node_modules...
rmdir /s /q backend\node_modules 2>nul
rmdir /s /q node_modules 2>nul

echo Deleting auto-generated database files...
del /q database\*.json 2>nul

echo Deleting package-lock.json...
del /q backend\package-lock.json 2>nul

echo Deleting DS_Store and temporary files...
del /s /q .DS_Store 2>nul
del /s /q npm-debug.log* 2>nul

echo.
echo Project is now CLEAN and ready for GitHub/Zipping!
echo Run start.bat again to rebuild everything when needed.
pause
