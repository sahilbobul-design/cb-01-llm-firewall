@echo off
REM =======================================================
REM Deploy SENTINEL AI Frontend to Vercel
REM =======================================================
echo =======================================================
echo  DEPLOYING SENTINEL AI FRONTEND TO VERCEL
echo =======================================================
echo.

cd "%~dp0sentinel-frontend"

echo [*] Step 1: Building production bundle (Vite + TypeScript)...
call npm run build
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed. Please check the error above.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [*] Step 2: Deploying to Vercel...
echo [*] If this is your first time, Vercel will open your browser to log in (GitHub/Email).
echo.
call npx vercel --prod

echo.
echo =======================================================
echo  DEPLOYMENT COMPLETE!
echo =======================================================
pause
