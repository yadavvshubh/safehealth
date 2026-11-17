@echo off
rem Pushes this folder to https://github.com/yadavvshubh/safehealth - double-click to run.
cd /d "%~dp0"
where git >/dev/null 2>nul
if errorlevel 1 (
  echo Git is not installed. Install it from https://git-scm.com/download/win then run this file again.
  pause
  exit /b 1
)
if not exist .git git init
git config user.name >/dev/null 2>/dev/null || git config user.name "yadavvshubh"
git config user.email >/dev/null 2>/dev/null || git config user.email "yadavvshubh@users.noreply.github.com"
git add .
git commit -m "SafeHealth prototype: secure clinic app, detection engine, backup and recovery"
git branch -M main
git remote remove origin 2>nul
git remote add origin https://github.com/yadavvshubh/safehealth.git
echo.
echo Pushing to GitHub. A sign-in window may open the first time.
git push -u origin main
echo.
if errorlevel 1 (echo Push FAILED - read the message above.) else (echo Done: https://github.com/yadavvshubh/safehealth)
pause
