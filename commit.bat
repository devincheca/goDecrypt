@ECHO OFF
git add *
SET /P mssg=Enter your commit message: 
git commit -m "%mssg%"
git push
git status

