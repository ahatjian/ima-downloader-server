@echo off
chcp 65001 >nul
echo ============================================
echo  IMA 下载助手 Pro - 推送到 GitHub
echo ============================================
echo.

cd /d "%~dp0"

REM 检查 git 是否可用
where git >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 未找到 git，请先安装 Git for Windows
    echo 下载地址: https://git-scm.com/download/win
    pause
    exit /b 1
)

echo [1/4] 初始化 git 仓库...
if exist .git (
    rmdir /s /q .git
)
git init
git config user.name "ahatjian"
git config user.email "2051645018@qq.com"

echo [2/4] 拉取远程仓库...
git remote add origin https://github.com/ahatjian/ima-downloader-server.git
git fetch origin main
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 无法连接到 GitHub，请检查网络
    echo 可以尝试：
    echo   1. 开启科学上网
    echo   2. 或稍后重试
    pause
    exit /b 1
)

echo [3/4] 合并远程代码...
git checkout -b main origin/main

REM 用本地文件覆盖远程文件
xcopy /y /q "%~dp0app.py" .\
xcopy /y /q "%~dp0requirements.txt" .\
xcopy /y /q "%~dp0Procfile" .\
xcopy /y /q "%~dp0render.yaml" .\
xcopy /y /q "%~dp0runtime.txt" .\
xcopy /y /q "%~dp0.env.example" .\
if exist "static\admin.html" (
    xcopy /y /q "%~dp0static\admin.html" "static\"
) else (
    mkdir static 2>nul
    xcopy /y /q "%~dp0static\admin.html" "static\"
)

git add -A
git commit -m "v2.1: 日落橙配色 + 安全加固 + 短信支持 + 管理后台增强"

echo [4/4] 推送到 GitHub...
echo.
echo 即将推送到 https://github.com/ahatjian/ima-downloader-server
echo 可能需要输入 GitHub 用户名和密码（或个人访问令牌）
echo.
git push origin main --force

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo  推送成功！现在可以去 LeapCell 部署了
    echo ============================================
) else (
    echo.
    echo [提示] 如果推送失败，可能是认证问题
    echo 请尝试以下方法之一：
    echo   1. 使用 GitHub 个人访问令牌：
    echo      git remote set-url origin https://TOKEN@github.com/ahatjian/ima-downloader-server.git
    echo      git push origin main --force
    echo   2. 使用 SSH：
    echo      git remote set-url origin git@github.com:ahatjian/ima-downloader-server.git
    echo      git push origin main --force
)

pause
