@echo off
chcp 65001 >nul
REM Aegis-Zero Personal & SMB Edition — Windows 1-Click Launcher
REM ダブルクリックするだけで Aegis-Zero ローカル管理画面がブラウザで開きます。

cd /d "%~dp0"
echo ================================================================
echo  [Aegis-Zero] 個人・中小企業向け セキュリティセンターを起動中...
echo ================================================================

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python -m aegis.server
    goto :eof
)

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    py -3 -m aegis.server
    goto :eof
)

echo [エラー] Python 3 がインストールされていません。Microsoft Store または python.org からインストールしてください。
pause
