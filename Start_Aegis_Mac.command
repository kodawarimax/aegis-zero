#!/bin/bash
# Aegis-Zero Personal & SMB Edition — macOS 1-Click Launcher
# ダブルクリックするだけで Aegis-Zero ローカル管理画面がブラウザで開きます。

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "================================================================"
echo " 🛡️ Aegis-Zero 個人・中小企業向け セキュリティセンターを起動中..."
echo "================================================================"

if ! command -v python3 >/dev/null 2>&1; then
  osascript -e 'display alert "Python 3 が見つかりません" message "macOS のコマンドラインツールまたは Python 3 をインストールしてください。" as critical'
  exit 1
fi

python3 -m aegis.server
