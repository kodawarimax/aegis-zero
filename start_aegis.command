#!/bin/zsh
# ダブルクリック1回で Aegis-Zero ローカル要塞ダッシュボードを起動するランチャー
cd "$(dirname "$0")" || exit 1
echo "🛡️ Aegis-Zero Control Center を起動しています..."
python3 -m aegis.server
