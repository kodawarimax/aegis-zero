function renderScanResult(res) {
  const box = document.getElementById("scan-status");
  if (!res) {
    box.innerHTML = "<div>このタブではコンテンツスクリプトを実行できません。</div>";
    return;
  }
  if (res.safe && (!res.actions || res.actions.length === 0)) {
    box.innerHTML = `<div style="color:#6ee7b7;font-weight:600;">✅ 問題は検出されませんでした（安全）</div>`;
    return;
  }
  let html = `<div style="font-weight:600;color:#fbbf24;margin-bottom:6px;">⚠️ 検出された項目: ${res.issueCount}件</div>`;
  for (const issue of res.issues || []) {
    html += `
      <div class="issue-item">
        <div style="font-weight:600;">[${issue.severity}] ${issue.title}</div>
        <div style="color:#94a3b8;font-size:11px;">${issue.detail}</div>
      </div>
    `;
  }
  if (res.actions && res.actions.length > 0) {
    html += `<div style="margin-top:8px;color:#6ee7b7;font-weight:600;">🛠️ 自動修復完了:</div>`;
    for (const act of res.actions) {
      html += `<div style="color:#a7f3d0;font-size:11px;">・${act}</div>`;
    }
  }
  box.innerHTML = html;
}

function sendToActiveTab(type) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]?.id) return;
    chrome.tabs.sendMessage(tabs[0].id, { type }, (res) => {
      renderScanResult(res);
    });
  });
}

document.getElementById("btn-rescan").addEventListener("click", () => sendToActiveTab("AEGIS_SCAN_PAGE"));
document.getElementById("btn-remediate").addEventListener("click", () => sendToActiveTab("AEGIS_REMEDIATE_PAGE"));
document.addEventListener("DOMContentLoaded", () => sendToActiveTab("AEGIS_SCAN_PAGE"));
