/**
 * Aegis-Zero Sovereign Browser Guard — Silent Background Service Worker (Manifest V3)
 * Runs quietly in the background without intrusive popups or page overlays.
 * Updates only the toolbar badge icon when risks or dark patterns are neutralized.
 */
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    aegisEnabled: true,
    silentBackgroundMode: true,
    chinaGateBlocked: true,
    pasteScrubberEnabled: true,
    trustedOwnerDomains: ["localhost", "127.0.0.1"]
  });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "AEGIS_SILENT_BADGE_UPDATE" && sender.tab?.id) {
    const count = Number(msg.issueCount || 0);
    const text = count > 0 ? String(count) : "";
    chrome.action.setBadgeText({ tabId: sender.tab.id, text });
    if (count > 0) {
      chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: "#0284c7" });
    }
    sendResponse({ ok: true, mode: "SILENT_BACKGROUND_BADGE_ONLY" });
  }
  return true;
});
