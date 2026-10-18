/**
 * Aegis-Zero Sovereign Browser Guard — Content Script (Manifest V3)
 * Protects users and AI Browser Agents in real time against:
 * 1. Pre-checked optional marketing consent dark patterns ("（任意）" checked by default -> Auto-OFF)
 * 2. DOM-embedded AI Agent / Autofill manipulation directives ("既存本人氏名「...」と承認済みメールアドレスを入力し...")
 * 3. Staging / PII placeholder exposure ("制作確認用・非公開", hardcoded emails/names in inputs)
 * 4. Hidden CSS / ROT13 / Caesar / Multi-turn split prompt injections
 * 5. Accidental paste of passwords, JWTs, API keys, and high-entropy secrets into AI chat boxes
 */

const AegisBrowserEngine = (() => {
  const sessionTurns = [];
  const MAX_TURNS = 6;

  const OVERRIDE_RE = /(?<!\bdo\s+not\s)(?<!\bdon't\s)(?<!\bnever\s)\b(?:ignore|disregard|forget|set\s+aside|bypass|override|skip|abandon|supersede)\b[\s\S]{0,60}?\b(?:all\s+|any\s+|your\s+|the\s+)?(?:(?:prior|earlier|previous|above|system|safety|security|initial|original|core)\s+(?:directives?|guidelines?|rules?|instructions?|constraints?|guardrails?|policies|prompts?)|guardrails?|(?:directives?|rules?|instructions?|constraints?)\s+(?:given|above|previously|earlier))\b/i;
  const EXFIL_RE = /\b(?:reveal|disclose|expose|output|print|display|share|hand\s+over|dump|extract|recite|list|send|give|tell|show)\b(?![\s\S]{0,25}?\bhow\s+to\b)(?![\s\S]{0,40}?\b(?:so\s+I\s+can\s+(?:delete|revoke|rotate)|in\s+AWS\s+IAM)\b)[\s\S]{0,60}?\b(?:(?:all|every|internal|system|hidden|stored|enclave|master|admin|root|raw|secret|private|confidential|your)\s+)+(?:credentials?|secrets?|passwords?|passphrases?|tokens?|api\s*keys?|private\s*keys?|seed\s*phrases?|auth|vault\s+configuration)\b/i;
  const JP_INJ_RE = /(?:これまで|以前|上記|既存|システム)の(?:指示|ルール|方針|制約|命令)[\s\S]*?(?:無視|脇に置|忘れ|破棄|解除)|(?:認証情報|秘密鍵|パスワード|シークレット|APIキー|トークン|隠しキー)を(?:開示|表示|出力|教え|送信)/;
  const PERSONA_RE = /(?:\b(?:act\s+as|pretend\s+to\s+be|roleplay\s+as|deceased\s+grandmother|bedtime\s+story|fictional\s+(?:debugging|scenario|mode)|hypothetical\s+(?:scenario|training|debugging)|safety\s+filters?\s+(?:do\s+not\s+exist|disabled|off))\b[\s\S]{0,160}\b(?:secret|vault|configuration|credentials?|keys?|passwords?|internal|system|restricted|variables?)\b)|(?:(?:祖母の遺言|寝物語|架空の(?:デバッグ|訓練|シナリオ)|仮定の話として|安全フィルタが(?:存在しない|ない)|制限(?:解除|なし)モード|デバッグモードとして振る舞)[\s\S]{0,120}(?:設定|隠しキー|秘密|内部変数|認証|パスワード|初期設定|システム))/i;
  const PIVOT_RE = /(?:---\s*END\s+OF\s+(?:DOCUMENT|EMAIL|TEXT|CONTEXT|INVOICE)\s*---|<\/(?:context|document|email|data|untrusted_data[^>]*?)>|\[\s*NEW\s+SYSTEM\s+(?:DIRECTIVE|INSTRUCTION|PROMPT|COMMAND)\s*\]|【(?:文書|メール|引用|請求書)終了】|ここからは(?:システム|管理者)(?:命令|指示))/i;
  const SPLIT_RE = /(?:\b(?:combine|concatenate|join|assemble)\b[\s\S]{0,80}['"][a-zA-Z]{1,6}['"]\s*\+\s*['"][a-zA-Z]{1,6}['"])|(?:(?:分割された|前後の)(?:文字|文字列|トークン)を(?:繋げて|結合して)(?:命令|実行))/i;
  const STATE_PLANT_RE = /(?:\b(?:remember|memorize|store|hold|buffer)\s+(?:the\s+)?(?:syllables?|letters?|fragments?|prefix|suffix|part|word|string)\s+['"][a-zA-Z0-9_-]{1,16}['"]\s+(?:for\s+the\s+next|until\s+the\s+next|and\s+wait))|(?:(?:次|後)の(?:メッセージ|ターン|指示)のために[「『"'][^「』"']{1,16}[」』"'](?:という)?(?:文字|音節|断片)を(?:記憶|保持|保存))/i;

  function shannonEntropy(token) {
    if (!token) return 0;
    const counts = {};
    for (const ch of token) counts[ch] = (counts[ch] || 0) + 1;
    const len = token.length;
    let ent = 0;
    for (const k in counts) {
      const p = counts[k] / len;
      ent -= p * Math.log2(p);
    }
    return ent;
  }

  function isHighEntropySecret(token) {
    if (!token || /^(?:REDACTED_|AEGIS_|JP-|ORD-|INV-|DOC-)/.test(token)) return false;
    const hasUpper = /[A-Z]/.test(token);
    const hasLower = /[a-z]/.test(token);
    const hasDigit = /[0-9]/.test(token);
    const hasSym = /[#!$%@&*^~+=]/.test(token);
    const digitCount = (token.match(/[0-9]/g) || []).length;
    const classes = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSym ? 1 : 0);
    const ent = shannonEntropy(token);
    if (hasSym && classes >= 3 && hasDigit) {
      return ent >= 3.65;
    }
    if (hasUpper && hasLower && digitCount >= 3 && token.length >= 16) {
      return ent >= 4.05;
    }
    return false;
  }

  function scrubPayloadForLLM(raw) {
    let s = String(raw || "");
    s = s.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED_JWT_TOKEN]");
    s = s.replace(/\b(?:sk-[a-zA-Z0-9_-]{12,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[a-zA-Z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b/g, "[REDACTED_API_TOKEN]");
    s = s.replace(/\b0x[a-fA-F0-9]{40,64}\b/g, "[REDACTED_HEX_KEY]");
    s = s.replace(/\b(?:\d{4}[-\s]){3}\d{4}\b/g, "[REDACTED_PAYMENT_CARD]");
    s = s.replace(/\b0[1-9]\d{0,3}-\d{2,4}-\d{4}\b/g, "[REDACTED_JP_PHONE]");
    s = s.replace(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g, "[REDACTED_EMAIL]");
    s = s.replace(/((?:パスワード|暗証番号|合言葉|合い言葉|秘密鍵|シークレット|復号キー|隠しキー)\s*(?:(?:は|が)\s*[「『"']|(?:：|:|=)\s*[「『"']?))([^\s「』"'。、，,？?]{3,64})([」』"']?)/g, "$1[REDACTED_CONTEXTUAL_SECRET]$3");
    s = s.replace(/((?:パスワード|暗証番号|合言葉|合い言葉|秘密鍵|シークレット|復号キー|隠しキー)\s*(?:は|が)\s*)([A-Za-z0-9#!$%@&*^~+\-=_]{6,64})/g, "$1[REDACTED_CONTEXTUAL_SECRET]");
    s = s.replace(/(\b(?:password|passwd|pwd|secret|api_key|db_password|access_key|private_key|passphrase)\s*(?:=|:|\bis\s+(?!expired\b|invalid\b|wrong\b|required\b|forgotten\b|reset\b|changed\b|weak\b|strong\b|missing\b|empty\b|correct\b|valid\b|safe\b|secure\b))\s*["']?)([^\s"',;.!?]{6,64})(["']?)/gi, "$1[REDACTED_CONTEXTUAL_SECRET]$3");
    s = s.replace(/\b([A-Za-z0-9#!$%@&*^~+\-=_]{14,64})\b/g, (m) => isHighEntropySecret(m) ? "[REDACTED_HIGH_ENTROPY_SECRET]" : m);
    return s;
  }

  function caesarShift(str, shift) {
    let out = "";
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      if (c >= 65 && c <= 90) out += String.fromCharCode(((c - 65 + shift) % 26) + 65);
      else if (c >= 97 && c <= 122) out += String.fromCharCode(((c - 97 + shift) % 26) + 97);
      else out += str[i];
    }
    return out;
  }

  function baseSemanticCheck(text) {
    if (OVERRIDE_RE.test(text) && EXFIL_RE.test(text)) return [true, "SEMANTIC_PARAPHRASED_OVERRIDE_AND_CREDENTIAL_EXFIL"];
    if (OVERRIDE_RE.test(text)) return [true, "SEMANTIC_PARAPHRASED_DIRECTIVE_OVERRIDE"];
    if (EXFIL_RE.test(text)) return [true, "SEMANTIC_PARAPHRASED_CREDENTIAL_HARVEST"];
    if (JP_INJ_RE.test(text)) return [true, "SEMANTIC_JP_INJECTION_INTENT"];
    if (PERSONA_RE.test(text)) return [true, "SEMANTIC_PERSONA_METAPHOR_INJECTION"];
    if (PIVOT_RE.test(text)) return [true, "SEMANTIC_BOUNDARY_PIVOT_INDIRECT_INJECTION"];
    if (SPLIT_RE.test(text)) return [true, "SEMANTIC_SPLIT_TOKEN_EVASION"];
    if (STATE_PLANT_RE.test(text)) return [true, "SEMANTIC_CROSS_TURN_STATE_PLANTING"];
    return [false, ""];
  }

  function inspectTextWithCiphersAndMultiTurn(text) {
    const [directFlag, directReason] = baseSemanticCheck(text);
    if (directFlag) return { safe: false, reason: directReason };

    // Caesar / ROT13 check
    const shifts = [13, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25];
    for (const s of shifts) {
      const shifted = caesarShift(text.slice(0, 800), s);
      const [cFlag, cReason] = baseSemanticCheck(shifted);
      if (cFlag) {
        return { safe: false, reason: `${s === 13 ? "ROT13_CIPHER_DECODED" : "CAESAR_SHIFT_" + s}: ${cReason}` };
      }
    }

    // Multi-turn sliding window check (only buffer individually clean turns to prevent Sticky Lockout)
    sessionTurns.push(text.slice(0, 400));
    if (sessionTurns.length > MAX_TURNS) sessionTurns.shift();
    if (sessionTurns.length >= 2) {
      const combined = sessionTurns.join(" ");
      const quotes = Array.from(combined.matchAll(/['"「『]([^'"」』]{1,24})['"」』]/g)).map(m => m[1]).join("");
      const [mFlag, mReason] = baseSemanticCheck(combined + " " + quotes);
      if (mFlag) {
        sessionTurns.length = 0; // Flush window so subsequent benign turns are not locked out
        return { safe: false, reason: `CROSS_TURN_STATEFUL_ASSEMBLY: ${mReason}` };
      }
    }
    return { safe: true, reason: "OK" };
  }

  return {
    scrubPayloadForLLM,
    inspectTextWithCiphersAndMultiTurn
  };
})();

// Track explicit user clicks on checkboxes so Aegis-Zero never overrides a user's manual opt-in
document.addEventListener("click", (e) => {
  const cb = e.target?.closest?.('input[type="checkbox"]');
  if (cb && e.isTrusted) {
    cb.dataset.aegisUserTouched = "true";
  }
}, true);

function showAegisUndoToast(message, onUndo) {
  let toast = document.getElementById("aegis-zero-undo-toast");
  if (toast) toast.remove();
  toast = document.createElement("div");
  toast.id = "aegis-zero-undo-toast";
  toast.style.cssText = "position:fixed;bottom:20px;right:20px;z-index:2147483647;background:#0f172a;color:#f8fafc;border:1px solid #10b981;border-radius:8px;padding:10px 14px;font:12px/1.4 -apple-system,BlinkMacSystemFont,sans-serif;box-shadow:0 10px 25px rgba(0,0,0,0.4);display:flex;align-items:center;gap:12px;";
  const span = document.createElement("span");
  span.textContent = `🛡️ ${message}`;
  const btn = document.createElement("button");
  btn.textContent = "元に戻す (Undo)";
  btn.style.cssText = "background:#1e293b;color:#38bdf8;border:1px solid #38bdf8;border-radius:5px;padding:4px 8px;font-size:11px;cursor:pointer;font-weight:600;";
  btn.onclick = () => {
    onUndo();
    toast.remove();
  };
  toast.appendChild(span);
  toast.appendChild(btn);
  document.body.appendChild(toast);
  setTimeout(() => {
    if (toast.parentNode) toast.remove();
  }, 6500);
}

function scanCurrentPageDOM(autoRemediate = false) {
  const issues = [];
  const actions = [];
  const visibleText = (document.body ? document.body.innerText : "").slice(0, 8000);

  // 1. Check for DOM-embedded AI Agent / Autofill manipulation directives
  if (/(?:既存本人氏名|承認済みメールアドレス|本人承認済みの登録確認用)[\s\S]*?(?:入力し|チェックを外すと|送信)|(?:AIエージェント|ブラウザ操作AI)への?(?:指示|命令)/.test(visibleText)) {
    issues.push({
      id: "DOM-AGENT-DIRECTIVE-01",
      severity: "HIGH",
      title: "ページ内に特定の個人名・メール入力や操作手順を誘導する指示ブロックを検出",
      detail: "AIブラウザ自動操作の暴走や本人情報の誤送信を防ぐため、フォームの自動送信ロックを推奨します。"
    });
    if (autoRemediate) {
      document.querySelectorAll("form").forEach(form => {
        form.dataset.aegisAgentLocked = "true";
      });
      actions.push("AI自動送信ロックを適用しました");
    }
  }

  // 2. Check for Pre-checked Optional Consent Dark Patterns (`（任意）` checked by default, unless user explicitly clicked it)
  const optionalRe = /(?:任意|optional|希望する|メルマガ|案内.*通|ニュースレター)/i;
  const checkboxes = Array.from(document.querySelectorAll('input[type="checkbox"]'));
  checkboxes.forEach((cb, idx) => {
    if (cb.dataset.aegisUserTouched === "true") return;
    const parentText = (cb.closest("label")?.innerText || cb.parentElement?.innerText || "").trim();
    if (cb.checked && optionalRe.test(parentText)) {
      issues.push({
        id: `DOM-DARKPATTERN-CB-${idx + 1}`,
        severity: "MEDIUM",
        title: `任意同意チェックボックスの初期ON（ダークパターン）: 「${parentText.slice(0, 42)}」`,
        detail: "『任意』の案内同意が最初からONになっています。"
      });
      if (autoRemediate) {
        cb.checked = false;
        cb.dispatchEvent(new Event("change", { bubbles: true }));
        actions.push(`任意チェック「${parentText.slice(0, 28)}」を自動でOFF（同意解除）にしました`);
      }
    }
  });

  // 3. Check for Staging / Exposed PII in placeholders or inputs (ignore benign dummy example placeholders)
  if (/(?:制作確認用・非公開|テスト環境|staging\s+only)/i.test(visibleText)) {
    issues.push({
      id: "DOM-STAGING-EXPOSURE-01",
      severity: "HIGH",
      title: "『制作確認用・非公開』表示およびテスト用個人情報の残留を検出",
      detail: "非公開・確認用ページの表示や実メールアドレス・氏名がページ上に残っています。"
    });
  }

  const benignExamplePhRe = /^(?:例\s*[:：）)]|e\.g\.,?\s*|sample\s*:)|@(?:example\.(?:com|co\.jp|org|net)|sample\.(?:com|co\.jp)|test\.example\.com)\b|\b(?:03-1234-5678|090-0000-0000|090-1234-5678|000-0000-0000)\b/i;
  const inputs = Array.from(document.querySelectorAll('input:not([type="checkbox"]):not([type="radio"]):not([type="submit"]):not([type="button"]), textarea'));
  inputs.forEach((inp, idx) => {
    const ph = (inp.getAttribute("placeholder") || "").trim();
    const val = (inp.value || "").trim();
    if (!val && ph && benignExamplePhRe.test(ph)) return;
    const rawVal = `${ph} ${val}`.trim();
    if (!rawVal) return;
    const scrubbed = AegisBrowserEngine.scrubPayloadForLLM(rawVal);
    if (scrubbed.includes("[REDACTED_")) {
      issues.push({
        id: `DOM-INPUT-PII-${idx + 1}`,
        severity: "HIGH",
        title: `入力欄に個人情報またはシークレットの露出を検出 (${scrubbed})`,
        detail: "プレースホルダーまたは初期値に実メールアドレス等のPIIが含まれています。"
      });
      if (autoRemediate && ph) {
        inp.setAttribute("placeholder", scrubbed);
        actions.push(`入力欄プレースホルダーのPIIをマスクしました (${scrubbed})`);
      }
    }
  });

  // 4. Hidden CSS Prompt Injection scan
  const allElements = Array.from(document.querySelectorAll("div, span, p, section, pre, code")).slice(0, 600);
  allElements.forEach((el, idx) => {
    const style = window.getComputedStyle(el);
    const isHidden = style.display === "none" || style.visibility === "hidden" || parseFloat(style.opacity) === 0 || parseFloat(style.fontSize) === 0;
    if (isHidden && el.innerText && el.innerText.trim().length > 10) {
      const check = AegisBrowserEngine.inspectTextWithCiphersAndMultiTurn(el.innerText.trim());
      if (!check.safe) {
        issues.push({
          id: `DOM-HIDDEN-INJ-${idx + 1}`,
          severity: "CRITICAL",
          title: "不可視DOM要素に埋め込まれた隠しAI攻撃命令を検出",
          detail: check.reason
        });
        if (autoRemediate) {
          el.textContent = "[NEUTRALIZED_BY_AEGIS_BROWSER_GUARD]";
          actions.push("不可視プロンプトインジェクション要素を無害化しました");
        }
      }
    }
  });

  return {
    url: window.location.href,
    title: document.title,
    safe: issues.length === 0,
    humanOperationAllowed: true,
    deliveryMode: "SILENT_BACKGROUND_BADGE_ONLY",
    issueCount: issues.length,
    issues,
    actions
  };
}

// Human Gesture Supremacy: Block ONLY untrusted automated AI agent submits (!e.isTrusted).
// Physical human user clicks/submits (e.isTrusted === true) are ALWAYS allowed without friction.
document.addEventListener("submit", (e) => {
  const form = e.target;
  if (form && form.dataset?.aegisAgentLocked === "true" && !e.isTrusted) {
    e.preventDefault();
    e.stopImmediatePropagation();
  }
}, true);

// Intercept paste on AI chat domains to prevent accidental secret/PII leakage (with 1-click Undo Toast)
document.addEventListener("paste", (e) => {
  if (window.__aegisOwnerBypassPaste) return;
  const host = window.location.hostname.toLowerCase();
  if (host === "localhost" || host === "127.0.0.1" || host.endsWith(".local")) return;
  const isAIChat = ["chatgpt.com", "claude.ai", "gemini.google.com", "chat.deepseek.com", "perplexity.ai"].some(d => host.endsWith(d));
  if (!isAIChat) return;
  const text = (e.clipboardData || window.clipboardData)?.getData("text");
  if (!text) return;
  const scrubbed = AegisBrowserEngine.scrubPayloadForLLM(text);
  if (scrubbed !== text) {
    e.preventDefault();
    const target = e.target;
    if (target && (target.tagName === "TEXTAREA" || target.tagName === "INPUT")) {
      const prevValue = target.value;
      const start = target.selectionStart || 0;
      const end = target.selectionEnd || 0;
      target.value = prevValue.slice(0, start) + scrubbed + prevValue.slice(end);
      target.dispatchEvent(new Event("input", { bubbles: true }));
      showAegisUndoToast("貼り付けテキスト内の機密情報・個人情報を自動マスクしました", () => {
        window.__aegisOwnerBypassPaste = true;
        target.value = prevValue.slice(0, start) + text + prevValue.slice(end);
        target.dispatchEvent(new Event("input", { bubbles: true }));
      });
    } else if (target && target.isContentEditable) {
      document.execCommand("insertText", false, scrubbed);
    }
  }
}, true);

// Passive Idle Background Scan: runs quietly when browser is idle, updating ONLY the toolbar badge (0 popups)
function runSilentBackgroundPass() {
  try {
    const res = scanCurrentPageDOM(true);
    if (typeof chrome !== "undefined" && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({ type: "AEGIS_SILENT_BADGE_UPDATE", issueCount: res.issueCount });
    }
  } catch (_) {}
}

if (typeof window.requestIdleCallback === "function") {
  window.requestIdleCallback(() => runSilentBackgroundPass(), { timeout: 2000 });
} else {
  setTimeout(runSilentBackgroundPass, 900);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "AEGIS_SCAN_PAGE") {
    sendResponse(scanCurrentPageDOM(false));
  } else if (msg.type === "AEGIS_REMEDIATE_PAGE") {
    sendResponse(scanCurrentPageDOM(true));
  }
  return true;
});
