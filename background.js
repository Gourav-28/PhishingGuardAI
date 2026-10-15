// background.js - PhishGuard AI: automatic Gmail scanning + notifications
const API = "http://localhost:8000";
const GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me";
const ALARM = "pollInbox";
const POLL_MINUTES = 0.5;      // every 30 s (Chrome's minimum in MV3)
const MAX_PER_RUN = 10;
const MAX_STORED_IDS = 500;
const MAX_RECENT = 20;

let scanning = false;

// ------------------------------------------------------------ scheduling
function ensureAlarm() {
  chrome.alarms.get(ALARM, (a) => {
    if (!a) chrome.alarms.create(ALARM, { delayInMinutes: 0.1, periodInMinutes: POLL_MINUTES });
  });
}
ensureAlarm(); // runs every time the service worker wakes up

chrome.runtime.onInstalled.addListener(() => { ensureAlarm(); scanInbox(); });
chrome.runtime.onStartup.addListener(() => { ensureAlarm(); scanInbox(); });
chrome.alarms.onAlarm.addListener((alarm) => { if (alarm.name === ALARM) scanInbox(); });

// ------------------------------------------------------------------ auth
function getToken(interactive = false) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError || !token) {
        reject(new Error(chrome.runtime.lastError?.message || "Not signed in"));
      } else {
        resolve(typeof token === "string" ? token : token.token);
      }
    });
  });
}
function removeToken(token) {
  return new Promise((resolve) => chrome.identity.removeCachedAuthToken({ token }, resolve));
}

async function gmailGet(path) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const token = await getToken(false);
    const res = await fetch(`${GMAIL}/${path}`, { headers: { Authorization: `Bearer ${token}` } });
    if (res.status === 401 && attempt === 0) { await removeToken(token); continue; }
    if (!res.ok) throw new Error(`Gmail API error ${res.status}`);
    return res.json();
  }
  throw new Error("Gmail authentication failed");
}

// ----------------------------------------------------- email extraction
function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8").decode(bytes);
}

function walkParts(part, out) {
  if (!part) return;
  (part.parts || []).forEach((p) => walkParts(p, out));
  const data = part.body && part.body.data;
  if (!data) return;
  try {
    if (part.mimeType === "text/plain") out.plain.push(b64urlDecode(data));
    else if (part.mimeType === "text/html") out.html.push(b64urlDecode(data));
  } catch (e) { /* ignore undecodable part */ }
}

function htmlToText(html) {
  return html
    .replace(/<(style|script)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<br\s*\/?>|<\/p>|<\/div>|<\/tr>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n").trim();
}

function extractContent(payload) {
  const out = { plain: [], html: [] };
  walkParts(payload, out);
  const urls = new Set();
  out.html.forEach((h) => {
    for (const m of h.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
      if (/^https?:\/\//i.test(m[1])) urls.add(m[1]);
    }
  });
  const text = out.plain.length ? out.plain.join("\n") : out.html.map(htmlToText).join("\n");
  (text.match(/https?:\/\/[^\s<>"')\]]+/gi) || []).forEach((u) => urls.add(u));
  return { text, urls: [...urls].slice(0, 30) };
}

// --------------------------------------------------------------- scanning
async function callBackend(payload) {
  const res = await fetch(`${API}/api/scan/gmail`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(130000),
  });
  if (!res.ok) throw new Error(`Backend error ${res.status}`);
  return res.json();
}

function verdictOf(r) {
  if (r.is_phishing) return "phishing";
  if ((r.score || 0) >= 30) return "suspicious";
  return "safe";
}

function notify(id, sender, subject, r, verdict) {
  const titles = {
    phishing: `🚨 PHISHING detected (${r.score}%)`,
    suspicious: `⚠️ Suspicious email (${r.score}%)`,
    safe: `✅ Email looks safe (${r.score}%)`,
  };
  const reason = (r.details && r.details[0]) || "";
  chrome.notifications.create(`pg-${id}`, {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: titles[verdict],
    message: `From: ${sender}\nSubject: ${subject}\n${reason}`.slice(0, 400),
    priority: verdict === "phishing" ? 2 : 0,
    requireInteraction: verdict === "phishing",
  });
}

chrome.notifications.onClicked.addListener((nid) => {
  if (nid.startsWith("pg-")) {
    chrome.tabs.create({ url: `https://mail.google.com/mail/u/0/#inbox/${nid.slice(3)}` });
  }
  chrome.notifications.clear(nid);
});

async function processMessage(id, state) {
  const msg = await gmailGet(`messages/${id}?format=full`);
  const headers = (msg.payload && msg.payload.headers) || [];
  const h = (n) => (headers.find((x) => x.name.toLowerCase() === n) || {}).value || "";
  const subject = h("subject") || "(No subject)";
  const sender = h("from") || "Unknown sender";
  const { text, urls } = extractContent(msg.payload);
  const body = text.trim() || msg.snippet || "";

  const result = await callBackend({
    text: `Subject: ${subject}\n\n${body}`.slice(0, 6000),
    sender,
    urls,
    reply_to: h("reply-to"),
    auth_results: h("authentication-results"),
  });

  const verdict = verdictOf(result);
  if (verdict !== "safe" || (state.notifySafe && state.initialized)) {
    notify(id, sender, subject, result, verdict);
  }
  return { id, sender, subject, score: result.score, verdict, time: Date.now() };
}

async function scanInbox() {
  if (scanning) return;
  scanning = true;
  try {
    const state = await chrome.storage.local.get({
      processedIds: [], initialized: false, notifySafe: true,
      backendDown: false, recentScans: [],
    });

    let list;
    try {
      list = await gmailGet(`messages?q=${encodeURIComponent("in:inbox newer_than:1d")}&maxResults=${MAX_PER_RUN}`);
    } catch (e) {
      const why = String(e.message || e);
      await chrome.storage.local.set({
        lastError: why, lastScan: Date.now(),
        lastStatus: /Gmail API error 403/.test(why)
          ? "Gmail API is not enabled for your Google Cloud project (or this account is not a test user)."
          : /Gmail API error/.test(why) ? why : "Not signed in to Google - click Connect Google Inbox.",
      });
      return;
    }

    const processed = new Set(state.processedIds);
    const fresh = (list.messages || []).filter((m) => !processed.has(m.id)).reverse(); // oldest first
    const recent = state.recentScans;
    let lastErr = "";
    let scannedCount = 0;

    for (const m of fresh) {
      try {
        const entry = await processMessage(m.id, state);
        processed.add(m.id);
        scannedCount++;
        recent.unshift(entry);
        await chrome.storage.local.set({
          processedIds: [...processed].slice(-MAX_STORED_IDS),
          recentScans: recent.slice(0, MAX_RECENT),
          backendDown: false,
        });
        state.backendDown = false;
      } catch (e) {
        const offline = /Failed to fetch|NetworkError|Backend error|TimeoutError|aborted/i.test(String(e));
        console.warn("PhishGuard: could not scan message", m.id, e);
        lastErr = String(e.message || e);
        if (offline) {
          if (!state.backendDown) {
            chrome.notifications.create("pg-backend-down", {
              type: "basic",
              iconUrl: "icons/icon128.png",
              title: "PhishGuard AI: backend offline",
              message: "Start it with: python main.py  (emails will be scanned once it is running)",
              priority: 1,
            });
            await chrome.storage.local.set({ backendDown: true });
          }
          break; // retry on the next poll
        }
      }
    }
    await chrome.storage.local.set({
      initialized: true, lastScan: Date.now(), lastError: lastErr,
      lastStatus: lastErr
        ? `Error while scanning: ${lastErr}`
        : `OK - ${scannedCount} new email(s) scanned, ${(list.messages || []).length} in last 24h.`,
    });
  } finally {
    scanning = false;
  }
}

// ------------------------------------------------- messages from UI pages
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "scanNow") {
    scanInbox().then(() => sendResponse({ ok: true })).catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg && msg.type === "scanText") {
    fetch(`${API}/api/scan/text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(msg.payload),
      signal: AbortSignal.timeout(130000),
    })
      .then((r) => r.json())
      .then((data) => sendResponse({ ok: true, data }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
});
