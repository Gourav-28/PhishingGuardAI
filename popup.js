document.addEventListener('DOMContentLoaded', async () => {
  const API = 'http://localhost:8000';
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function setStatus(el, ok, text) {
    el.innerHTML = `<span class="dot ${ok === null ? 'dot-gray' : ok ? 'dot-green' : 'dot-red'}"></span>${esc(text)}`;
  }

  async function checkBackend() {
    try {
      const res = await fetch(`${API}/`);
      if (!res.ok) throw new Error();
      const d = await res.json();
      setStatus($('popup-backend-status'), true, d.ollama_online ? 'Online + AI model' : 'Online (rules only)');
    } catch {
      setStatus($('popup-backend-status'), false, 'Offline - run python main.py');
    }
  }

  function checkAuth() {
    chrome.identity.getAuthToken({ interactive: false }, (token) => {
      const ok = !chrome.runtime.lastError && !!token;
      setStatus($('popup-gmail-status'), ok, ok ? 'Connected' : 'Not connected');
      const btn = $('popup-signin');
      btn.textContent = ok ? '🟢 Connected' : '🔐 Connect Google Inbox';
      btn.disabled = ok;
    });
  }

  async function renderRecent() {
    const s = await chrome.storage.local.get({ recentScans: [], lastScan: 0, notifySafe: true, lastStatus: '' });
    $('notify-safe').checked = s.notifySafe;
    $('popup-last-scan').textContent = s.lastScan ? new Date(s.lastScan).toLocaleTimeString() : '—';
    $('popup-status-line').textContent = s.lastStatus || 'No scan has run yet.';
    const list = $('recent-list');
    if (!s.recentScans.length) { list.innerHTML = '<span class="label">Nothing scanned yet.</span>'; return; }
    list.innerHTML = s.recentScans.map((r) => `
      <div class="item">
        <div><span class="v-${esc(r.verdict)}">${r.verdict === 'phishing' ? '🚨 Phishing' : r.verdict === 'suspicious' ? '⚠️ Suspicious' : '✅ Safe'}</span> · ${esc(r.score)}%</div>
        <div class="meta">${esc(r.subject)}</div>
        <div class="meta">${esc(r.sender)}</div>
      </div>`).join('');
  }

  $('popup-signin').addEventListener('click', () => {
    const btn = $('popup-signin');
    btn.textContent = 'Connecting...';
    btn.disabled = true;
    chrome.identity.getAuthToken({ interactive: true }, (token) => {
      if (chrome.runtime.lastError || !token) {
        btn.textContent = 'Connection failed - retry';
        btn.disabled = false;
        return;
      }
      checkAuth();
      chrome.runtime.sendMessage({ type: 'scanNow' }, () => { void chrome.runtime.lastError; renderRecent(); });
    });
  });

  $('scan-now-btn').addEventListener('click', () => {
    const btn = $('scan-now-btn');
    btn.disabled = true; btn.textContent = 'Scanning...';
    chrome.runtime.sendMessage({ type: 'scanNow' }, () => {
      void chrome.runtime.lastError;
      btn.disabled = false; btn.textContent = 'Scan inbox now';
      renderRecent();
    });
  });

  $('notify-safe').addEventListener('change', (e) => chrome.storage.local.set({ notifySafe: e.target.checked }));

  $('quick-scan-btn').addEventListener('click', async () => {
    const text = $('quick-text-input').value.trim();
    if (!text) return;
    const btn = $('quick-scan-btn'), box = $('quick-result-box');
    btn.disabled = true; btn.textContent = 'Scanning...';
    box.style.display = 'block'; box.textContent = 'Analyzing...';
    try {
      const res = await fetch(`${API}/api/scan/text`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || 'Scan failed');
      const cls = d.is_phishing ? 'v-phishing' : d.score >= 30 ? 'v-suspicious' : 'v-safe';
      const label = d.is_phishing ? '🚨 Phishing' : d.score >= 30 ? '⚠️ Suspicious' : '✅ Looks safe';
      box.innerHTML = `<span class="${cls}">${label} (${esc(d.score)}%)</span><br>${esc((d.details || [])[0] || '')}`;
    } catch (e) {
      box.textContent = 'Could not reach backend. Is python main.py running?';
    } finally {
      btn.disabled = false; btn.textContent = 'Scan Message';
    }
  });

  $('open-dashboard').addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('app.html') }));

  checkBackend(); checkAuth(); renderRecent();
  chrome.storage.onChanged.addListener(renderRecent);
});
