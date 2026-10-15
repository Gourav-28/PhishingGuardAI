document.addEventListener('DOMContentLoaded', () => {
  const API = 'http://localhost:8000';

  const backendStatusEl = document.getElementById('backend-status');
  const signInBtn = document.getElementById('signin-btn');
  const senderInput = document.getElementById('sender-input');
  const textInput = document.getElementById('text-input');
  const scanBtn = document.getElementById('scan-btn');
  const sampleBtn = document.getElementById('sample-btn');
  const errBox = document.getElementById('err-box');
  const resultsContainer = document.getElementById('results-container');

  // 1. Check local Python server health
  async function checkBackend() {
    try {
      const res = await fetch(`${API}/`);
      if (res.ok) {
        backendStatusEl.textContent = '🟢 Online (Ollama Local LLM)';
        backendStatusEl.style.color = '#34d399';
      } else {
        throw new Error();
      }
    } catch {
      backendStatusEl.textContent = '🔴 Backend Offline';
      backendStatusEl.style.color = '#f87171';
    }
  }

  checkBackend();

  // 2. Google OAuth Trigger
  if (signInBtn) {
    signInBtn.addEventListener('click', () => {
      signInBtn.textContent = 'Connecting...';
      signInBtn.disabled = true;

      try {
        chrome.identity.getAuthToken({ interactive: true }, (token) => {
          if (chrome.runtime.lastError || !token) {
            console.error('Auth error:', chrome.runtime.lastError?.message);
            signInBtn.textContent = 'Connection Failed';
            signInBtn.style.background = '#ef4444';
            signInBtn.disabled = false;
            return;
          }

          // Successfully authenticated!
          signInBtn.textContent = '🟢 Inbox Connected';
          signInBtn.style.background = '#10b981';
          signInBtn.disabled = true;
          console.log('Successfully acquired OAuth token for Gmail API scanning.');
        });
      } catch (err) {
        console.error('Identity API error:', err);
        signInBtn.textContent = 'Connection Failed';
        signInBtn.style.background = '#ef4444';
        signInBtn.disabled = false;
      }
    });
  }

  // 3. Load Sample Phishing Email
  if (sampleBtn) {
    sampleBtn.addEventListener('click', () => {
      senderInput.value = 'security@account-apple-support.net';
      textInput.value = 'URGENT: Your Apple ID has been locked due to suspicious login attempts from Russia. Verify your credentials immediately within 24 hours at http://apple-id-verify-secure.com or face permanent account termination.';
    });
  }

  // 4. Trigger Scan Execution
  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      const text = textInput.value.trim();
      const sender = senderInput.value.trim();

      if (!text) return;

      scanBtn.disabled = true;
      scanBtn.textContent = 'Running Local AI Analysis...';
      errBox.style.display = 'none';

      try {
        const res = await fetch(`${API}/api/scan/text`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text, sender })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Scan failed');

        renderResults(data);
      } catch (e) {
        errBox.style.display = 'block';
        errBox.textContent = e.message || 'Failed to connect to local Python backend. Is python main.py running?';
      } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = 'Scan via Local LLM';
      }
    });
  }

  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // Render Telemetry Score & Reasoning
  function renderResults(data) {
    const isPhish = data.is_phishing;
    const score = data.score || 0;
    const color = isPhish ? '#ef4444' : score >= 30 ? '#f59e0b' : '#10b981';
    const label = isPhish ? 'Critical Risk' : score >= 30 ? 'Medium Risk' : 'Low Risk';

    const r = 40;
    const circ = 2 * Math.PI * r;
    const offset = circ * (1 - score / 100);

    let urlsHtml = '';
    if (data.urls && data.urls.length > 0) {
      const list = data.urls.map(u => `<div style="font-size:11px; color:#fbbf24; font-family:monospace; word-break:break-all;">🔗 ${esc(u)}</div>`).join('');
      urlsHtml = `
        <div style="padding: 12px; background: #0f172a; border: 1px solid #334155; border-radius: 12px; margin-top: 12px;">
          <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase; font-weight: 700; margin-bottom: 6px;">Extracted URLs</div>
          ${list}
        </div>
      `;
    }

    resultsContainer.innerHTML = `
      <div class="res-card ${isPhish ? 'res-phish' : 'res-safe'}" style="padding: 16px; border-radius: 16px; border: 1px solid #334155; display: flex; align-items: center; gap: 16px; background: ${isPhish ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)'};">
        <div class="meter-container" style="position: relative; width: 100px; height: 100px; flex-shrink: 0;">
          <svg style="transform: rotate(-90deg); width: 100px; height: 100px;" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="${r}" stroke="#1e293b" stroke-width="8" fill="none" />
            <circle cx="50" cy="50" r="${r}" stroke="${color}" stroke-width="8" fill="none"
              stroke-dasharray="${circ}" stroke-dashoffset="${offset}" stroke-linecap="round" style="transition: stroke-dashoffset 0.6s ease;" />
          </svg>
          <div style="position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center;">
            <span style="font-size: 20px; font-weight: 900; color: ${color};">${score}%</span>
            <span style="font-size: 8px; text-transform: uppercase; color: #94a3b8; font-weight: 700;">${label}</span>
          </div>
        </div>

        <div style="flex: 1;">
          <div style="font-weight: 700; font-size: 15px; color: ${color}; display: flex; align-items: center; gap: 6px;">
            ${isPhish ? '🚨 Phishing Threat Detected' : '✅ Message Appears Safe'}
          </div>
          <p style="margin: 6px 0 0 0; font-size: 12px; color: #cbd5e1; line-height: 1.4;">
            ${esc(data.details && data.details[0] ? data.details[0] : 'Analyzed by local AI inference engine.')}${data.flags && data.flags.length ? '<br><br>' + data.flags.map((f) => '• ' + esc(f)).join('<br>') : ''}
          </p>
        </div>
      </div>
      ${urlsHtml}
    `;
  }
});