// content.js - shows an in-page warning banner inside opened Gmail messages.
// Network calls go through the background worker (avoids mixed-content/CORS issues).
const scannedEmails = new WeakSet();

function analyzeEmailElement(body, senderName, subjectText) {
  if (scannedEmails.has(body)) return;
  scannedEmails.add(body);

  const textContent = body.innerText || '';
  const links = Array.from(body.querySelectorAll('a')).map((a) => a.href).filter((h) => /^https?:/i.test(h));
  if (!textContent.trim() && links.length === 0) return;

  try {
    chrome.runtime.sendMessage({
      type: 'scanText',
      payload: { text: `Subject: ${subjectText}\n\n${textContent}`.slice(0, 6000), sender: senderName, urls: links.slice(0, 30) },
    }, (resp) => {
      if (chrome.runtime.lastError || !resp || !resp.ok) return;
      const r = resp.data;
      if (r && (r.is_phishing || r.score >= 60)) injectBanner(body, r);
    });
  } catch (e) { /* extension reloaded - ignore */ }
}

function injectBanner(container, result) {
  if (container.querySelector('.phishguard-warning-banner')) return;
  const banner = document.createElement('div');
  banner.className = 'phishguard-warning-banner';
  banner.style.cssText = 'background:#7f1d1d;border:2px solid #ef4444;color:#fef2f2;padding:12px 16px;margin-bottom:12px;border-radius:8px;font-size:13px;position:relative;z-index:999;';

  const title = document.createElement('div');
  title.style.cssText = 'font-weight:bold;font-size:14px;margin-bottom:4px;';
  title.textContent = `🚨 PHISHING THREAT DETECTED (${result.score}%)`;

  const msg = document.createElement('p');
  msg.style.cssText = 'margin:0 0 8px;color:#fca5a5;';
  msg.textContent = 'This email shows signs of phishing. Do not click links or share credentials.';

  const flags = document.createElement('div');
  flags.style.cssText = 'font-size:11px;background:rgba(0,0,0,.3);padding:6px;border-radius:4px;';
  flags.textContent = 'Flags: ' + ((result.flags && result.flags.length ? result.flags : result.details) || ['Suspicious patterns']).slice(0, 4).join(' • ');

  banner.append(title, msg, flags);
  container.prepend(banner);
}

function scanOpenEmails() {
  document.querySelectorAll('.a3s.aiL').forEach((body) => {
    if (scannedEmails.has(body)) return;
    const wrap = body.closest('.adn') || body.parentElement;
    const senderEl = (wrap && wrap.querySelector('.gD')) || document.querySelector('.gD');
    const subjectEl = document.querySelector('h2.hP');
    const sender = senderEl ? (senderEl.getAttribute('email') || senderEl.innerText) : 'Unknown Sender';
    const subject = subjectEl ? subjectEl.innerText : 'No Subject';
    analyzeEmailElement(body, sender, subject);
  });
}

let timer = null;
new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(scanOpenEmails, 600); })
  .observe(document.body, { childList: true, subtree: true });
