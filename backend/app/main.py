"""PhishGuard AI - local backend.

Combines a local LLM (Ollama) verdict with rule-based analysis of
message text, URLs, domains and email metadata (SPF/DKIM/DMARC, Reply-To,
display-name spoofing).  Works even when Ollama is offline (heuristics only).
"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from email.utils import parseaddr
from urllib.parse import urlparse
import ipaddress
import json
import re
import time
import urllib.request

OLLAMA_API_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"
LOCAL_MODEL_NAME = "llama3.2"
OLLAMA_TIMEOUT = 120          # first call may need to load the model
MAX_BODY_BYTES = 2_000_000
MAX_TEXT_CHARS = 6000

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq",
                   "work", "support", "loan", "country", "kim", "men", "icu", "cyou", "monster"}
SECOND_LEVEL = {"co.uk", "co.in", "com.au", "org.in", "gov.in", "ac.in", "net.in",
                "com.br", "co.jp", "co.za", "com.cn", "org.uk", "com.sg"}

BRANDS = {
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "youtube.com", "goog.le"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com",
                  "microsoftonline.com", "office365.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com", "amazon.de"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "facebookmail.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbicard.com", "sbi.bank.in"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
}

KEYWORD_GROUPS = [
    ("Urgency / pressure language", 12,
     ["urgent", "immediately", "within 24 hours", "act now", "final notice",
      "last warning", "expires today", "right away", "limited time"]),
    ("Requests credentials or sensitive data", 15,
     ["verify your", "confirm your", "update your password", "your password", "login details",
      "credentials", "otp", "one-time password", "cvv", "social security",
      "account number", "card number", "sign in to", "log in to"]),
    ("Threat of account suspension", 12,
     ["suspended", "locked", "terminated", "deactivated", "disabled", "unauthorized",
      "unusual activity", "suspicious login", "permanent"]),
    ("Prize / reward / refund bait", 15,
     ["you have won", "you've won", "winner", "lottery", "prize", "gift card",
      "claim your", "free iphone", "refund", "cashback"]),
    ("Money transfer / crypto request", 10,
     ["wire transfer", "bitcoin", "crypto", "western union", "bank transfer", "upi pin"]),
]

URL_RE = re.compile(r'(?:https?://|www\.)[^\s<>"\'\)\]]+', re.IGNORECASE)


# ----------------------------------------------------------------- helpers
def registered_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in SECOND_LEVEL and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_official(reg: str, brand: str) -> bool:
    return reg in BRANDS[brand]


def normalize_leet(s: str) -> str:
    return s.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"}))


def brand_in_host(host: str):
    tokens = set(re.split(r"[.\-_]", host))
    tokens |= set(re.split(r"[.\-_]", normalize_leet(host)))
    for brand in BRANDS:
        if brand in tokens:
            return brand
    return None


def clean_url(u: str) -> str:
    return u.rstrip(".,;:!?)]}>\"'")


def collect_urls(text: str, extra) -> list:
    found = [clean_url(u) for u in URL_RE.findall(text or "")]
    for u in (extra or []):
        if isinstance(u, str) and u.strip():
            found.append(clean_url(u.strip()))
    seen, out = set(), []
    for u in found:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:30]


def parse_host(url: str):
    try:
        p = urlparse(url if "://" in url else "http://" + url)
        return p, (p.hostname or "").lower()
    except ValueError:
        return None, ""


def analyze_url(url: str):
    """Return (points, [flags]) for a single URL."""
    p, host = parse_host(url)
    if not host:
        return 0, []
    pts, flags = 0, []
    reg = registered_domain(host)
    try:
        ipaddress.ip_address(host)
        pts += 30
        flags.append(f"Link points to a raw IP address ({host})")
    except ValueError:
        pass
    if host in SHORTENERS:
        pts += 15
        flags.append(f"URL shortener hides the real destination ({host})")
    if "@" in (p.netloc or ""):
        pts += 25
        flags.append("URL contains '@' (can disguise the real host)")
    if "xn--" in host:
        pts += 20
        flags.append(f"Punycode / lookalike characters in domain ({host})")
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        pts += 12
        flags.append(f"Suspicious top-level domain (.{tld}) in {host}")
    brand = brand_in_host(host)
    if brand and not is_official(reg, brand):
        pts += 35
        flags.append(f"Domain '{host}' imitates {brand.title()} but is not an official {brand.title()} domain")
    if len(host.split(".")) >= 5:
        pts += 10
        flags.append(f"Excessive subdomains in {host}")
    if host.count("-") >= 3:
        pts += 8
        flags.append(f"Many hyphens in domain {host}")
    if p.scheme == "http":
        pts += 8
        flags.append(f"Unencrypted (http) link to {host}")
    if len(url) > 150:
        pts += 5
        flags.append("Unusually long URL")
    return pts, flags


def analyze_text(text: str):
    low = (text or "").lower()
    pts, flags = 0, []
    for label, weight, words in KEYWORD_GROUPS:
        hits = [w for w in words if w in low]
        if hits:
            pts += weight
            flags.append(f"{label} ({', '.join(hits[:3])})")
    return pts, flags


def analyze_metadata(sender: str, reply_to: str, auth_results: str, urls: list):
    pts, flags = 0, []
    name, addr = parseaddr(sender or "")
    sender_domain = addr.split("@")[-1].lower() if "@" in addr else ""
    sender_reg = registered_domain(sender_domain) if sender_domain else ""

    if sender_domain:
        for brand in BRANDS:
            if brand in (name or "").lower() and not is_official(sender_reg, brand):
                pts += 30
                flags.append(f"Display name claims '{brand.title()}' but sender domain is {sender_domain}")
                break
        else:
            b = brand_in_host(sender_domain)
            if b and not is_official(sender_reg, b):
                pts += 30
                flags.append(f"Sender domain {sender_domain} imitates {b.title()}")
        tld = sender_domain.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            pts += 10
            flags.append(f"Sender uses suspicious TLD (.{tld})")

    _, rt_addr = parseaddr(reply_to or "")
    if "@" in rt_addr and sender_domain:
        rt_reg = registered_domain(rt_addr.split("@")[-1].lower())
        if rt_reg != sender_reg:
            pts += 15
            flags.append(f"Reply-To domain ({rt_reg}) differs from sender domain ({sender_reg})")

    ar = (auth_results or "").lower()
    failed = [k for k in ("spf", "dkim", "dmarc") if re.search(rf"{k}=(fail|softfail|none)", ar)]
    hard = [k for k in ("spf", "dkim", "dmarc") if re.search(rf"{k}=fail", ar)]
    if hard:
        pts += 25
        flags.append(f"Email authentication failed ({', '.join(x.upper() for x in hard)})")
    elif failed and ar:
        pts += 5
        flags.append(f"Weak email authentication ({', '.join(x.upper() for x in failed)})")
    return pts, flags


def heuristic_analysis(text, sender, urls, reply_to="", auth_results=""):
    t_pts, t_flags = analyze_text(text)
    per_url = []
    u_flags = []
    for u in urls:
        pts, fl = analyze_url(u)
        if fl:
            per_url.append(pts)
            u_flags.extend(fl)
    u_pts = 0
    if per_url:
        u_pts = min(70, max(per_url) + 5 * (len(per_url) - 1))
    m_pts, m_flags = analyze_metadata(sender, reply_to, auth_results, urls)
    score = min(100, t_pts + u_pts + m_pts)
    # de-duplicate flags, keep order
    flags = list(dict.fromkeys(m_flags + u_flags + t_flags))
    return score, flags


# --------------------------------------------------------------- local LLM
def to_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return str(v).strip().lower() in ("true", "yes", "1", "phishing")


def query_local_ai_model(text: str, sender: str, urls: list, signals: list):
    sig = "\n".join(f"- {s}" for s in signals) or "- none"
    link_list = "\n".join(urls[:15]) or "none"
    prompt = f"""You are an expert cybersecurity analyst. Decide whether the email below is phishing, a scam, or legitimate.
Legitimate newsletters, receipts and notifications from real companies are NOT phishing.

Sender: {sender}
Links found:
{link_list}

Automated signals already detected:
{sig}

Message:
{text[:MAX_TEXT_CHARS]}

Respond ONLY with valid JSON in exactly this shape:
{{"score": <integer 0-100 threat score>, "is_phishing": <true or false>, "reasoning": "<one short sentence>"}}"""
    payload = {
        "model": LOCAL_MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
    }
    try:
        req = urllib.request.Request(
            OLLAMA_API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        out = json.loads(body.get("response", "{}"))
        score = max(0, min(100, int(float(out.get("score")))))
        return {
            "score": score,
            "is_phishing": to_bool(out.get("is_phishing", score >= 50)),
            "reasoning": str(out.get("reasoning") or "Analyzed by local AI model.").strip(),
        }
    except Exception as e:
        print(f"[warn] Local AI unavailable ({e}). Using heuristics only.")
        return None


_ollama_cache = {"t": 0.0, "ok": False}


def ollama_online() -> bool:
    """Cached for 10 s so status checks never stall the UI."""
    now = time.time()
    if now - _ollama_cache["t"] < 10:
        return _ollama_cache["ok"]
    try:
        with urllib.request.urlopen(OLLAMA_TAGS_URL, timeout=1):
            ok = True
    except Exception:
        ok = False
    _ollama_cache.update(t=now, ok=ok)
    return ok


def analyze(data: dict) -> dict:
    text = (data.get("text") or data.get("url") or "")
    if not isinstance(text, str):
        text = str(text)
    sender = str(data.get("sender") or "")
    if not sender:
        m = re.search(r"^From:\s*(.+)$", text, re.MULTILINE)
        sender = m.group(1).strip() if m else "Unknown Sender"
    urls = collect_urls(text, data.get("urls"))
    reply_to = str(data.get("reply_to") or "")
    auth = str(data.get("auth_results") or "")

    h_score, flags = heuristic_analysis(text, sender, urls, reply_to, auth)
    ai = query_local_ai_model(text, sender, urls, flags)

    if ai:
        if h_score >= 60:
            score = max(ai["score"], h_score)
        else:
            score = round(0.7 * ai["score"] + 0.3 * h_score)
        is_phishing = score >= 50 or (ai["is_phishing"] and score >= 40)
        reasoning = ai["reasoning"]
    else:
        score = h_score
        is_phishing = score >= 50
        reasoning = ("Rule-based analysis (local AI offline): " +
                     ("multiple phishing indicators found." if is_phishing
                      else "no strong phishing indicators found."))

    return {
        "score": int(score),
        "is_phishing": bool(is_phishing),
        "details": [reasoning] + flags,
        "flags": flags,
        "urls": urls,
        "domains": sorted({registered_domain(parse_host(u)[1]) for u in urls if parse_host(u)[1]}),
        "ai_used": ai is not None,
    }


# ------------------------------------------------------------------ server
class PhishGuardHandler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (ConnectionError, BrokenPipeError):
            pass  # client (popup/page) closed before reply - harmless

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        self._json(200, {
            "status": "online",
            "service": "PhishGuard AI Local LLM Engine",
            "model": LOCAL_MODEL_NAME,
            "ollama_online": ollama_online(),
        })

    def do_POST(self):
        if self.path not in ("/api/scan/text", "/api/scan/gmail", "/api/scan/url"):
            return self._json(404, {"error": "Unknown endpoint"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY_BYTES:
                return self._json(413, {"error": "Payload too large"})
            data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            if not isinstance(data, dict):
                return self._json(400, {"error": "JSON object expected"})
            self._json(200, analyze(data))
        except json.JSONDecodeError:
            self._json(400, {"error": "Invalid JSON"})
        except Exception as e:  # never crash the handler thread
            print(f"[error] {e}")
            self._json(500, {"error": str(e)})


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        import sys
        if isinstance(sys.exc_info()[1], (ConnectionError, BrokenPipeError)):
            return  # aborted connections are normal for browsers
        super().handle_error(request, client_address)


def run_server(port=8000):
    httpd = QuietServer(("localhost", port), PhishGuardHandler)
    httpd.daemon_threads = True
    print(f"PhishGuard AI Backend running at http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    run_server()
