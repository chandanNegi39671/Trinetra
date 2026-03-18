"""
whatsapp_bot.py — Trinetra WhatsApp Bot (Twilio)
================================================
Users send a URL/SMS text to your WhatsApp number → instant scam analysis reply.

SETUP (Free in 5 min):
  1. Sign up at https://www.twilio.com/try-twilio  (free trial, no credit card)
  2. Twilio Console → Messaging → Try it out → Send a WhatsApp Message
  3. Follow sandbox join instructions (send "join <word>" to +1 415 523 8886)
  4. Set Webhook URL in sandbox settings:
       https://your-render-url.onrender.com/whatsapp
  5. Set env vars:
       TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxx
       TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxx
       TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
  6. Run:  python whatsapp_bot.py  (or add routes to app.py)

USAGE:
  User sends:   http://sbi-kyc.xyz
  Bot replies:  ☠️ DANGER (92/100) — Phishing detected!
                🔴 Google Safe Browsing: THREAT
                🕐 Domain: 3 days old
                🌍 Hosted in: Russia (hosting datacenter)
                ↩️ 4 redirects found
                ⚠️ Flags: IP_IN_URL, SCAM_KEYWORD, SUSPICIOUS_TLD

  User sends:   Dear SBI customer your KYC expired click http://...
  Bot replies:  📱 SCAM SMS DETECTED (Score: 97/100)
                Signal hits: urgent, kyc, verify, click, sbi
                🔗 URL found: http://... → DANGER 88%
"""

import os, re, logging, requests
from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
TRINETRA_API = os.environ.get("TRINETRA_API_URL", "http://localhost:5000")
TWILIO_FROM   = os.environ.get("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")

# URL regex
URL_RE = re.compile(
    r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+'
    r'|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
    re.IGNORECASE
)

# ── Flask App ─────────────────────────────────────────────────────────────────
bot_app = Flask(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────
def call_analyze(url: str) -> dict:
    try:
        r = requests.post(
            f"{TRINETRA_API}/analyze",
            json={"url": url}, timeout=20
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error(f"analyze error: {e}")
        return None


def call_analyze_sms(text: str) -> dict:
    try:
        r = requests.post(
            f"{TRINETRA_API}/analyze-sms",
            json={"text": text}, timeout=20
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error(f"sms analyze error: {e}")
        return None


def score_emoji(score: float) -> str:
    if score >= 70: return "☠️"
    if score >= 40: return "⚠️"
    return "✅"


def format_url_reply(data: dict, url: str) -> str:
    if not data:
        return f"❌ Could not analyze {url}. Try again."

    score  = data.get("final_score", 0)
    label  = data.get("final_label", "UNKNOWN")
    d      = data.get("details", {})
    emoji  = score_emoji(score)

    # Header
    lines = [
        f"{emoji} *TRINETRA SCAN RESULT*",
        f"🔗 `{url[:60]}{'...' if len(url)>60 else ''}`",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"*Score: {score}/100 — {label}*",
        "",
    ]

    # Key signals
    gsb     = d.get("safe_browsing", {})
    age     = d.get("domain_age", {})
    geo     = d.get("geo", {})
    redir   = d.get("redirects", {})
    ssl     = d.get("ssl", {})
    flags   = d.get("url_flags", [])
    look    = d.get("lookalike", {})
    short   = d.get("shortener", {})

    if gsb.get("is_malicious"):
        lines.append(f"🚨 Google Safe Browsing: *THREAT* ({gsb.get('threat_type','MALICIOUS')})")
    elif gsb.get("checked"):
        lines.append(f"✅ Google Safe Browsing: Clear")
    else:
        lines.append(f"⚠️ Safe Browsing: Not checked")

    if age.get("age_days") is not None:
        age_days = age["age_days"]
        warn = "🕐 ⚠️" if age_days < 30 else "🕐"
        lines.append(f"{warn} Domain age: *{age_days} days* {'(very new!)' if age_days<30 else ''}")

    if geo.get("country"):
        hosting = " — 🏭 Hosting/Datacenter" if geo.get("is_hosting") else ""
        lines.append(f"🌍 Hosted in: *{geo['country']}*{hosting}")

    if redir.get("hop_count", 0) >= 3:
        lines.append(f"↩️ Redirects: *{redir['hop_count']} hops* (suspicious!)")

    if ssl.get("ssl_risk_score", 0) > 50:
        lines.append(f"🔓 SSL issue detected")
    elif ssl.get("has_ssl"):
        lines.append(f"🔒 SSL: Valid")

    if look.get("is_lookalike"):
        lines.append(f"🎭 Impersonates: *{look.get('matched_brand', 'known brand')}*")

    if short.get("is_shortener"):
        lines.append(f"🔗 URL shortener hiding true destination!")

    if flags:
        lines.append(f"⚠️ Flags: `{', '.join(flags[:5])}`")

    lines += ["", "━━━━━━━━━━━━━━━━━━━━"]

    # Verdict
    if score >= 70:
        lines.append("🚫 *DO NOT OPEN THIS LINK*")
        lines.append("Report to cybercrime.gov.in")
    elif score >= 40:
        lines.append("⚠️ *Proceed with extreme caution*")
    else:
        lines.append("✅ *Appears safe* — stay alert")

    lines.append("\n_Powered by Trinetra AI_")
    return "\n".join(lines)


def format_sms_reply(data: dict, text: str) -> str:
    if not data:
        return "❌ Could not analyze message. Try again."

    score  = data.get("final_score", 0)
    label  = data.get("final_label", "UNKNOWN")
    sms    = data.get("sms_analysis", {})
    urls   = data.get("urls_found", [])
    emoji  = score_emoji(score)
    cats   = sms.get("categories", {})

    lines = [
        f"{emoji} *SMS/WHATSAPP SCAN*",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"*Score: {score}/100 — {label}*",
        f"Signal hits: *{sms.get('total_hits', 0)}*",
        "",
    ]

    if cats:
        for cat, hits in cats.items():
            kws = ', '.join(hits[:4]) if isinstance(hits, list) else str(hits)
            lines.append(f"• {cat.title()}: `{kws}`")
        lines.append("")

    if urls:
        lines.append("🔗 *URLs found:*")
        for u in urls[:3]:
            e = score_emoji(u["score"])
            lines.append(f"{e} `{u['url'][:50]}` → *{u['score']}%*")
        lines.append("")

    lines.append("━━━━━━━━━━━━━━━━━━━━")
    if score >= 70:
        lines.append("🚫 *SCAM MESSAGE — Do NOT respond or click any links*")
        lines.append("Report: cybercrime.gov.in | 1930")
    elif score >= 40:
        lines.append("⚠️ *Suspicious message — verify before taking any action*")
    else:
        lines.append("✅ *Message appears safe*")

    lines.append("\n_Powered by Trinetra AI_")
    return "\n".join(lines)


# ── Webhook ───────────────────────────────────────────────────────────────────
@bot_app.route("/whatsapp", methods=["POST"])
def whatsapp_webhook():
    incoming = request.values.get("Body", "").strip()
    sender   = request.values.get("From", "")

    logger.info(f"WhatsApp from {sender}: {incoming[:80]}")

    resp = MessagingResponse()
    msg  = resp.message()

    # Empty message
    if not incoming:
        msg.body("👋 Hi! Send me any suspicious URL or WhatsApp message and I'll analyze it instantly.\n\nExample:\n• http://sbi-kyc.xyz\n• Dear customer your KYC expired click http://...\n\n_Trinetra — AI Scam Detector_")
        return str(resp)

    # Help command
    if incoming.lower() in ("hi","hello","help","/start","start"):
        msg.body(
            "👁️ *TRINETRA — AI Scam Detector*\n\n"
            "I can detect scam links and messages instantly.\n\n"
            "*Send me:*\n"
            "🔗 Any suspicious URL\n"
            "📱 Any suspicious SMS/WhatsApp message\n\n"
            "*I will tell you:*\n"
            "• Threat score (0-100)\n"
            "• Why it's dangerous\n"
            "• Google Safe Browsing result\n"
            "• Domain age, SSL, geo location\n\n"
            "Stay safe 🛡️"
        )
        return str(resp)

    # Detect if it's a URL or SMS text
    has_url = bool(URL_RE.search(incoming))
    is_pure_url = incoming.startswith(("http://","https://")) and len(incoming.split()) == 1

    if is_pure_url:
        # Pure URL analysis
        data  = call_analyze(incoming)
        reply = format_url_reply(data, incoming)
    elif has_url or len(incoming) > 40:
        # SMS/message with possible URLs
        data  = call_analyze_sms(incoming)
        reply = format_sms_reply(data, incoming)
    else:
        # Short text — treat as SMS
        data  = call_analyze_sms(incoming)
        reply = format_sms_reply(data, incoming)

    msg.body(reply)
    return str(resp)


@bot_app.route("/whatsapp/status", methods=["POST"])
def whatsapp_status():
    """Twilio delivery status callback — just acknowledge"""
    return "", 204


# ── Run standalone (dev) ──────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("BOT_PORT", 5001))
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"\n📱 Trinetra WhatsApp Bot — http://localhost:{port}")
    print(f"   Webhook: POST /whatsapp")
    print(f"   API:     {TRINETRA_API}\n")
    bot_app.run(debug=debug_mode, host="0.0.0.0", port=port)
