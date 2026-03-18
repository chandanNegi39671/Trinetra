# 👁️ TRINETRA — AI Scam Intelligence Engine

> **Real-time phishing, malware & fraud detection powered by XGBoost ML + 18 threat signals + Google Safe Browsing**


---

## 🚀 What is Trinetra?

Trinetra is a full-stack AI-powered scam detection system that analyzes suspicious URLs, SMS messages, and WhatsApp screenshots in real-time. It combines machine learning, rule-based heuristics, and Google Safe Browsing to give a threat score from 0–100.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🤖 **XGBoost ML Model** | Trained on UCI Phishing Dataset, 35 features, 95%+ accuracy |
| 🛡️ **Google Safe Browsing** | Real-time malware & phishing check via Google API |
| 📱 **SMS Analysis** | India-specific scam keyword detection (SBI, KYC, OTP, TRAI...) |
| 🖼️ **OCR Image Scan** | WhatsApp screenshot → extract text → analyze URLs |
| ↩️ **Redirect Chain** | Follows redirect hops, flags chains of 3+ |
| 🌍 **Geo + IP Check** | Country, ISP, datacenter/hosting detection |
| 🔒 **SSL Analysis** | Certificate validity, issuer, days left |
| 🎭 **Lookalike Detection** | Catches brand impersonation (sbi-login.xyz etc.) |
| 📊 **Entropy Analysis** | Detects randomized/obfuscated URLs |
| 🚫 **Blacklist Check** | Cross-references threat intelligence lists |
| 💬 **WhatsApp Bot** | Send any URL to WhatsApp → instant reply |
| 🔐 **Security Middleware** | Headers, SSRF protection, input sanitization |
| 📜 **Scan History** | Last 50 scans stored in memory |

---

## 📁 Project Structure

```
📁 Backened/           ← Backend (run this)
├── app.py                  ← Main Flask API server
├── train_model.py          ← Run once to generate ML model
├── whatsapp_bot.py         ← WhatsApp bot (Twilio)
├── security_middleware.py  ← Security layer (import in app.py)
├── scam_model.pkl          ← Trained ML model (auto-generated)
├── feature_columns.pkl     ← ML feature list (auto-generated)
├── requirements.txt        ← Python dependencies
├── render.yaml             ← Render.com deployment config
├── .env                    ← Your API keys (never commit this!)
└── .env.example            ← Template for .env

📁 TRINETRA_frontend/           ← Frontend (open in browser)
└── index.html              ← 3D dashboard (only file needed)
```

---

## ⚡ Quick Start

## 🌐 Deployment (Vercel + Render)

To avoid Vercel Lambda package-size errors, deploy only the frontend on Vercel and only the backend on Render.

### Frontend on Vercel

1. Import this repository in Vercel.
2. Keep `vercel.json` at repo root (already configured).
3. Keep `.vercelignore` at repo root (already configured) so backend files are excluded.
4. Deploy.

### Backend on Render

1. Create Render services from `Backened/render.yaml`.
2. Set backend environment variables in Render dashboard:
  - `GOOGLE_SAFE_BROWSING_KEY`
  - `TWILIO_ACCOUNT_SID` (optional)
  - `TWILIO_AUTH_TOKEN` (optional)
3. Update `ALLOWED_ORIGINS` in Render to your real Vercel URL.

This split prevents Vercel from packaging Python/ML dependencies and resolves the 500 MB Lambda ephemeral storage limit issue.

### 1. Clone & Setup

```bash
cd Backened
python -m venv .venv
.venv\Scripts\Activate.ps1        # Windows PowerShell
pip install -r requirements.txt
```

### 2. Set Environment Variables

```bash
# Copy example file
copy .env.env

# Edit .env and add your keys:
GOOGLE_SAFE_BROWSING_KEY=AIzaSy...
TWILIO_ACCOUNT_SID=ACxxxxxxxx         # optional, for WhatsApp bot
TWILIO_AUTH_TOKEN=xxxxxxxx            # optional, for WhatsApp bot
```

### 3. Add Security Middleware to app.py

Add these lines at the top of `app.py`:

```python
from dotenv import load_dotenv
load_dotenv()

from security_middleware import apply_security
# After app = Flask(__name__):
apply_security(app)
```

### 4. Run Backend

```powershell
$env:GOOGLE_SAFE_BROWSING_KEY="your_key_here"; python app.py
```

Expected output:
```
✅ ML Model loaded! Features: 35
🚀 Scam Detector v3.1 — http://localhost:5000
   ML Model      : ✅
   OCR           : ✅
   Safe Browsing : ✅
```

### 5. Open Frontend

Just double-click `TRINETRA_frontend/index.html` in your browser. That's it!

---


### Twilio WhatsApp Bot (Free trial)

1. Sign up at [twilio.com/try-twilio](https://www.twilio.com/try-twilio)
2. Console → Messaging → Try WhatsApp → follow sandbox instructions
3. Set webhook URL: `https://your-render-url.onrender.com/whatsapp`
4. Copy `ACCOUNT_SID` and `AUTH_TOKEN` → paste in `.env`

---

## 📡 API Endpoints

### `POST /analyze` — Analyze a URL

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://sbi-kyc-update.xyz"}'
```

Response:
```json
{
  "final_score": 87.5,
  "final_label": "DANGER 🔴",
  "ml_based":    { "score": 95.8, "label": "DANGER 🔴" },
  "rule_based":  { "score": 65.8, "label": "SUSPICIOUS 🟡" },
  "ensemble":    { "score": 87.5, "label": "DANGER 🔴" },
  "details": {
    "domain_age":    { "age_days": 3, "registrar": "..." },
    "ssl":           { "has_ssl": false, "ssl_risk_score": 80 },
    "geo":           { "country": "Russia", "is_hosting": true },
    "safe_browsing": { "is_malicious": true, "threat_type": "SOCIAL_ENGINEERING" },
    "redirects":     { "hop_count": 4, "suspicious": true },
    "url_flags":     ["IP_IN_URL", "SCAM_KEYWORD", "SUSPICIOUS_TLD"]
  }
}
```

### `POST /analyze-sms` — Analyze SMS/WhatsApp text

```bash
curl -X POST http://localhost:5000/analyze-sms \
  -H "Content-Type: application/json" \
  -d '{"text": "Dear customer your SBI KYC expired click http://sbi-kyc.xyz"}'
```

### `POST /analyze-image` — Analyze WhatsApp screenshot

```bash
curl -X POST http://localhost:5000/analyze-image \
  -F "image=@screenshot.png"
```

### `GET /health` — Server status

```bash
curl http://localhost:5000/health
# { "status": "ok", "ml": true, "ocr": true, "gsb": true, "features": 35 }
```

### `GET /history` — Last 50 scans

```bash
curl http://localhost:5000/history
```

---

## 🏆 Scoring Logic

| Score | Label | Meaning |
|---|---|---|
| 0–39 | 🟢 SAFE | No significant threats found |
| 40–69 | 🟡 SUSPICIOUS | Proceed with caution |
| 70–100 | 🔴 DANGER | High probability scam/phishing |

**Ensemble formula:**
```
Final Score = (Rule-based × 45%) + (ML Model × 50%) + (Lexical × 5%)
```

---

## 🔧 Retrain ML Model

If you want to retrain on fresh data:

1. Download dataset from [Kaggle UCI Phishing Dataset](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector)
2. Save as `phishing_data.csv` in `TRINETRA_backened/`
3. Run:
```bash
python train_model.py
```
4. New `scam_model.pkl` and `feature_columns.pkl` will be generated automatically.

---


## 🧪 Test Commands (PowerShell)

```powershell
# Health check
Invoke-RestMethod -Uri "http://localhost:5000/health" -Method GET

# Scan phishing URL
Invoke-RestMethod -Uri "http://localhost:5000/analyze" -Method POST `
  -ContentType "application/json" `
  -Body '{"url": "http://paypal-secure-login.xyz/verify"}'

# Scan safe URL
Invoke-RestMethod -Uri "http://localhost:5000/analyze" -Method POST `
  -ContentType "application/json" `
  -Body '{"url": "https://www.google.com"}'

# Scan scam SMS
Invoke-RestMethod -Uri "http://localhost:5000/analyze-sms" -Method POST `
  -ContentType "application/json" `
  -Body '{"text": "Dear customer your SBI KYC expired click http://sbi-kyc.xyz"}'

# Google malware test URL
Invoke-RestMethod -Uri "http://localhost:5000/analyze" -Method POST `
  -ContentType "application/json" `
  -Body '{"url": "http://malware.testing.google.test/testing/malware/"}'

# View history
Invoke-RestMethod -Uri "http://localhost:5000/history" -Method GET
```

---

## 🛡️ Security Features

- **Rate limiting** — 100 req/hour, 20 req/minute per IP
- **SSRF protection** — blocks private/internal IP analysis
- **Input sanitization** — URL and SMS input validation
- **Security headers** — XSS, clickjacking, MIME sniff protection
- **CORS** — configurable allowed origins via `.env`
- **Request size limits** — max 64KB body

---

## 📦 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Flask 3.0 |
| ML Model | XGBoost, scikit-learn, pandas |
| OCR | Tesseract, pytesseract, Pillow |
| DNS/WHOIS | dnspython, python-whois |
| WhatsApp | Twilio API |
| Frontend | HTML5, Three.js (3D), Vanilla JS |
| Deployment | Render.com |

---

## 👥 Team

**Shield Squad** — Delhi NCR Hackathon

---

## 📄 License

MIT License — free to use, modify and distribute.

---

> ⚠️ **Disclaimer:** Trinetra is a security research tool. Always verify results independently before taking action. Report cybercrime at [cybercrime.gov.in](https://cybercrime.gov.in) or call **1930**.
