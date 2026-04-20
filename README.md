# Security Headers Scanner 🔒

Advanced security headers analysis tool that checks CSP, HSTS, X-Frame-Options, and more.

## Features

- ✅ Checks 11+ security headers
- ✅ Security score (0-100%) with A+ to F grading
- ✅ SSL/TLS validation
- ✅ Async scanning with caching
- ✅ REST API + Bulk scanning (up to 10 URLs)
- ✅ Export JSON & Print reports

## Quick Installation

```bash
git clone https://github.com/hamidrezal/sescan.git
cd security-headers-scanner
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver


Access the App
Open browser: http://localhost:8000

⚠️ Django dev server only supports HTTP, not HTTPS. Always use http://

Testing with Ngrok (HTTPS locally)
Ngrok creates a secure HTTPS tunnel to your localhost.

Setup
bash
# 1. Install ngrok
pip install pyngrok
# OR download from https://ngrok.com

# 2. Sign up & get authtoken from https://dashboard.ngrok.com/auth
ngrok config add-authtoken YOUR_TOKEN

# 3. Start Django (Terminal 1)
python manage.py runserver 8000

# 4. Start ngrok (Terminal 2)
ngrok http 8000
Access
https://abc123.ngrok.io   ← Use this URL in the scanner
Inspect requests: http://localhost:4040

API Endpoints
bash
# Single URL check
GET /api/check-headers/?url=example.com

# Bulk check (max 10 URLs)
POST /api/bulk-check-headers/
Content-Type: application/json
{"urls": ["example.com", "google.com"]}
