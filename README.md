# 🛡️ ScamShield

AI-assisted scam-risk analysis for suspicious SMS, WhatsApp messages, emails, job offers and payment requests.

## What it does
- Explainable 0–100 risk score
- LOW / MEDIUM / HIGH / CRITICAL classification
- Scam-category detection
- Red-flag explanations
- Recommended actions and things to avoid
- Hinglish-aware deterministic signals
- Two-layer architecture: local safety engine + Gemini structured analysis
- Graceful fallback when Gemini is unavailable
- Server-side API key handling

## Architecture
```text
Browser → Flask API → local safety layer + Gemini → structured risk assessment
```

The browser never receives the Gemini API key. The key is supplied through an environment variable on the server.

## Run locally
```bash
pip install -r requirements.txt
```
PowerShell:
```powershell
$env:GEMINI_API_KEY="YOUR_KEY"
$env:GEMINI_MODEL="gemini-3.5-flash-lite"
python app.py
```
Open `http://127.0.0.1:5000`.

## Deploy on Render
Create a Render Web Service from this repository.

Build command:
```text
pip install -r requirements.txt
```
Start command:
```text
gunicorn --bind 0.0.0.0:$PORT app:app
```
Environment variables:
```text
GEMINI_API_KEY=your-key
GEMINI_MODEL=gemini-3.5-flash-lite
```
Never commit an API key.

## Portfolio description
Built a two-layer scam-risk analysis application combining deterministic fraud indicators with structured LLM classification, explainable risk scoring, safety guardrails, Hinglish support, server-side secret handling, and graceful AI-service fallback.

## Limitation
ScamShield cannot authenticate a sender or guarantee that a message is fraudulent or legitimate. High-impact requests involving money, credentials or identity documents should be independently verified through official channels.

**Never paste passwords, OTPs, PINs, CVVs or full card numbers into the app.**
