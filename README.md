# 🛡️ ScamShield

**Live demo:** https://scamshield-ai-dpm7.onrender.com

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
Browser
   ↓
Flask API
   ↓
Deterministic safety signals ─────┐
   ↓                              │
Gemini structured analysis ──────┘
   ↓
Risk score + category + evidence + actions
```

The browser never receives the Gemini API key. The key is supplied through an environment variable on the server.

## Evaluation
The repository includes a 30-case labeled evaluation set covering:
- bank/account impersonation
- job scams
- delivery scams
- investment scams
- lottery/prize scams
- phishing/suspicious links
- benign and ambiguous messages

Run the evaluator against the live deployment:

```bash
python evaluation/evaluate.py https://scamshield-ai-dpm7.onrender.com
```

The evaluator reports:
- risk-level accuracy
- category accuracy
- exact-match accuracy
- a risk-level confusion matrix
- per-case results

**Do not claim an accuracy percentage until the evaluator has actually been run.** The dataset is a small engineering test set, not a statistically representative benchmark.

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
Built a two-layer scam-risk analysis application combining deterministic fraud indicators with structured LLM classification, explainable risk scoring, safety guardrails, Hinglish support, server-side secret handling, automated evaluation, and graceful AI-service fallback; deployed the application as a public web service.

## Limitations
ScamShield cannot authenticate a sender or guarantee that a message is fraudulent or legitimate. High-impact requests involving money, credentials or identity documents should be independently verified through official channels.

The 30-case evaluation set is a small development benchmark and should not be presented as production accuracy.

**Never paste passwords, OTPs, PINs, CVVs or full card numbers into the app.**
