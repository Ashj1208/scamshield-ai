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

## Proof / evidence
The repository includes project evidence cards documenting the working system and the actual development benchmark. These are deliberately separated from marketing claims so the results remain auditable.

- [Live AI analysis evidence](proof/live-analysis.svg)
- [Public Render deployment evidence](proof/render-deployment.svg)
- [Evaluation results evidence](proof/evaluation-results.svg)

The public application is available at https://scamshield-ai-dpm7.onrender.com.

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

A live evaluation was run against the deployed application. The first baseline produced:

| Metric | Baseline result |
|---|---:|
| Cases completed | 29 / 30 |
| Risk-level accuracy | 51.7% |
| Category accuracy | 65.5% |
| Exact level + category | 34.5% |

One case returned HTTP 500 and was excluded from the completed-case denominator. These numbers are reported as observed; they are **not** a production accuracy claim.

Run the evaluator against the live deployment:

```bash
python -u evaluation/evaluate.py https://scamshield-ai-dpm7.onrender.com
```

The evaluator reports:
- risk-level accuracy
- category accuracy
- exact-match accuracy
- a risk-level confusion matrix
- per-case results
- failure cases and per-category breakdowns

The evaluation workflow is intentionally a baseline → intervention → re-evaluation loop rather than a cherry-picked accuracy claim.

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
