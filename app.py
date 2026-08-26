import os, re, json, requests
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder="static", static_url_path="")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

SYSTEM_PROMPT = """You are ScamShield, a careful scam-risk analyst.
Analyze a user-provided message for phishing, fraud, impersonation and social-engineering indicators.
Never claim certainty. Never tell the user to click suspicious links. Never request or unnecessarily repeat passwords, OTPs, PINs, CVVs, full card numbers or bank credentials.
Return ONLY valid JSON:
{"risk_score":0,"risk_level":"LOW","scam_category":"","summary":"","red_flags":[{"title":"","why":""}],"recommended_actions":[],"avoid":[],"confidence":0}
Risk guide: 0-20 LOW, 21-45 MEDIUM, 46-70 HIGH, 71-100 CRITICAL.
Absence of red flags does not prove legitimacy."""

PATTERNS = [
(["immediately","urgent","urgently","act now","today","turant","jaldi","abhi","right away","limited time","final warning"],"Urgency / pressure","Pressure to act quickly can prevent independent verification.",13),
(["blocked","suspended","closed","legal action","arrest","penalty","band ho","band ho jayega","expire"],"Threat or consequence","Threats can trigger fear and rushed decisions.",13),
(["otp","password","pin","cvv","card number","bank details","login","credentials","verification code"],"Credential request","Requests for secret authentication information are a major warning sign.",24),
(["pay","payment","fee","registration fee","deposit","transfer","send money","processing fee","₹","rs "],"Money request","Unexpected payment requests are a common scam signal.",20),
(["kyc","verify","verification","account","sbi","bank","government","income tax","police"],"Authority / account impersonation","Scammers often impersonate trusted institutions.",11),
(["http://","https://","www.","bit.ly","tinyurl","t.me/"],"Link present","A link may lead to phishing; verify destinations independently.",12),
(["guaranteed","guarantee","double your","10x","huge returns","profit","earn","selected","congratulations","prize","lottery","winner"],"Too-good-to-be-true claim","Unusually attractive or guaranteed rewards are a common manipulation pattern.",17),
(["work from home","job offer","onboarding","position","hiring"],"Unsolicited job signal","Fake recruitment often combines attractive offers with fees or urgency.",8),
(["parcel","delivery","redelivery","courier"],"Delivery impersonation","Fake delivery notices commonly use small payments and links.",8),
]

def local_analysis(message):
    m=message.lower(); flags=[]; score=0
    for keys,title,why,pts in PATTERNS:
        if any(k in m for k in keys):
            flags.append({"title":title,"why":why}); score += pts
    urls=re.findall(r"https?://\S+|www\.\S+",message,re.I)
    if urls and not any(f["title"]=="Link present" for f in flags):
        flags.append({"title":"Link present","why":"Verify links independently instead of using the message link."}); score+=12
    score=min(100,score)
    if re.search(r"\b(job|work from home|onboarding|position|hiring)\b",m): category="Job Scam"
    elif re.search(r"\b(kyc|sbi|bank|account|otp)\b",m): category="Bank / Account Verification Scam"
    elif re.search(r"\b(parcel|delivery|courier|redelivery)\b",m): category="Delivery Scam"
    elif re.search(r"\b(invest|guaranteed returns|profit|guaranteed)\b",m): category="Investment Scam"
    elif re.search(r"\b(prize|lottery|winner)\b",m): category="Lottery / Prize Scam"
    elif urls: category="Phishing / Suspicious Link"
    else: category="Other / Suspicious"
    level="CRITICAL" if score>=71 else "HIGH" if score>=46 else "MEDIUM" if score>=21 else "LOW"
    summary=("This message shows several indicators commonly associated with scams. Treat it as high risk and verify independently before taking action." if score>=46 else "This message contains patterns worth checking before you act. The message itself cannot verify the sender or request." if score>=21 else "No strong scam indicators were detected in this text. That does not prove the message is legitimate.")
    return {"risk_score":score,"risk_level":level,"scam_category":category,"summary":summary,"red_flags":flags,"recommended_actions":["Verify the organization using its official website or app.","Do not rely on links or contact details supplied only by the message.","Never share OTPs, passwords, PINs, CVVs or full card details."],"avoid":["Do not click suspicious links.","Do not send money based only on this message.","Do not disclose authentication credentials."],"confidence":min(94,max(48,55+len(flags)*7))}

def gemini_analysis(message):
    models = list(dict.fromkeys([GEMINI_MODEL,"gemini-3.6-flash","gemini-3.5-flash"]))
    schema={"type":"OBJECT","properties":{"risk_score":{"type":"INTEGER"},"risk_level":{"type":"STRING","enum":["LOW","MEDIUM","HIGH","CRITICAL"]},"scam_category":{"type":"STRING"},"summary":{"type":"STRING"},"red_flags":{"type":"ARRAY","items":{"type":"OBJECT","properties":{"title":{"type":"STRING"},"why":{"type":"STRING"}},"required":["title","why"]}},"recommended_actions":{"type":"ARRAY","items":{"type":"STRING"}},"avoid":{"type":"ARRAY","items":{"type":"STRING"}},"confidence":{"type":"INTEGER"}},"required":["risk_score","risk_level","scam_category","summary","red_flags","recommended_actions","avoid","confidence"]}
    last_diag="Unknown Gemini error."
    for model in models:
        url=f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        payload={"systemInstruction":{"parts":[{"text":SYSTEM_PROMPT}]},"contents":[{"parts":[{"text":"Analyze this message:\n\n"+message}]}],"generationConfig":{"responseMimeType":"application/json","responseSchema":schema}}
        try:
            r=requests.post(url,headers={"x-goog-api-key":GEMINI_API_KEY,"Content-Type":"application/json"},json=payload,timeout=35)
            if not r.ok:
                try:
                    err=r.json().get("error",{}); detail=err.get("message",r.text[:300]); code=err.get("code",r.status_code)
                except Exception:
                    detail=r.text[:300]; code=r.status_code
                detail=re.sub(r'(?i)(key=|x-goog-api-key["\']?\s*[:=]\s*)[A-Za-z0-9_\-]+',r'\1[REDACTED]',str(detail))
                last_diag=f"Gemini HTTP {code}: {detail}"
                print(f"[ScamShield] {last_diag}")
                if r.status_code in (400,404): continue
                r.raise_for_status()
            data=r.json(); text_out=data["candidates"][0]["content"]["parts"][0]["text"]; result=json.loads(text_out)
            result["risk_score"]=max(0,min(100,int(result["risk_score"]))); result["confidence"]=max(0,min(100,int(result["confidence"])))
            return result,f"Gemini OK ({model})"
        except requests.RequestException as e:
            last_diag=f"Network error contacting Gemini: {type(e).__name__}"; print(f"[ScamShield] {last_diag}")
        except (KeyError,IndexError,json.JSONDecodeError,ValueError) as e:
            last_diag=f"Gemini returned an unexpected response: {type(e).__name__}"; print(f"[ScamShield] {last_diag}")
        except Exception as e:
            last_diag=f"Gemini integration error: {type(e).__name__}"; print(f"[ScamShield] {last_diag}")
    raise RuntimeError(last_diag)

@app.get("/")
def index(): return send_from_directory("static","index.html")

@app.post("/api/analyze")
def analyze():
    body=request.get_json(silent=True) or {}; message=str(body.get("message","")).strip()
    if not message: return jsonify({"error":"Please paste a message to analyze."}),400
    if len(message)>5000: return jsonify({"error":"Please keep the message under 5,000 characters."}),400
    local=local_analysis(message); result=local; mode="local"; diagnostic=None
    if GEMINI_API_KEY:
        try:
            result,diagnostic=gemini_analysis(message); mode="gemini + local safety layer"
            if local["risk_score"]>=71 and result["risk_score"]<71: result["risk_score"]=local["risk_score"]; result["risk_level"]="CRITICAL"
            result["red_flags"]=result.get("red_flags") or local["red_flags"]
        except Exception as e:
            mode="local fallback"; diagnostic=str(e)
    else: diagnostic="GEMINI_API_KEY is not set."
    result["analysis_mode"]=mode; result["gemini_diagnostic"]=diagnostic
    return jsonify(result)

if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.getenv("PORT","5000")),debug=False)
