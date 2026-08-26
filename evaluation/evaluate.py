import json
import os
import sys
import time
from collections import Counter

import requests

DEFAULT_URL = "https://scamshield-ai-dpm7.onrender.com"


def normalize_level(value):
    value = str(value or "").upper().strip()
    return value if value in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "UNKNOWN"


def category_family(value):
    value = str(value or "").lower()
    if "bank" in value or "account verification" in value:
        return "Bank / Account Verification Scam"
    if "job" in value:
        return "Job Scam"
    if "delivery" in value:
        return "Delivery Scam"
    if "investment" in value:
        return "Investment Scam"
    if "lottery" in value or "prize" in value:
        return "Lottery / Prize Scam"
    if "phishing" in value or "link" in value:
        return "Phishing / Suspicious Link"
    return "Other / Suspicious"


def run(base_url):
    with open(os.path.join(os.path.dirname(__file__), "test_cases.json"), encoding="utf-8") as f:
        cases = json.load(f)

    url = base_url.rstrip("/") + "/api/analyze"
    results = []
    print(f"Evaluating {len(cases)} cases against {url}\n")

    for i, case in enumerate(cases, 1):
        try:
            r = requests.post(url, json={"message": case["message"]}, timeout=90)
            r.raise_for_status()
            out = r.json()
            pred_level = normalize_level(out.get("risk_level"))
            pred_category = category_family(out.get("scam_category"))
            true_level = normalize_level(case["risk_level"])
            true_category = category_family(case["category"])
            level_ok = pred_level == true_level
            category_ok = pred_category == true_category
            results.append({"id": case["id"], "level_ok": level_ok, "category_ok": category_ok, "pred_level": pred_level, "true_level": true_level, "pred_category": pred_category, "true_category": true_category, "score": out.get("risk_score"), "mode": out.get("analysis_mode")})
            print(f"{i:02d}. {case['id']}  level={'✓' if level_ok else '✗'}  category={'✓' if category_ok else '✗'}  score={out.get('risk_score')}  mode={out.get('analysis_mode')}")
        except Exception as e:
            results.append({"id": case["id"], "error": str(e)})
            print(f"{i:02d}. {case['id']}  ERROR: {e}")
        time.sleep(0.25)

    valid = [x for x in results if "error" not in x]
    level_accuracy = sum(x["level_ok"] for x in valid) / len(valid) if valid else 0
    category_accuracy = sum(x["category_ok"] for x in valid) / len(valid) if valid else 0
    exact_accuracy = sum(x["level_ok"] and x["category_ok"] for x in valid) / len(valid) if valid else 0

    print("\n=== ScamShield Evaluation ===")
    print(f"Cases evaluated:       {len(valid)}/{len(cases)}")
    print(f"Risk-level accuracy:   {level_accuracy:.1%}")
    print(f"Category accuracy:     {category_accuracy:.1%}")
    print(f"Exact match accuracy:  {exact_accuracy:.1%}")

    if valid:
        print("\nRisk-level confusion matrix (actual -> predicted):")
        levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        print("actual\\predicted | " + " | ".join(f"{x:>8}" for x in levels))
        for actual in levels:
            counts = Counter(x["pred_level"] for x in valid if x["true_level"] == actual)
            print(f"{actual:16} | " + " | ".join(f"{counts[x]:8}" for x in levels))

    os.makedirs(os.path.dirname(__file__), exist_ok=True)
    with open(os.path.join(os.path.dirname(__file__), "latest_results.json"), "w", encoding="utf-8") as f:
        json.dump({"base_url": base_url, "cases": len(cases), "valid": len(valid), "risk_level_accuracy": level_accuracy, "category_accuracy": category_accuracy, "exact_match_accuracy": exact_accuracy, "results": results}, f, indent=2)
    print("\nSaved evaluation/latest_results.json")


if __name__ == "__main__":
    base_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    run(base_url)
