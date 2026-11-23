from app.services.explainer import explain
import re
from urllib.parse import urlparse
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class EmailIn(BaseModel):
    content: str

URGENCY = ["urgent", "immediately", "within 24 hours", "account suspended",
           "final notice", "act now", "expires today", "verify now"]
CREDENTIAL = ["verify your account", "confirm your password", "login to",
              "update your payment", "enter your otp", "security alert", "kyc"]
MONEY = ["wire transfer", "gift card", "invoice attached", "change of bank",
         "payment overdue", "refund"]
BRANDS = ["paypal", "amazon", "microsoft", "google", "apple", "sbi", "hdfc", "icici", "netflix"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"]
RISKY_TLDS = (".xyz", ".top", ".click", ".work", ".zip", ".tk", ".ru")

def find_hits(text, words):
    return [w for w in words if w in text]

@router.post("/analyze")
async def analyze(email: EmailIn):
    text = email.content.lower()
    findings = []  # each: {category, severity, points, reason}

    def add(category, points, reason):
        findings.append({"category": category, "points": points, "reason": reason})

    if hits := find_hits(text, URGENCY):
        add("Urgency / fear", min(10 + 5 * len(hits), 25),
            f"Uses pressure language ({', '.join(hits[:3])}) to rush you into acting without thinking.")

    if hits := find_hits(text, CREDENTIAL):
        add("Credential harvesting", 25,
            f"Asks you to verify or enter account details ({', '.join(hits[:3])}). Legitimate companies rarely ask this by email.")

    if hits := find_hits(text, MONEY):
        add("Payment / BEC", 20,
            f"Mentions money requests ({', '.join(hits[:3])}), a common pattern in business email compromise.")

    # URLs
    urls = re.findall(r"https?://[^\s<>\"')]+", email.content)
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        if any(host == s or host.endswith("." + s) for s in SHORTENERS):
            add("Suspicious link", 15, f"Shortened link ({host}) hides the real destination.")
        elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            add("Suspicious link", 25, f"Link points to a raw IP address ({host}) instead of a real website.")
        elif host.endswith(RISKY_TLDS):
            add("Suspicious link", 15, f"Link uses an uncommon domain ending ({host}) often seen in scams.")
        for b in BRANDS:
            if b in host and not re.search(rf"(^|\.){b}\.(com|in|co\.in)$", host):
                add("Lookalike domain", 30,
                    f"Link domain '{host}' mentions '{b}' but is not the real {b} website.")
                break
        if u.startswith("http://"):
            add("Suspicious link", 5, f"Link {host} is not encrypted (http, not https).")

    # Sender spoofing
    m = re.search(r"from:.*?<?([\w.+-]+@([\w.-]+))>?", email.content, re.I)
    if m:
        domain = m.group(2).lower()
        for b in BRANDS:
            if b in domain and not re.search(rf"(^|\.){b}\.(com|in|co\.in)$", domain):
                add("Sender spoofing", 30, f"Sender domain '{domain}' imitates {b}.")
                break
        if re.search(r"reply-to:.*@", email.content, re.I):
            rt = re.search(r"reply-to:.*?@([\w.-]+)", email.content, re.I).group(1).lower()
            if rt != domain:
                add("Sender spoofing", 20, f"Replies go to a different domain ({rt}) than the sender ({domain}).")

    if re.search(r"\.(exe|scr|zip|js|iso|html?)\b", text) and "attach" in text:
        add("Dangerous attachment", 20, "Mentions an attachment type commonly used to deliver malware.")

    score = min(sum(f["points"] for f in findings), 100)
    level = "High risk" if score >= 60 else "Medium risk" if score >= 30 else "Low risk"
    explanation = await explain(email.content, score, level, findings)
    return {"score": score, "level": level, "findings": findings,
            "urls": urls, "explanation": explanation}