import re
from email import message_from_string
from email.utils import parseaddr

from app.utils.domains import LEGIT, registrable


def domain_of(value):
    _, addr = parseaddr(value or "")
    return addr.split("@")[-1].lower().strip() if "@" in addr else ""


def display_name_check(from_value):
    """Catches 'PayPal Support <someone@gmail.com>' style impersonation."""
    name, addr = parseaddr(from_value or "")
    dom = domain_of(from_value)
    if not name or not dom:
        return None
    reg = registrable(dom)
    lname = name.lower()
    for brand, legit in LEGIT.items():
        if re.search(rf"\b{re.escape(brand)}\b", lname) and reg not in legit:
            return (30, f"The sender calls itself '{name}', but the address really comes from '{reg}', not an official {brand} domain.")
    return None


def _status(msg, mech):
    found = []
    for h in msg.get_all("Authentication-Results", []):
        found += [s.lower() for s in re.findall(rf"\b{mech}=(\w+)", str(h), re.I)]
    if not found and mech == "spf":
        m = re.match(r"\s*(\w+)", str(msg.get("Received-SPF", "")))
        if m:
            found.append(m.group(1).lower())
    if not found:
        return "not found"
    if mech == "dkim" and "pass" in found:
        return "pass"
    return found[0]


def analyze_headers(raw):
    """Returns {'auth': {...}, 'findings': [(category, points, reason)], 'note': str|None}"""
    msg = message_from_string(raw.strip())
    auth = {m: _status(msg, m) for m in ("spf", "dkim", "dmarc")}
    findings, note = [], None

    if not (msg.get("From") or msg.get("Received") or msg.get("Authentication-Results")):
        return {"auth": auth, "findings": [], "note": "The headers could not be read. Paste the full original headers, starting from the first line."}

    if auth["spf"] == "fail":
        findings.append(("Email authentication", 25, "SPF check FAILED: the server that sent this email is not authorised to send for the sender's domain."))
    elif auth["spf"] == "softfail":
        findings.append(("Email authentication", 15, "SPF check soft-failed: the sending server is probably not authorised for the sender's domain."))
    if auth["dkim"] in ("fail", "permerror"):
        findings.append(("Email authentication", 25, "DKIM check FAILED: the email's digital signature is invalid, so it may have been forged or altered."))
    if auth["dmarc"] == "fail":
        findings.append(("Email authentication", 30, "DMARC check FAILED: the sender's domain says this email does not pass its own security policy."))

    if all(v == "not found" for v in auth.values()):
        note = "No SPF/DKIM/DMARC results were found in these headers. Make sure you copied the full original headers."

    from_d = domain_of(msg.get("From"))
    rp = domain_of(msg.get("Return-Path"))
    reply = domain_of(msg.get("Reply-To"))
    if from_d and rp and registrable(from_d) != registrable(rp):
        findings.append(("Sender mismatch", 10, f"The visible sender domain ({from_d}) differs from the real return address domain ({rp}). Bulk mailers do this legitimately too, so it counts for little on its own."))
    if from_d and reply and registrable(from_d) != registrable(reply):
        findings.append(("Sender mismatch", 20, f"Replies would go to {reply}, not to the sender's domain ({from_d})."))

    dn = display_name_check(msg.get("From"))
    if dn:
        findings.append(("Sender spoofing", dn[0], dn[1]))

    return {"auth": auth, "findings": findings, "note": note}