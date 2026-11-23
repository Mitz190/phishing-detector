LEGIT = {
    "paypal": ["paypal.com", "paypal.me"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
    "google": ["google.com", "google.co.in", "gmail.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "whatsapp": ["whatsapp.com"],
    "flipkart": ["flipkart.com"],
    "paytm": ["paytm.com"],
    "sbi": ["sbi.co.in", "onlinesbi.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
}

TWO_PART_TLDS = {"co.in", "co.uk", "com.au", "org.in", "net.in", "gov.in", "ac.in", "com.br"}
ALL_LEGIT = {d for domains in LEGIT.values() for d in domains}


def registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def variants(name: str) -> set:
    """Undo common character swaps: 0->o, 1->l or i, 3->e, 5->s, rn->m, vv->w."""
    base = name.replace("rn", "m").replace("vv", "w")
    base = base.replace("0", "o").replace("3", "e").replace("5", "s").replace("4", "a")
    return {name, base.replace("1", "l"), base.replace("1", "i")}


def check_host(host: str):
    """Returns a list of (points, reason) for one hostname."""
    host = (host or "").lower().strip(".")
    results = []
    if not host or "." not in host:
        return results

    if host.startswith("xn--") or ".xn--" in host or any(ord(c) > 127 for c in host):
        results.append((30, f"'{host}' contains look-alike foreign characters (for example a Cyrillic 'а' that looks like an English 'a'), a classic trick to imitate real sites."))

    reg = registrable(host)
    if reg in ALL_LEGIT:
        return results  # genuine brand domain

    name = reg.split(".")[0]
    for brand, legit in LEGIT.items():
        # 1) Real domain hidden in a subdomain: paypal.com.evil.xyz
        if any(l in host for l in legit):
            results.append((35, f"'{host}' puts a real company name in front to fool you. The actual site you would land on is '{reg}'."))
            break
        # 2) Typosquatting: paypa1.com, paypall.com, micr0soft.com
        if len(brand) >= 5:
            for v in variants(name):
                if v == brand and name != brand:
                    results.append((35, f"'{reg}' imitates {brand} by swapping look-alike characters (like 0 for o or 1 for l)."))
                    break
                if 0 < lev(v, brand) <= (2 if len(brand) >= 8 else 1):
                    results.append((35, f"'{reg}' is almost identical to {brand} (a likely typo-squatting domain)."))
                    break
            else:
                v = None
            if results and results[-1][0] == 35:
                break
        # 3) Brand name inside another domain: paypal-verify-login.xyz
        if brand in name:
            results.append((30, f"'{reg}' uses the name '{brand}' but is not the real {brand} website."))
            break

    if host.count("-") >= 3:
        results.append((10, f"'{host}' has many hyphens, which is common in throwaway scam domains."))
    if len(host.split(".")) >= 5:
        results.append((10, f"'{host}' has an unusually long chain of subdomains, which is often used to hide the real domain."))
    return results