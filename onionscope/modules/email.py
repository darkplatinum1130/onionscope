from __future__ import annotations

import hashlib
import re
import threading

from ..common import dns, run_steps
from ..net import Net

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}$")

PROVIDERS = [
    ("google.com", "Google (Gmail / Workspace)"), ("googlemail.com", "Google (Gmail / Workspace)"),
    ("outlook.com", "Microsoft 365 / Outlook"), ("protection.outlook.com", "Microsoft 365"),
    ("protonmail.ch", "Proton Mail"), ("proton.me", "Proton Mail"), ("tutanota.de", "Tuta (Tutanota)"),
    ("yahoodns.net", "Yahoo"), ("icloud.com", "Apple iCloud"), ("zoho", "Zoho Mail"), ("yandex", "Yandex"),
    ("mail.ru", "Mail.ru"), ("ovh.net", "OVH"), ("mimecast", "Mimecast"), ("pphosted.com", "Proofpoint"),
    ("messagingengine.com", "Fastmail"), ("mailbox.org", "mailbox.org"), ("riseup.net", "Riseup"),
    ("cock.li", "cock.li"), ("disroot.org", "Disroot"), ("posteo.de", "Posteo"),
    ("wp.pl", "Wirtualna Polska (WP Poczta)"), ("o2.pl", "o2 / WP"), ("onet", "Onet Poczta"),
    ("interia", "Interia Poczta"), ("home.pl", "home.pl"), ("nazwa.pl", "nazwa.pl"), ("gmx", "GMX"),
    ("web.de", "WEB.DE"), ("secureserver.net", "GoDaddy"), ("zoho.eu", "Zoho Mail"),
]

BUILTIN_DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "sharklasers.com", "10minutemail.com",
    "temp-mail.org", "tempmail.com", "yopmail.com", "trashmail.com", "getnada.com", "dispostable.com",
    "maildrop.cc", "mohmal.com", "emailondeck.com", "throwawaymail.com", "fakeinbox.com", "mintemail.com",
    "tempr.email", "discard.email", "spamgourmet.com", "mailnesia.com", "burnermail.io", "33mail.com",
    "tmpmail.org", "moakt.com", "inboxkitten.com", "mail.tm", "tempmail.plus", "1secmail.com",
}
_DISP: dict = {"set": None}
_DISP_LOCK = threading.Lock()


def disposable_domains(net: Net) -> set[str]:
    with _DISP_LOCK:
        if _DISP["set"] is None:
            try:
                r = net.get("https://raw.githubusercontent.com/disposable-email-domains/"
                            "disposable-email-domains/main/disposable_email_blocklist.conf")
                r.raise_for_status()
                _DISP["set"] = {l.strip().lower() for l in r.text.splitlines() if l.strip()} | BUILTIN_DISPOSABLE
            except Exception:
                _DISP["set"] = set(BUILTIN_DISPOSABLE)
        return _DISP["set"]


def _mail_dns(net: Net, domain: str):
    mx = dns(net, domain, "MX")
    out: dict = {"MX": mx or "BRAK — domena nie przyjmuje poczty"}
    mx_join = " ".join(mx).lower()
    prov = sorted({name for frag, name in PROVIDERS if frag in mx_join})
    out["Dostawca poczty"] = prov[0] if len(prov) == 1 else (prov or "nie rozpoznano (własny serwer?)")
    txt = dns(net, domain, "TXT")
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    out["SPF"] = spf[0] if spf else "brak"
    dmarc = [t for t in dns(net, "_dmarc." + domain, "TXT") if t.lower().startswith("v=dmarc1")]
    out["DMARC"] = dmarc[0] if dmarc else "brak"
    return out


def _gravatar(net: Net, email: str):
    h = hashlib.md5(email.lower().encode()).hexdigest()
    r = net.get(f"https://www.gravatar.com/avatar/{h}", params={"d": "404", "s": "200"})
    if r.status_code == 404:
        return "brak konta Gravatar"
    out: dict = {"Awatar": f"https://www.gravatar.com/avatar/{h}?s=400"}
    try:
        j = net.get_json(f"https://en.gravatar.com/{h}.json")
        e = (j.get("entry") or [{}])[0]
        out |= {k: v for k, v in {
            "Profil": e.get("profileUrl"), "Nazwa wyświetlana": e.get("displayName"),
            "Użytkownik": e.get("preferredUsername"), "Lokalizacja": e.get("currentLocation"),
            "O mnie": e.get("aboutMe"),
            "Konta": [f"{a.get('shortname') or a.get('domain')}: {a.get('url')}" for a in e.get("accounts", [])],
            "Linki": [u.get("value") for u in e.get("urls", [])],
        }.items() if v}
    except Exception:
        pass
    return out


def _pgp(net: Net, email: str):
    out = {}
    r = net.get(f"https://keys.openpgp.org/vks/v1/by-email/{email}")
    out["keys.openpgp.org"] = (f"klucz znaleziony: https://keys.openpgp.org/search?q={email}"
                               if r.status_code == 200 else "brak")
    r = net.get("https://keyserver.ubuntu.com/pks/lookup",
                params={"op": "index", "search": email, "options": "mr", "fingerprint": "on"})
    keys = []
    if r.status_code == 200:
        cur = None
        for ln in r.text.splitlines():
            p = ln.split(":")
            if p[0] == "pub" and len(p) > 1:
                cur = {"Odcisk": p[1], "Utworzony": _epoch(p[4] if len(p) > 4 else ""), "UID": []}
                keys.append(cur)
            elif p[0] == "uid" and cur is not None and len(p) > 1:
                from urllib.parse import unquote
                cur["UID"].append(unquote(p[1]))
    out["keyserver.ubuntu.com"] = keys or "brak"
    return out


def _epoch(s: str) -> str:
    import datetime as dt
    try:
        return dt.datetime.fromtimestamp(int(s), dt.timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, OSError):
        return s


def run(net: Net, target: str, log=print, gravatar: bool = True, pgp: bool = True, **_):
    email = target.strip().lower()
    if not EMAIL_RE.match(email):
        raise ValueError(f"Niepoprawny adres e-mail: {target!r}")
    local, domain = email.split("@", 1)
    out: dict = {"E-mail": email, "Część lokalna": local, "Domena": domain}

    def disp():
        return "TAK — domena jednorazowa (tymczasowa skrzynka)" if domain in disposable_domains(net) else "nie"

    out |= run_steps(net, log, [
        ("DNS poczty", True, lambda: _mail_dns(net, domain)),
        ("Domena jednorazowa", True, disp),
        ("Gravatar", gravatar, lambda: _gravatar(net, email)),
        ("Klucze PGP", pgp, lambda: _pgp(net, email)),
    ])
    out["Następny krok"] = f"Sprawdź nazwę użytkownika „{local.split('+')[0]}” w module Użytkownik."
    return out
