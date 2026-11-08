from __future__ import annotations

import hashlib
import html
import re
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin

from .net import b32_onion_ok

EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![\w-])")
BAD_EMAIL_TLD = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico", "bmp", "woff", "woff2", "avif"}
ONION_RE = re.compile(r"(?<![a-z2-7])[a-z2-7]{56}\.onion\b", re.I)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BTC_LEGACY_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![1-9A-HJ-NP-Za-km-z])")
BTC_BECH32_RE = re.compile(r"\bbc1[ac-hj-np-z02-9]{11,71}\b", re.I)
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[48][1-9A-HJ-NP-Za-km-z]{94}(?![1-9A-HJ-NP-Za-km-z])")
PGP_RE = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----", re.S)
DEOBF = [(re.compile(r"\s*[\[\(\{]\s*(?:at|małpa)\s*[\]\)\}]\s*", re.I), "@"),
         (re.compile(r"\s*[\[\(\{]\s*(?:dot|kropka)\s*[\]\)\}]\s*", re.I), ".")]

SOCIAL = {
    "Telegram": r"(?:https?://)?(?:t\.me|telegram\.me)/(?!share|joinchat/?$)[A-Za-z0-9_+/-]{3,}",
    "Discord": r"(?:https?://)?(?:discord\.gg|discord(?:app)?\.com/invite)/[A-Za-z0-9-]+",
    "X / Twitter": r"https?://(?:www\.)?(?:twitter|x)\.com/(?!share|intent|home|search)[A-Za-z0-9_]{1,15}\b",
    "Facebook": r"https?://(?:www\.|m\.)?facebook\.com/(?!sharer|share|dialog|tr\b|plugins)[A-Za-z0-9.\-]+",
    "Instagram": r"https?://(?:www\.)?instagram\.com/(?!p/|explore)[A-Za-z0-9_.]+",
    "GitHub": r"https?://(?:www\.)?github\.com/[A-Za-z0-9-]+(?:/[A-Za-z0-9_.-]+)?",
    "LinkedIn": r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:in|company)/[A-Za-z0-9_%-]+",
    "YouTube": r"https?://(?:www\.)?youtube\.com/(?:@|channel/|c/|user/)[A-Za-z0-9_.-]+",
    "Reddit": r"https?://(?:www\.|old\.)?reddit\.com/(?:r|u|user)/[A-Za-z0-9_-]+",
    "Keybase": r"https?://keybase\.io/[A-Za-z0-9_]+",
    "Matrix": r"https?://matrix\.to/#/[@!#][^\s\"'<>]+",
    "XMPP / Jabber": r"xmpp:[^\s\"'<>]+",
    "Session ID": r"\b05[0-9a-f]{64}\b",
    "Tox ID": r"\b[0-9A-F]{76}\b",
}
SOCIAL_RE = {k: re.compile(v) for k, v in SOCIAL.items()}


def base58check_ok(s: str) -> bool:
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            return False
        n = n * 58 + i
    if n.bit_length() > 200:
        return False
    raw = n.to_bytes(25, "big")
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _bech32_polymod(values) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def bech32_ok(addr: str) -> bool:
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    a = addr.lower()
    hrp, _, data = a.rpartition("1")
    if not hrp or len(data) < 6 or any(c not in charset for c in data):
        return False
    hrp_exp = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    return _bech32_polymod(hrp_exp + [charset.find(c) for c in data]) in (1, 0x2BC830A3)


def extract_all(text: str) -> dict:
    t = html.unescape(text)
    deobf = t
    for rx, rep in DEOBF:
        deobf = rx.sub(rep, deobf)

    res: dict[str, list] = {}
    emails = {e.lower() for src in (t, deobf) for e in EMAIL_RE.findall(src)
              if e.rsplit(".", 1)[-1].lower() not in BAD_EMAIL_TLD}
    res["E-maile"] = sorted(emails)
    res["Adresy .onion (v3)"] = sorted({o.lower() for o in ONION_RE.findall(t) if b32_onion_ok(o)})
    btc = {a for a in BTC_LEGACY_RE.findall(t) if base58check_ok(a)}
    btc |= {a for a in BTC_BECH32_RE.findall(t) if bech32_ok(a)}
    res["Bitcoin"] = sorted(btc)
    res["Monero"] = sorted(set(XMR_RE.findall(t)))
    res["Ethereum"] = sorted(set(ETH_RE.findall(t)))
    pgp = PGP_RE.findall(t)
    if pgp:
        res["Klucze PGP"] = [f"blok klucza publicznego ({len(k)} znaków)" for k in pgp]
    for name, rx in SOCIAL_RE.items():
        found = sorted({m.rstrip("/.,)") for m in rx.findall(t)})
        if found:
            res[name] = found[:50]
    return {k: v for k, v in res.items() if v}


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.meta: dict[str, str] = {}
        self._title: list[str] | None = None
        self.title = ""

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("a", "area", "link") and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("iframe", "frame") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "form" and a.get("action"):
            self.links.append(a["action"])
        elif tag == "title" and not self.title:
            self._title = []
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or a.get("http-equiv") or "").lower()
            if name and a.get("content"):
                self.meta.setdefault(name, a["content"].strip())

    def handle_endtag(self, tag):
        if tag == "title" and self._title is not None:
            self.title = " ".join("".join(self._title).split())[:300]
            self._title = None

    def handle_data(self, data):
        if self._title is not None:
            self._title.append(data)


def parse_html(text: str, base_url: str = "") -> dict:
    p = _PageParser()
    try:
        p.feed(text)
        p.close()
    except Exception:
        pass
    links = []
    seen = set()
    for href in p.links:
        href = href.strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        u = urldefrag(urljoin(base_url, href))[0] if base_url else href
        if u.startswith(("http://", "https://")) and u not in seen:
            seen.add(u)
            links.append(u)
    return {"title": p.title, "meta": p.meta, "links": links}
