from __future__ import annotations

import time
from urllib.parse import urlparse

from ..common import parallel, short_error
from ..extract import parse_html
from ..net import Net, b32_onion_ok


def _normalize(t: str) -> str:
    t = t.strip()
    if "://" not in t:
        t = "http://" + t
    return t


def run(net: Net, target, log=print, **_):
    targets = target if isinstance(target, list) else [target]
    urls = [_normalize(t) for t in targets if t and t.strip()]
    out: dict[str, dict] = {}
    valid = []
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        info = {"Adres": host}
        if not host.endswith(".onion"):
            info["Format"] = "to nie jest adres .onion"
        elif b32_onion_ok(host):
            info["Format"] = "v3, suma kontrolna poprawna"
            valid.append(u)
        else:
            info["Format"] = "NIEPRAWIDŁOWY (literówka, podróbka albo przestarzały v2)"
        out[u] = info

    if valid and not net.use_tor:
        for u in valid:
            out[u]["Status"] = "nie sprawdzono — włącz tryb Tor"
        log("[!] Do sprawdzenia dostępności .onion potrzebny jest tryb Tor.")
        return out

    def check(url):
        t0 = time.time()
        r, text = net.fetch(url, max_bytes=600_000)
        page = parse_html(text, r.url)
        return {
            "Status": "ONLINE",
            "HTTP": r.status_code,
            "Tytuł": page["title"] or "—",
            "Serwer": r.headers.get("Server", "—"),
            "Końcowy URL": r.url,
            "Czas odpowiedzi [s]": round(time.time() - t0, 1),
        }

    log(f"[*] Sprawdzam {len(valid)} adres(ów) przez Tor…")
    for url, res in parallel(net, check, valid, workers=4):
        if isinstance(res, Exception):
            out[url].update({"Status": "OFFLINE / nieosiągalny", "Błąd": short_error(res)})
            log(f"[-] {url}: {short_error(res)}")
        else:
            out[url].update(res)
            log(f"[+] {url}: ONLINE ({res['HTTP']}) {res['Tytuł']}")
    return out
