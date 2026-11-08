from __future__ import annotations

import base64
import html
import re
from urllib.parse import parse_qs, unquote, urlparse

from ..common import short_error
from ..net import Cancelled, Net, b32_onion_ok

AHMIA = "https://ahmia.fi"
DDG_CLEAR = "https://html.duckduckgo.com/html/"
DDG_ONION = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html/"


def _clean(s: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", s)).split())


def ahmia(net: Net, query: str, limit: int):
    home = net.get(AHMIA + "/").text
    form = re.search(r'<form[^>]*id="searchForm".*?</form>', home, re.S)
    params = {"q": query}
    if form:
        for name, value in re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"',
                                      form.group(0)):
            params[name] = value
    r = net.get(AHMIA + "/search/", params=params, timeout=max(net.timeout, 45))
    r.raise_for_status()
    results, seen = [], set()
    for block in re.findall(r'<li class="result">(.*?)</li>', r.text, re.S):
        m = re.search(r'href="[^"]*redirect_url=([^"&]+)"[^>]*>(.*?)</a>', block, re.S)
        if not m:
            continue
        url = unquote(html.unescape(m.group(1)))
        if url in seen:
            continue
        seen.add(url)
        desc = re.search(r"<p>(.*?)</p>", block, re.S)
        last = re.search(r'data-timestamp="([^"]+)"', block)
        host = urlparse(url).hostname or ""
        results.append({
            "Tytuł": _clean(m.group(2))[:160] or host,
            "URL": url,
            "Opis": _clean(desc.group(1))[:300] if desc else "",
            "Ostatnio widziany": last.group(1) if last else "",
            "Adres v3 poprawny": b32_onion_ok(host),
        })
        if len(results) >= limit:
            break
    return results


def _bing_url(href: str) -> str:
    href = html.unescape(href)
    if "bing.com/ck/a" in href:
        u = parse_qs(urlparse(href).query).get("u", [""])[0]
        if u.startswith("a1"):
            u = u[2:]
            try:
                return base64.urlsafe_b64decode(u + "=" * (-len(u) % 4)).decode("utf-8", "replace")
            except (ValueError, UnicodeDecodeError):
                pass
    return href


def bing(net: Net, query: str, limit: int):
    results, seen, first = [], set(), 1
    while len(results) < limit and first < 60:
        r = net.get("https://www.bing.com/search", params={"q": query, "first": first, "setlang": "en"})
        r.raise_for_status()
        blocks = re.split(r'<li class="b_algo"', r.text)[1:]
        if not blocks:
            break
        for b in blocks:
            m = re.search(r'<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', b, re.S)
            if not m:
                continue
            url = _bing_url(m.group(1))
            if url in seen or not url.startswith("http"):
                continue
            seen.add(url)
            snip = re.search(r'<p[^>]*>(.*?)</p>', b, re.S)
            results.append({"Tytuł": _clean(m.group(2))[:160], "URL": url,
                            "Opis": _clean(snip.group(1))[:300] if snip else ""})
            if len(results) >= limit:
                break
        first += 10
    return results


def ddg(net: Net, query: str, limit: int):
    base = DDG_ONION if net.use_tor else DDG_CLEAR
    r = net.request("POST", base, data={"q": query, "kl": "wt-wt"})
    if "anomaly" in r.text or r.status_code == 202:
        raise RuntimeError("DuckDuckGo zwrócił CAPTCHA (ochrona przed botami) — użyj Bing lub spróbuj później")
    results = []
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>(.*?)(?=<a[^>]+class="result__a"|$)',
                         r.text, re.S):
        href = html.unescape(m.group(1))
        if "uddg=" in href:
            href = unquote(parse_qs(urlparse(href).query).get("uddg", [href])[0])
        snip = re.search(r'class="result__snippet"[^>]*>(.*?)</a>', m.group(3), re.S)
        results.append({"Tytuł": _clean(m.group(2)), "URL": href, "Opis": _clean(snip.group(1)) if snip else ""})
        if len(results) >= limit:
            break
    return results


ENGINES = {"ahmia": ("Ahmia (.onion)", ahmia), "bing": ("Bing", bing), "ddg": ("DuckDuckGo", ddg)}


def run(net: Net, target: str, log=print, engine: str = "auto", limit: int = 30, **_):
    query = target.strip()
    if not query:
        raise ValueError("Podaj zapytanie.")
    keys = {"auto": ["ahmia", "bing"], "wszystkie": ["ahmia", "bing", "ddg"]}.get(engine, [engine])
    out: dict = {"Zapytanie": query}
    onions: set[str] = set()
    for key in keys:
        label, fn = ENGINES[key]
        net.check_cancel()
        log(f"[*] {label}: szukam „{query}”…")
        try:
            res = fn(net, query, limit)
            out[f"{label} — {len(res)} wyników"] = res or "brak wyników"
            log(f"[+] {label}: {len(res)} wyników")
            for it in res:
                h = urlparse(it["URL"]).hostname or ""
                if h.endswith(".onion"):
                    onions.add(h)
        except Cancelled:
            raise
        except Exception as e:
            out[label] = "błąd: " + short_error(e)
            log(f"[!] {label}: {short_error(e)}")
    if onions:
        out["Unikalne usługi .onion"] = sorted(onions)
    return out
