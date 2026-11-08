from __future__ import annotations

import re
from collections import deque
from urllib.parse import urlparse

from ..common import ensure_url, short_error
from ..extract import extract_all, parse_html
from ..net import Cancelled, Net

SKIP_EXT = re.compile(r"\.(?:png|jpe?g|gif|webp|svg|ico|bmp|css|js|mjs|map|woff2?|ttf|eot|pdf|zip|rar|7z|gz|tar|"
                      r"mp[34]|webm|avi|mov|mkv|flac|wav|ogg|exe|msi|dmg|apk|iso|bin|torrent)(?:\?|$)", re.I)


def run(net: Net, target: str, log=print, depth: int = 1, max_pages: int = 25, external: bool = False, **_):
    start = ensure_url(target)
    if not urlparse(start).path:
        start += "/"
    host0 = (urlparse(start).hostname or "").lower()
    if not host0:
        raise ValueError(f"Niepoprawny adres: {target!r}")
    queue: deque = deque([(start, 0)])
    seen: set[str] = set()
    pages: list[dict] = []
    findings: dict[str, dict[str, str]] = {}
    ext_links: set[str] = set()

    log(f"[*] Crawl {start} (głębokość {depth}, max {max_pages} stron, {net.mode})")
    while queue and len(pages) < max_pages:
        net.check_cancel()
        url, d = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            r, text = net.fetch(url)
        except Cancelled:
            raise
        except Exception as e:
            pages.append({"URL": url, "Błąd": short_error(e)})
            log(f"[-] {url}: {short_error(e)}")
            continue
        ctype = r.headers.get("Content-Type", "").lower()
        page = parse_html(text, r.url) if "html" in ctype or "<html" in text[:2000].lower() else \
            {"title": "", "links": [], "meta": {}}
        pages.append({"URL": url, "HTTP": r.status_code, "Tytuł": page["title"] or "—",
                      "Typ": ctype.split(";")[0] or "—", "Rozmiar [B]": len(r.content)})
        log(f"[+] {r.status_code} {url} — {page['title'][:70]}")

        for cat, vals in extract_all(text).items():
            bucket = findings.setdefault(cat, {})
            for v in vals:
                bucket.setdefault(v, url)

        if d >= depth:
            continue
        for link in page["links"]:
            h = (urlparse(link).hostname or "").lower()
            if SKIP_EXT.search(urlparse(link).path):
                continue
            same = h == host0 or h.endswith("." + host0)
            if same or external:
                if link not in seen:
                    queue.append((link, d + 1))
            else:
                ext_links.add(link)

    out: dict = {
        "Start": start,
        "Podsumowanie": f"odwiedzono {len(pages)} stron, znaleziono "
                        + ", ".join(f"{k}: {len(v)}" for k, v in findings.items()) if findings else
                        f"odwiedzono {len(pages)} stron, brak artefaktów",
    }
    for cat, vals in findings.items():
        out[cat] = dict(sorted(vals.items()))
    out["Odwiedzone strony"] = pages
    if ext_links:
        hosts = sorted({urlparse(l).hostname for l in ext_links if urlparse(l).hostname})
        out["Domeny zewnętrzne"] = hosts[:200]
    if queue:
        out["Niezbadane (limit stron)"] = len(queue)
    return out
