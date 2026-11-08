from __future__ import annotations

import concurrent.futures as cf
import re
from urllib.parse import urlparse

from .net import Cancelled, Net

DOH_SERVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


def _txt(data: str) -> str:
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(parts) if parts else data


def dns(net: Net, name: str, rtype: str = "A") -> list[str]:
    last = None
    for srv in DOH_SERVERS:
        try:
            r = net.get(srv, params={"name": name, "type": rtype},
                        headers={"Accept": "application/dns-json"}, timeout=min(net.timeout, 20))
            r.raise_for_status()
            out = []
            for a in r.json().get("Answer") or []:
                if a.get("type") != RTYPES[rtype]:
                    continue
                d = a.get("data", "")
                if rtype == "MX" and d.strip() in ("0 .", "0"):
                    d = "0 . (Null MX — domena nie przyjmuje poczty)"
                else:
                    d = _txt(d) if rtype == "TXT" else d.rstrip(".")
                if d not in out:
                    out.append(d)
            return out
        except Cancelled:
            raise
        except Exception as e:
            last = e
    raise RuntimeError(f"serwery DoH nie odpowiadają ({last})")


def vcard_name(entity: dict) -> str | None:
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item[0] == "fn" and item[3]:
                return item[3]
    except (IndexError, TypeError):
        pass
    return None


def rdap_entities(j: dict, role: str) -> list[str]:
    out: list[str] = []

    def walk(ents):
        for e in ents or []:
            if role in (e.get("roles") or []):
                n = vcard_name(e) or e.get("handle")
                if n and n not in out:
                    out.append(n)
            walk(e.get("entities"))

    walk(j.get("entities"))
    return out


def rdap_events(j: dict) -> dict:
    return {e.get("eventAction"): (e.get("eventDate") or "")[:10] for e in j.get("events", []) or []}


def _whois_ask(net: Net, server: str, query: str) -> str:
    s = net.connect(server, 43, timeout=min(net.timeout, 30))
    try:
        s.sendall((query + "\r\n").encode())
        data = b""
        while len(data) < 300_000:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    return data.decode("utf-8", errors="replace")


def whois_query(net: Net, query: str) -> tuple[str, str]:
    iana = _whois_ask(net, "whois.iana.org", query)
    m = re.search(r"^(?:refer|whois):\s*(\S+)", iana, re.M | re.I)
    if not m:
        return "whois.iana.org", iana
    server = m.group(1)
    txt = _whois_ask(net, server, query)
    m2 = re.search(r"Registrar WHOIS Server:\s*(?:whois://)?([\w.-]+)", txt, re.I)
    if m2 and m2.group(1).lower() != server.lower():
        try:
            txt += "\n" + _whois_ask(net, m2.group(1), query)
            server += " → " + m2.group(1)
        except Cancelled:
            raise
        except Exception:
            pass
    return server, txt


def whois_lines(txt: str, limit: int = 80) -> list[str]:
    skip = ("%", "#", ">>>", "NOTICE", "TERMS OF USE", "by the following", "URL of the ICANN")
    out = []
    for ln in txt.splitlines():
        s = ln.strip()
        if not s or s.startswith(skip) or ":" not in s:
            continue
        k, _, v = s.partition(":")
        if not v.strip():
            continue
        if s not in out:
            out.append(s)
        if len(out) >= limit:
            break
    return out


TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl", "waw.pl",
    "info.pl", "biz.pl", "com.au", "net.au", "org.au", "co.jp", "co.nz", "com.br", "com.cn", "com.tr",
    "co.za", "co.in", "com.mx", "com.ar", "com.ua", "co.il", "com.sg", "com.hk",
}


def clean_domain(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = "http://" + t
    host = urlparse(t).hostname or ""
    return host.lower().rstrip(".")


def registrable(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def ensure_url(target: str) -> str:
    t = target.strip()
    if "://" in t:
        return t
    return ("http://" if ".onion" in t.split("/")[0] else "https://") + t


def run_steps(net: Net, log, steps) -> dict:
    out = {}
    for label, enabled, fn in steps:
        if not enabled:
            continue
        net.check_cancel()
        log(f"[*] {label}…")
        try:
            out[label] = fn()
        except Cancelled:
            raise
        except Exception as e:
            out[label] = {"Błąd": short_error(e)}
            log(f"[!] {label}: {short_error(e)}")
    return out


def parallel(net: Net, fn, items, workers: int = 8):
    ex = cf.ThreadPoolExecutor(max_workers=workers)
    futs = {ex.submit(fn, it): it for it in items}
    pending = set(futs)
    try:
        while pending:
            done, pending = cf.wait(pending, timeout=0.4, return_when=cf.FIRST_COMPLETED)
            net.check_cancel()
            for f in done:
                try:
                    yield futs[f], f.result()
                except Cancelled:
                    raise
                except Exception as e:
                    yield futs[f], e
    except GeneratorExit:
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    except BaseException:
        net.stop_event.set()
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    ex.shutdown(wait=False)


def short_error(e: Exception) -> str:
    s = str(e)
    for pat, nice in (
        (r"SOCKS.*(?:Error connecting to SOCKS5 proxy|SOCKS.*(?:10061|refused))",
         "brak połączenia z proxy Tor — czy Tor jest uruchomiony?"),
        (r"SOCKS.*(?:0x0[1-6]: |Host unreachable|TTL expired|General SOCKS server failure)",
         "usługa nieosiągalna przez Tor (offline lub zły adres)"),
        (r"Failed to establish a new connection.*(?:10061|refused)", "połączenie odrzucone"),
        (r"(?:Read|Connect) ?timed out|timeout", "przekroczono czas oczekiwania"),
        (r"NameResolutionError|getaddrinfo failed|Name or service not known", "nie można rozwiązać nazwy hosta"),
        (r"CERTIFICATE_VERIFY_FAILED", "nieprawidłowy certyfikat TLS"),
        (r"Missing dependencies for SOCKS", "brak PySocks — pip install \"requests[socks]\""),
    ):
        if re.search(pat, s, re.I):
            return nice
    s = re.sub(r"\(Caused by .*", "", s).strip()
    return (s[:200] + "…") if len(s) > 200 else (s or type(e).__name__)
