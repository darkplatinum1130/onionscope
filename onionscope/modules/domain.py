from __future__ import annotations

import os
import re
import ssl
import tempfile

from ..common import (dns, parallel, rdap_entities, rdap_events, registrable, run_steps, clean_domain,
                      short_error, whois_lines, whois_query)
from ..extract import extract_all, parse_html
from ..net import Cancelled, Net

SEC_HEADERS = ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
               "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy")

TECH = [
    ("Cloudflare", "header", "cf-ray"), ("Cloudflare", "header", "server=cloudflare"),
    ("Akamai", "header", "x-akamai-transformed"), ("Fastly", "header", "x-served-by=cache-"),
    ("Varnish", "header", "x-varnish"), ("Amazon CloudFront", "header", "x-amz-cf-id"),
    ("Amazon S3", "header", "x-amz-request-id"), ("Vercel", "header", "x-vercel-id"),
    ("Netlify", "header", "x-nf-request-id"), ("GitHub Pages", "header", "server=github\\.com"),
    ("nginx", "header", "server=nginx"), ("Apache", "header", "server=apache"),
    ("Microsoft IIS", "header", "server=iis"), ("LiteSpeed", "header", "server=litespeed"),
    ("OpenResty", "header", "server=openresty"), ("Caddy", "header", "server=caddy"),
    ("PHP", "header", "x-powered-by=php"), ("ASP.NET", "header", "x-aspnet-version"),
    ("ASP.NET", "header", "x-powered-by=asp\\.net"), ("Express", "header", "x-powered-by=express"),
    ("Next.js", "header", "x-powered-by=next\\.js"),
    ("PHP", "cookie", "phpsessid"), ("Laravel", "cookie", "laravel_session"), ("Django", "cookie", "csrftoken"),
    ("ASP.NET", "cookie", "asp.net_sessionid"), ("Java", "cookie", "jsessionid"),
    ("WordPress", "body", r"/wp-content/|/wp-includes/"), ("Joomla", "body", r"/media/jui/|Joomla!"),
    ("Drupal", "body", r"Drupal\.settings|/sites/default/files/"), ("Shopify", "body", r"cdn\.shopify\.com"),
    ("Wix", "body", r"static\.wixstatic\.com"), ("Squarespace", "body", r"static1\.squarespace\.com"),
    ("PrestaShop", "body", r"prestashop"), ("Magento", "body", r"Mage\.Cookies|/static/version\d+/"),
    ("Next.js", "body", r"__NEXT_DATA__|/_next/static/"), ("Nuxt", "body", r"__NUXT__|/_nuxt/"),
    ("React", "body", r"data-reactroot|react-dom"), ("Vue.js", "body", r"data-v-[0-9a-f]{8}|vue(?:\.min)?\.js"),
    ("Angular", "body", r"ng-version="), ("Svelte", "body", r"class=\"[^\"]*svelte-[a-z0-9]{6}"),
    ("jQuery", "body", r"jquery[.-]?(?:\d[\d.]*)?(?:\.min)?\.js"),
    ("Bootstrap", "body", r"bootstrap(?:\.min)?\.(?:css|js)"), ("Tailwind CSS", "body", r"tailwind"),
    ("Google Analytics", "body", r"google-analytics\.com|gtag\("),
    ("Google Tag Manager", "body", r"googletagmanager\.com/gtm\.js"),
    ("Facebook Pixel", "body", r"connect\.facebook\.net/[^\"']+/fbevents\.js"),
    ("Hotjar", "body", r"static\.hotjar\.com"), ("reCAPTCHA", "body", r"google\.com/recaptcha"),
    ("hCaptcha", "body", r"hcaptcha\.com"), ("Cloudflare Turnstile", "body", r"challenges\.cloudflare\.com/turnstile"),
    ("Font Awesome", "body", r"font-?awesome"), ("Google Fonts", "body", r"fonts\.googleapis\.com"),
]


def fingerprint(r, body: str) -> list[str]:
    h = {k.lower(): v for k, v in r.headers.items()}
    cookies = (" ".join(r.cookies.keys()) + " " + h.get("set-cookie", "")).lower()
    found: list[str] = []
    for name, where, pat in TECH:
        hit = False
        if where == "header":
            hn, _, rx = pat.partition("=")
            hit = hn in h and (not rx or re.search(rx, h[hn], re.I) is not None)
        elif where == "cookie":
            hit = pat in cookies
        elif where == "body":
            hit = re.search(pat, body, re.I) is not None
        if hit and name not in found:
            found.append(name)
    return found


def _dns(net: Net, domain: str):
    types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
    jobs = [(t, domain) for t in types] + [("TXT", "_dmarc." + domain)]
    out = {}
    for (t, name), res in parallel(net, lambda j: dns(net, j[1], j[0]), jobs, workers=5):
        key = "DMARC" if name.startswith("_dmarc.") else t
        if isinstance(res, Exception):
            out[key] = "błąd: " + short_error(res)
        elif res:
            out[key] = res if len(res) > 1 else res[0]
    order = types + ["DMARC"]
    out = {k: out[k] for k in order if k in out}
    txt = out.get("TXT", [])
    txt = [txt] if isinstance(txt, str) else txt
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if spf:
        out["SPF"] = spf[0]
    verif = [t.split("=")[0] for t in txt if re.match(r"^[\w.-]+-(?:site-)?verification=", t, re.I)]
    if verif:
        out["Weryfikacje usług (TXT)"] = sorted(set(verif))
    return out or "brak rekordów"


def _whois(net: Net, domain: str, log):
    reg = registrable(domain)
    try:
        j = net.get_json(f"https://rdap.org/domain/{reg}")
        ev = rdap_events(j)
        out = {
            "Źródło": "RDAP",
            "Domena": j.get("ldhName", reg).lower(),
            "Rejestrator": ", ".join(rdap_entities(j, "registrar")) or "—",
            "Utworzona": ev.get("registration", "—"),
            "Wygasa": ev.get("expiration", "—"),
            "Ostatnia zmiana": ev.get("last changed", "—"),
            "Status": j.get("status", []),
            "Serwery NS": [ns.get("ldhName", "").lower() for ns in j.get("nameservers", []) or []],
            "DNSSEC": (j.get("secureDNS") or {}).get("delegationSigned", "—"),
        }
        reg_ent = rdap_entities(j, "registrant")
        if reg_ent:
            out["Właściciel"] = reg_ent
        abuse = [v for e in j.get("entities", []) for v in _abuse_emails(e)]
        if abuse:
            out["Kontakt abuse"] = sorted(set(abuse))
        return out
    except Cancelled:
        raise
    except Exception as e:
        log(f"[i] RDAP niedostępne ({short_error(e)}) — próbuję klasycznego WHOIS…")
    server, txt = whois_query(net, reg)
    return {"Źródło": f"WHOIS ({server})", "Dane": whois_lines(txt)}


def _abuse_emails(entity: dict):
    if "abuse" in (entity.get("roles") or []):
        for item in (entity.get("vcardArray") or [None, []])[1]:
            if item[0] == "email":
                yield item[3]
    for sub in entity.get("entities", []) or []:
        yield from _abuse_emails(sub)


def _http(net: Net, domain: str):
    last = None
    for scheme in ("https", "http"):
        try:
            r, body = net.fetch(f"{scheme}://{domain}/", allow_redirects=True)
            break
        except Cancelled:
            raise
        except Exception as e:
            last = e
    else:
        raise RuntimeError(short_error(last))
    page = parse_html(body, r.url)
    out = {
        "Status HTTP": r.status_code,
        "Końcowy URL": r.url,
    }
    if r.history:
        out["Przekierowania"] = [f"{h.status_code} {h.url}" for h in r.history] + [f"{r.status_code} {r.url}"]
    out["Tytuł strony"] = page["title"] or "—"
    for key, label in (("description", "Opis (meta)"), ("generator", "Generator (meta)")):
        if page["meta"].get(key):
            out[label] = page["meta"][key][:300]
    onion_loc = r.headers.get("Onion-Location") or page["meta"].get("onion-location")
    if onion_loc:
        out["Onion-Location (mirror w Tor)"] = onion_loc
    out["Technologie"] = fingerprint(r, body) or ["nie rozpoznano"]
    out["Nagłówki bezpieczeństwa"] = {h: ("obecny" if h in r.headers else "BRAK") for h in SEC_HEADERS}
    out["Nagłówki odpowiedzi"] = dict(r.headers)
    artefacts = extract_all(body)
    if artefacts:
        out["Artefakty na stronie głównej"] = artefacts
    ext = sorted({l.split("/")[2] for l in page["links"] if domain not in l.split("/")[2]})
    if ext:
        out["Domeny zewnętrzne w linkach"] = ext[:60]

    files = {}
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/humans.txt"):
        try:
            rr, txt = net.fetch(f"{r.url.split('/')[0]}//{r.url.split('/')[2]}{path}", max_bytes=200_000,
                                allow_redirects=False)
            if rr.status_code == 200 and txt.strip() and "<html" not in txt[:500].lower():
                if path == "/robots.txt":
                    files[path] = [l.strip() for l in txt.splitlines()
                                   if re.match(r"^\s*(dis)?allow|^\s*sitemap", l, re.I)][:40] or "pusty"
                elif path == "/sitemap.xml":
                    files[path] = f"istnieje ({len(re.findall(r'<loc>', txt))} wpisów <loc>)"
                else:
                    files[path] = [l for l in txt.splitlines() if l.strip() and not l.startswith("#")][:15]
            else:
                files[path] = f"brak (HTTP {rr.status_code})"
        except Cancelled:
            raise
        except Exception as e:
            files[path] = "błąd: " + short_error(e)
    out["Pliki"] = files
    return out


def _decode_der(der: bytes) -> dict:
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        return ssl._ssl._test_decode_cert(path)
    except Exception:
        return {}
    finally:
        os.unlink(path)


def _tls(net: Net, domain: str):
    try:
        import certifi
        cafile = certifi.where()
    except ImportError:
        cafile = None
    ctx = ssl.create_default_context(cafile=cafile)
    raw = net.connect(domain, 443, timeout=min(net.timeout, 25))
    verdict = "poprawny"
    try:
        s = ctx.wrap_socket(raw, server_hostname=domain)
    except ssl.SSLCertVerificationError as e:
        raw.close()
        verdict = f"NIEPOPRAWNY: {e.verify_message}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(net.connect(domain, 443, timeout=min(net.timeout, 25)), server_hostname=domain)
    with s:
        cert = s.getpeercert() or _decode_der(s.getpeercert(binary_form=True) or b"")
        version, cipher = s.version(), s.cipher()

    def flat(seq):
        return ", ".join(f"{k}={v}" for rdn in seq for k, v in rdn)

    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    return {
        "Weryfikacja": verdict,
        "Podmiot": flat(cert.get("subject", [])),
        "Wystawca": flat(cert.get("issuer", [])),
        "Ważny od": cert.get("notBefore"),
        "Ważny do": cert.get("notAfter"),
        "Protokół": version,
        "Szyfr": cipher[0] if cipher else "—",
        f"Nazwy w certyfikacie (SAN: {len(sans)})": sans[:150],
    }


def _subdomains(net: Net, domain: str, log):
    reg = registrable(domain)
    names: set[str] = set()
    try:
        r = net.get("https://crt.sh/", params={"q": f"%.{reg}", "output": "json"}, timeout=max(net.timeout, 60))
        r.raise_for_status()
        for e in r.json():
            for n in e.get("name_value", "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(reg):
                    names.add(n)
        src = "crt.sh"
    except Cancelled:
        raise
    except Exception as e:
        log(f"[i] crt.sh nie odpowiada ({short_error(e)}) — próbuję CertSpotter…")
        j = net.get_json("https://api.certspotter.com/v1/issuances",
                         params={"domain": reg, "include_subdomains": "true", "expand": "dns_names"})
        for it in j:
            for n in it.get("dns_names", []):
                n = n.lower().lstrip("*.")
                if n.endswith(reg):
                    names.add(n)
        src = "CertSpotter"
    lst = sorted(names)
    log(f"[+] {len(lst)} subdomen z {src}")
    return {"Źródło": f"{src} (Certificate Transparency)", "Liczba": len(lst), "Subdomeny": lst[:1000]}


def _wayback(net: Net, domain: str):
    out = {}
    j = net.get_json("https://archive.org/wayback/available", params={"url": domain})
    snap = (j.get("archived_snapshots") or {}).get("closest")
    if snap:
        out["Najnowsza kopia"] = snap.get("url")
        out["Data najnowszej"] = _ts(snap.get("timestamp", ""))
    rows = net.get_json("https://web.archive.org/cdx/search/cdx",
                        params={"url": domain, "limit": 1, "output": "json", "fl": "timestamp,original"})
    if len(rows) > 1:
        out["Pierwsza kopia"] = _ts(rows[1][0])
        out["Link do pierwszej"] = f"https://web.archive.org/web/{rows[1][0]}/{rows[1][1]}"
    out["Wszystkie kopie"] = f"https://web.archive.org/web/*/{domain}*"
    return out if len(out) > 1 else "brak kopii w archiwum"


def _ts(ts: str) -> str:
    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts


def run(net: Net, target: str, log=print, dns_records: bool = True, whois: bool = True, http: bool = True,
        tls: bool = True, subdomains: bool = False, wayback: bool = True, **_):
    domain = clean_domain(target)
    if not domain or "." not in domain:
        raise ValueError(f"Niepoprawna domena: {target!r}")
    out = {"Domena": domain}
    if domain.endswith(".onion"):
        out["Uwaga"] = "Adres .onion — wykonuję tylko analizę HTTP (DNS/WHOIS/TLS/CT nie dotyczą sieci Tor)."
        dns_records = whois = tls = subdomains = wayback = False
        http = True
    out |= run_steps(net, log, [
        ("DNS", dns_records, lambda: _dns(net, domain)),
        ("Rejestracja (RDAP / WHOIS)", whois, lambda: _whois(net, domain, log)),
        ("HTTP i technologie", http, lambda: _http(net, domain)),
        ("Certyfikat TLS", tls, lambda: _tls(net, domain)),
        ("Subdomeny (CT)", subdomains, lambda: _subdomains(net, domain, log)),
        ("Wayback Machine", wayback, lambda: _wayback(net, domain)),
    ])
    return out
