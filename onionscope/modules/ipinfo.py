from __future__ import annotations

import ipaddress
import threading
import time

from ..common import dns, rdap_entities, run_steps
from ..net import Net

_EXIT_CACHE: dict = {"t": 0.0, "set": set()}
_EXIT_LOCK = threading.Lock()


def tor_exit_nodes(net: Net) -> set[str]:
    with _EXIT_LOCK:
        if time.time() - _EXIT_CACHE["t"] < 1800 and _EXIT_CACHE["set"]:
            return _EXIT_CACHE["set"]
        r = net.get("https://check.torproject.org/torbulkexitlist")
        r.raise_for_status()
        _EXIT_CACHE["set"] = {ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#")}
        _EXIT_CACHE["t"] = time.time()
        return _EXIT_CACHE["set"]


def _geo(net: Net, ip: str):
    try:
        j = net.get_json(f"https://ipinfo.io/{ip}/json")
        if not j.get("bogon"):
            return {k: v for k, v in {
                "Kraj": j.get("country"), "Region": j.get("region"), "Miasto": j.get("city"),
                "Współrzędne": j.get("loc"), "Organizacja / ASN": j.get("org"), "Strefa czasowa": j.get("timezone"),
                "Host": j.get("hostname"), "Źródło": "ipinfo.io",
            }.items() if v}
    except Exception:
        pass
    j = net.get_json(f"http://ip-api.com/json/{ip}",
                     params={"fields": "status,message,country,regionName,city,lat,lon,isp,org,as,proxy,hosting"})
    if j.get("status") != "success":
        raise RuntimeError(j.get("message", "brak danych"))
    return {
        "Kraj": j.get("country"), "Region": j.get("regionName"), "Miasto": j.get("city"),
        "Współrzędne": f"{j.get('lat')},{j.get('lon')}", "ISP": j.get("isp"), "Organizacja": j.get("org"),
        "ASN": j.get("as"), "Proxy/VPN": j.get("proxy"), "Hosting": j.get("hosting"), "Źródło": "ip-api.com",
    }


def _rdap(net: Net, ip: str):
    j = net.get_json(f"https://rdap.org/ip/{ip}")
    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in j.get("cidr0_cidrs", []) or []]
    return {k: v for k, v in {
        "Nazwa sieci": j.get("name"),
        "Uchwyt": j.get("handle"),
        "Zakres": f"{j.get('startAddress')} – {j.get('endAddress')}",
        "CIDR": cidrs or None,
        "Kraj": j.get("country"),
        "Typ": j.get("type"),
        "Właściciel": rdap_entities(j, "registrant") or None,
        "Abuse": rdap_entities(j, "abuse") or None,
    }.items() if v}


def _shodan(net: Net, ip: str):
    r = net.get(f"https://internetdb.shodan.io/{ip}")
    if r.status_code == 404:
        return "brak danych w Shodan InternetDB"
    r.raise_for_status()
    j = r.json()
    return {k: v for k, v in {
        "Otwarte porty": j.get("ports"), "Nazwy hostów": j.get("hostnames"), "Tagi": j.get("tags"),
        "CPE (oprogramowanie)": j.get("cpes"), "Podatności (CVE)": j.get("vulns"),
    }.items() if v} or "brak danych"


def run(net: Net, target: str, log=print, geo: bool = True, rdap: bool = True, shodan: bool = True,
        tor_exit: bool = True, **_):
    t = target.strip()
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        log(f"[*] „{t}” to nie IP — rozwiązuję nazwę…")
        recs = dns(net, t, "A") or dns(net, t, "AAAA")
        if not recs:
            raise ValueError(f"Nie można rozwiązać {t!r} na adres IP.")
        ip = ipaddress.ip_address(recs[0])
        log(f"[+] {t} → {ip}")
    ips = str(ip)
    out: dict = {"Adres IP": ips, "Wersja": f"IPv{ip.version}"}
    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
        out["Uwaga"] = "Adres prywatny/zarezerwowany — brak danych publicznych."
        return out

    def ptr():
        res = dns(net, ip.reverse_pointer, "PTR")
        return res or "brak rekordu PTR"

    def exitnode():
        return "TAK — to węzeł wyjściowy Tor" if ips in tor_exit_nodes(net) else "nie"

    out |= run_steps(net, log, [
        ("Reverse DNS (PTR)", True, ptr),
        ("Geolokalizacja", geo, lambda: _geo(net, ips)),
        ("Właściciel sieci (RDAP)", rdap, lambda: _rdap(net, ips)),
        ("Shodan InternetDB", shodan, lambda: _shodan(net, ips)),
        ("Węzeł wyjściowy Tor", tor_exit, exitnode),
    ])
    return out
