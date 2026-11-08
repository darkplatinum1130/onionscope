from __future__ import annotations

from ..common import short_error
from ..net import TOR_CONTROL_PORTS, TOR_SOCKS_PORTS, Cancelled, Net, port_open


def run(net: Net, target=None, log=print, **_):
    out = {"Tryb": net.mode}
    host = net.tor_host
    log("[*] Szukam lokalnego Tora…")
    out["Lokalny Tor"] = {
        f"SOCKS {p}": ("otwarty" if port_open(host, p) else "zamknięty") for p in TOR_SOCKS_PORTS
    } | {
        f"Kontrolny {p}": ("otwarty" if port_open(host, p) else "zamknięty") for p in TOR_CONTROL_PORTS
    }
    log("[*] Pytam check.torproject.org…")
    try:
        j = net.get_json("https://check.torproject.org/api/ip")
        out["Ruch przez Tor"] = bool(j.get("IsTor"))
        out["Widoczny adres IP"] = j.get("IP")
        if net.use_tor and not j.get("IsTor"):
            out["UWAGA"] = "Tryb Tor jest włączony, ale ruch NIE wychodzi przez sieć Tor!"
        log(f"[+] IsTor={j.get('IsTor')} IP={j.get('IP')}")
    except Cancelled:
        raise
    except Exception as e:
        out["check.torproject.org"] = "błąd: " + short_error(e)
        log(f"[!] {short_error(e)}")
    if out.get("Widoczny adres IP"):
        try:
            g = net.get_json(f"https://ipinfo.io/{out['Widoczny adres IP']}/json")
            out["Lokalizacja wyjścia"] = ", ".join(x for x in (g.get("city"), g.get("country"), g.get("org")) if x)
        except Cancelled:
            raise
        except Exception:
            pass
    return out
