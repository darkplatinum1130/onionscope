from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from . import crawler, domain, email, ipinfo, onion, search, torcheck, username


@dataclass
class Opt:
    name: str
    label: str
    kind: str = "bool"
    default: Any = True
    choices: tuple = ()
    minv: int = 0
    maxv: int = 1000
    help: str = ""


@dataclass
class Module:
    key: str
    title: str
    func: Callable
    description: str
    target: str | None = None
    example: str = ""
    multi: bool = False
    opts: list[Opt] = field(default_factory=list)


MODULES: list[Module] = [
    Module("user", "Nazwa użytkownika", username.run,
           "Szuka publicznych profili o danej nazwie w ~40 serwisach (kod, społecznościowe, gry, media).",
           target="Nazwa użytkownika", example="torvalds",
           opts=[Opt("only_found", "Pokaż tylko znalezione", default=False)]),
    Module("domain", "Domena / strona", domain.run,
           "DNS, właściciel (RDAP/WHOIS), nagłówki i technologie, certyfikat TLS, subdomeny z CT, "
           "archiwum Wayback. Dla .onion — analiza HTTP przez Tor.",
           target="Domena lub URL", example="example.com",
           opts=[Opt("dns_records", "DNS"), Opt("whois", "RDAP / WHOIS"), Opt("http", "HTTP + technologie"),
                 Opt("tls", "Certyfikat TLS"), Opt("subdomains", "Subdomeny (crt.sh, wolne)", default=False),
                 Opt("wayback", "Wayback Machine")]),
    Module("ip", "Adres IP", ipinfo.run,
           "Reverse DNS, geolokalizacja, właściciel sieci (RDAP), otwarte porty i CVE (Shodan InternetDB), "
           "czy to węzeł wyjściowy Tor.",
           target="Adres IP lub host", example="1.1.1.1",
           opts=[Opt("geo", "Geolokalizacja"), Opt("rdap", "RDAP"), Opt("shodan", "Shodan InternetDB"),
                 Opt("tor_exit", "Lista węzłów Tor")]),
    Module("email", "Adres e-mail", email.run,
           "Rekordy MX/SPF/DMARC, dostawca poczty, skrzynki jednorazowe, Gravatar, klucze PGP na serwerach kluczy.",
           target="Adres e-mail", example="someone@example.com",
           opts=[Opt("gravatar", "Gravatar"), Opt("pgp", "Serwery kluczy PGP")]),
    Module("search", "Wyszukiwarka (web + .onion)", search.run,
           "Ahmia — indeks usług ukrytych Tor; Bing / DuckDuckGo — clearnet. Wyniki .onion otworzysz crawlerem "
           "w trybie Tor.",
           target="Zapytanie", example="ransomware leak site",
           opts=[Opt("engine", "Wyszukiwarka", "choice", "auto", ("auto", "ahmia", "bing", "ddg", "wszystkie"),
                     help="auto = Ahmia + Bing"),
                 Opt("limit", "Limit wyników", "int", 30, minv=1, maxv=200)]),
    Module("crawl", "Crawler (web + .onion)", crawler.run,
           "Przechodzi po stronach (także .onion w trybie Tor) i zbiera e-maile, adresy .onion, portfele BTC/XMR/ETH, "
           "klucze PGP, kontakty (Telegram, Discord, Session, XMPP…).",
           target="URL startowy", example="https://example.com",
           opts=[Opt("depth", "Głębokość", "int", 1, minv=0, maxv=5),
                 Opt("max_pages", "Maks. stron", "int", 25, minv=1, maxv=500),
                 Opt("external", "Wchodź na inne domeny", default=False)]),
    Module("onion", "Status usług .onion", onion.run,
           "Sprawdza poprawność adresów v3 (suma kontrolna) i czy usługi odpowiadają przez Tor. "
           "Można podać wiele adresów oddzielonych spacją.",
           target="Adresy .onion", example="duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
           multi=True),
    Module("torcheck", "Test połączenia / Tor", torcheck.run,
           "Pokazuje, czy ruch faktycznie idzie przez Tor, widoczny adres IP i stan lokalnych portów Tora."),
]

BY_KEY = {m.key: m for m in MODULES}
