from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote

from ..common import parallel, short_error
from ..net import Net


@dataclass
class Site:
    name: str
    url: str
    kind: str = "status"
    marker: str = ""
    check: Callable | None = None
    profile: str = ""
    pattern: str = r"^[A-Za-z0-9_.-]{1,40}$"
    headers: dict | None = None
    cookies: dict | None = None


SUB = r"^[A-Za-z0-9-]{1,40}$"
BOT_UA = {"User-Agent": "OnionScope/1.0 (OSINT research tool)"}
YT_CONSENT = {"SOCS": "CAESEwgDEgk0ODE3Nzk3MjQaAmVuIAEaBgiA_LyaBg"}
CHALLENGE_RE = re.compile(r"<title>\s*(?:Client Challenge|Just a moment|Attention Required|Access denied|"
                          r"DDoS-Guard|Captcha)", re.I)

SITES: list[Site] = [
    Site("GitHub", "https://github.com/{}", pattern=r"^[A-Za-z0-9-]{1,39}$"),
    Site("GitLab", "https://gitlab.com/api/v4/users?username={}", "json", check=lambda j: len(j) > 0,
         profile="https://gitlab.com/{}"),
    Site("Codeberg", "https://codeberg.org/api/v1/users/{}", profile="https://codeberg.org/{}"),
    Site("Docker Hub", "https://hub.docker.com/v2/users/{}/", profile="https://hub.docker.com/u/{}"),
    Site("npm", "https://registry.npmjs.org/-/v1/search?text=maintainer:{}&size=1", "json",
         check=lambda j: j.get("total", 0) > 0, profile="https://www.npmjs.com/~{}"),
    Site("Hugging Face", "https://huggingface.co/api/users/{}/overview", profile="https://huggingface.co/{}"),
    Site("Dev.to", "https://dev.to/api/users/by_username?url={}", profile="https://dev.to/{}"),
    Site("Hacker News", "https://hacker-news.firebaseio.com/v0/user/{}.json", "json",
         check=lambda j: j is not None, profile="https://news.ycombinator.com/user?id={}"),
    Site("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "json",
         check=lambda j: bool(j.get("them")) and j["them"][0] is not None, profile="https://keybase.io/{}"),
    Site("Codewars", "https://www.codewars.com/api/v1/users/{}", profile="https://www.codewars.com/users/{}"),
    Site("Replit", "https://replit.com/@{}"),
    Site("Kaggle", "https://www.kaggle.com/{}"),
    Site("Scratch", "https://api.scratch.mit.edu/users/{}", profile="https://scratch.mit.edu/users/{}"),
    Site("Trello", "https://trello.com/1/Members/{}", profile="https://trello.com/u/{}"),
    Site("Pastebin", "https://pastebin.com/u/{}"),
    Site("Reddit", "https://www.reddit.com/user/{}/about.json", profile="https://www.reddit.com/user/{}"),
    Site("Telegram", "https://t.me/{}", "present", marker="tgme_page_title", pattern=r"^[A-Za-z0-9_]{5,32}$"),
    Site("Mastodon.social", "https://mastodon.social/api/v1/accounts/lookup?acct={}",
         profile="https://mastodon.social/@{}"),
    Site("Bluesky", "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social",
         profile="https://bsky.app/profile/{}.bsky.social", pattern=SUB),
    Site("YouTube", "https://www.youtube.com/@{}", cookies=YT_CONSENT),
    Site("Snapchat", "https://www.snapchat.com/add/{}"),
    Site("Linktree", "https://linktr.ee/{}"),
    Site("Disqus", "https://disqus.com/by/{}/"),
    Site("Gravatar", "https://en.gravatar.com/{}.json", profile="https://gravatar.com/{}"),
    Site("Wikipedia (EN)", "https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={}&format=json",
         "json", check=lambda j: not ({"missing", "invalid"} & set(j["query"]["users"][0])),
         profile="https://en.wikipedia.org/wiki/User:{}", headers=BOT_UA),
    Site("Wikipedia (PL)", "https://pl.wikipedia.org/w/api.php?action=query&list=users&ususers={}&format=json",
         "json", check=lambda j: not ({"missing", "invalid"} & set(j["query"]["users"][0])),
         profile="https://pl.wikipedia.org/wiki/Wikipedysta:{}", headers=BOT_UA),
    Site("SoundCloud", "https://soundcloud.com/{}"),
    Site("Vimeo", "https://vimeo.com/{}"),
    Site("Flickr", "https://www.flickr.com/people/{}"),
    Site("DeviantArt", "https://www.deviantart.com/{}"),
    Site("Dribbble", "https://dribbble.com/{}"),
    Site("Medium", "https://medium.com/feed/@{}", profile="https://medium.com/@{}"),
    Site("Blogger", "https://{}.blogspot.com/", pattern=SUB),
    Site("itch.io", "https://{}.itch.io/", pattern=SUB),
    Site("Wattpad", "https://www.wattpad.com/api/v3/users/{}", profile="https://www.wattpad.com/user/{}"),
    Site("Steam", "https://steamcommunity.com/id/{}", "absent", marker="The specified profile could not be found"),
    Site("Minecraft", "https://api.mojang.com/users/profiles/minecraft/{}", profile="https://namemc.com/profile/{}",
         pattern=r"^[A-Za-z0-9_]{3,16}$"),
    Site("Chess.com", "https://api.chess.com/pub/player/{}", profile="https://www.chess.com/member/{}"),
    Site("Lichess", "https://lichess.org/api/user/{}", profile="https://lichess.org/@/{}"),
    Site("Speedrun.com", "https://www.speedrun.com/api/v1/users/{}", profile="https://www.speedrun.com/users/{}"),
    Site("Duolingo", "https://www.duolingo.com/2017-06-30/users?username={}&fields=users", "json",
         check=lambda j: len(j.get("users", [])) > 0, profile="https://www.duolingo.com/profile/{}"),
]

BLOCK_CODES = {401, 403, 429, 503, 520, 521, 522, 523, 525}


def _check(net: Net, site: Site, name: str):
    url = site.url.format(quote(name, safe=""))
    headers = {"Accept": "application/json"} if site.kind == "json" else {}
    headers.update(site.headers or {})
    r = net.get(url, headers=headers, cookies=site.cookies, allow_redirects=True)
    code = r.status_code
    if code in BLOCK_CODES:
        return None, f"HTTP {code} (blokada / limit)"
    if site.kind != "json" and CHALLENGE_RE.search(r.text[:5000]):
        return None, "ochrona anty-bot (challenge)"
    if site.kind == "status":
        if code == 200:
            if name.lower() not in r.url.lower():
                return False, "przekierowanie"
            return True, ""
        if code in (404, 410, 400):
            return False, ""
        return None, f"HTTP {code}"
    if site.kind in ("absent", "present"):
        if code == 404:
            return False, ""
        has = site.marker in r.text
        return (not has if site.kind == "absent" else has), ""
    if site.kind == "json":
        if code in (404, 400):
            return False, ""
        try:
            return bool(site.check(r.json())), ""
        except ValueError:
            return None, "niepoprawna odpowiedź JSON"
    return None, "nieznany typ"


def run(net: Net, target: str, log=print, only_found: bool = False, **_):
    name = target.strip().lstrip("@")
    if not name:
        raise ValueError("Podaj nazwę użytkownika.")
    sites = [s for s in SITES if re.match(s.pattern, name)]
    skipped = [s.name for s in SITES if s not in sites]
    log(f"[*] Sprawdzam „{name}” w {len(sites)} serwisach ({net.mode})…")

    found, unsure, missing = {}, {}, []
    workers = 8 if net.use_tor else 16
    for site, res in parallel(net, lambda s: _check(net, s, name), sites, workers=workers):
        if isinstance(res, Exception):
            unsure[site.name] = short_error(res)
            continue
        ok, note = res
        if ok:
            link = (site.profile or site.url).format(quote(name, safe=""))
            found[site.name] = link
            log(f"[+] {site.name}: {link}")
        elif ok is None:
            unsure[site.name] = note
        else:
            missing.append(site.name)

    out = {
        "Nazwa": name,
        "Podsumowanie": f"znaleziono {len(found)} • niepewne {len(unsure)} • brak {len(missing)} • "
                        f"sprawdzono {len(sites)} serwisów",
        "Znalezione": dict(sorted(found.items())),
    }
    if not only_found:
        out["Niepewne (blokada / błąd)"] = dict(sorted(unsure.items()))
        out["Nie znaleziono"] = sorted(missing)
        if skipped:
            out["Pominięte (nazwa niedozwolona w serwisie)"] = skipped
    if net.use_tor and len(unsure) > len(sites) // 3:
        out["Wskazówka"] = ("Część serwisów blokuje węzły wyjściowe Tora. Spróbuj „Nowej tożsamości” "
                            "albo sprawdź niepewne serwisy w trybie clearnet.")
    return out
