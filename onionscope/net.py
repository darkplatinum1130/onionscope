from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import socket
import threading
from urllib.parse import urlparse

import requests

try:
    import socks
except ImportError:
    socks = None

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
TOR_SOCKS_PORTS = (9050, 9150)
TOR_CONTROL_PORTS = (9051, 9151)


class Cancelled(Exception):
    pass


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def detect_tor_port(host: str = "127.0.0.1") -> int:
    for p in TOR_SOCKS_PORTS:
        if port_open(host, p):
            return p
    return 0


def is_onion(url_or_host: str) -> bool:
    host = urlparse(url_or_host).hostname if "://" in url_or_host else url_or_host
    return bool(host) and host.lower().rstrip(".").endswith(".onion")


class Net:
    def __init__(self, use_tor: bool = False, tor_host: str = "127.0.0.1", tor_port: int = 0,
                 timeout: float = 25, user_agent: str = DEFAULT_UA,
                 stop_event: threading.Event | None = None):
        self.use_tor = use_tor
        self.tor_host = tor_host
        self.tor_port = tor_port or (detect_tor_port(tor_host) if use_tor else 0) or 9050
        self.timeout = max(timeout, 40) if use_tor else timeout
        self.user_agent = user_agent
        self.stop_event = stop_event or threading.Event()
        self._local = threading.local()
        if use_tor and socks is None:
            raise RuntimeError("Brak modułu PySocks. Zainstaluj: pip install \"requests[socks]\"")

    @property
    def mode(self) -> str:
        return f"Tor ({self.tor_host}:{self.tor_port})" if self.use_tor else "Clearnet"

    def check_cancel(self):
        if self.stop_event.is_set():
            raise Cancelled("Przerwano")

    def session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update({
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            })
            if self.use_tor:
                proxy = f"socks5h://{self.tor_host}:{self.tor_port}"
                s.proxies = {"http": proxy, "https": proxy}
                s.trust_env = False
            self._local.session = s
        return s

    def request(self, method: str, url: str, **kw) -> requests.Response:
        self.check_cancel()
        if is_onion(url) and not self.use_tor:
            raise RuntimeError("Adres .onion wymaga trybu Tor (opcja --tor / przełącznik „Przez Tor”).")
        kw.setdefault("timeout", self.timeout)
        if is_onion(url):
            kw["timeout"] = max(kw["timeout"], 60)
        return self.session().request(method, url, **kw)

    def get(self, url: str, **kw) -> requests.Response:
        return self.request("GET", url, **kw)

    def get_json(self, url: str, **kw):
        r = self.get(url, **kw)
        r.raise_for_status()
        return r.json()

    def fetch(self, url: str, max_bytes: int = 3_000_000, **kw):
        r = self.request("GET", url, stream=True, **kw)
        chunks, size = [], 0
        try:
            for chunk in r.iter_content(65536):
                self.check_cancel()
                chunks.append(chunk)
                size += len(chunk)
                if size >= max_bytes:
                    break
        finally:
            r.close()
        raw = b"".join(chunks)
        enc = None
        m = re.search(r"charset=([\w-]+)", r.headers.get("Content-Type", ""), re.I)
        if m:
            enc = m.group(1)
        else:
            m = re.search(rb"<meta[^>]+charset=[\"']?([\w-]+)", raw[:4096], re.I)
            if m:
                enc = m.group(1).decode("ascii", "ignore")
        try:
            text = raw.decode(enc or "utf-8", errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        r._content = raw
        return r, text

    def connect(self, host: str, port: int, timeout: float | None = None) -> socket.socket:
        self.check_cancel()
        t = timeout or self.timeout
        if self.use_tor:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, self.tor_host, self.tor_port, rdns=True)
            s.settimeout(t)
            s.connect((host, port))
            return s
        if host.endswith(".onion"):
            raise RuntimeError("Adres .onion wymaga trybu Tor.")
        return socket.create_connection((host, port), timeout=t)


def _ctl_read(sock: socket.socket) -> list[str]:
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        lines = buf.decode("utf-8", "replace").split("\r\n")
        for ln in lines:
            if re.match(r"^\d{3} ", ln):
                return [l for l in lines if l]
    return [l for l in buf.decode("utf-8", "replace").split("\r\n") if l]


def _ctl_cmd(sock: socket.socket, cmd: str) -> list[str]:
    sock.sendall(cmd.encode() + b"\r\n")
    return _ctl_read(sock)


def tor_new_identity(host: str = "127.0.0.1", control_port: int = 0, password: str | None = None) -> str:
    ports = [control_port] if control_port else list(TOR_CONTROL_PORTS)
    errors = []
    for port in ports:
        try:
            sock = socket.create_connection((host, port), timeout=6)
        except OSError as e:
            errors.append(f"{port}: {e.strerror or e}")
            continue
        with sock:
            info = " ".join(_ctl_cmd(sock, "PROTOCOLINFO 1"))
            methods = (re.search(r"METHODS=([\w,]+)", info) or [None, ""])[1].split(",")
            cookie_file = re.search(r'COOKIEFILE="((?:[^"\\]|\\.)*)"', info)
            cookie_path = cookie_file.group(1).replace("\\\\", "\\").replace('\\"', '"') if cookie_file else None

            if password is not None and "HASHEDPASSWORD" in methods:
                auth = 'AUTHENTICATE "%s"' % password.replace("\\", "\\\\").replace('"', '\\"')
            elif "NULL" in methods:
                auth = "AUTHENTICATE"
            elif cookie_path and os.path.exists(cookie_path) and ("COOKIE" in methods or "SAFECOOKIE" in methods):
                cookie = open(cookie_path, "rb").read()
                if "COOKIE" in methods:
                    auth = "AUTHENTICATE " + binascii.hexlify(cookie).decode()
                else:
                    client_nonce = os.urandom(32)
                    resp = " ".join(_ctl_cmd(sock, "AUTHCHALLENGE SAFECOOKIE " + client_nonce.hex()))
                    m = re.search(r"SERVERNONCE=([0-9A-Fa-f]+)", resp)
                    if not m:
                        errors.append(f"{port}: AUTHCHALLENGE nieudane: {resp}")
                        continue
                    server_nonce = bytes.fromhex(m.group(1))
                    digest = hmac.new(b"Tor safe cookie authentication controller-to-server hash",
                                      cookie + client_nonce + server_nonce, hashlib.sha256).hexdigest()
                    auth = "AUTHENTICATE " + digest
            elif "HASHEDPASSWORD" in methods:
                errors.append(f"{port}: wymagane hasło portu kontrolnego (--password)")
                continue
            else:
                errors.append(f"{port}: brak obsługiwanej metody uwierzytelnienia ({','.join(methods)})")
                continue

            resp = _ctl_cmd(sock, auth)
            if not resp or not resp[-1].startswith("250"):
                errors.append(f"{port}: uwierzytelnienie odrzucone: {' '.join(resp)}")
                continue
            resp = _ctl_cmd(sock, "SIGNAL NEWNYM")
            if resp and resp[-1].startswith("250"):
                return f"Nowa tożsamość Tor ustawiona (port kontrolny {port}). Nowe połączenia użyją nowych obwodów."
            errors.append(f"{port}: {' '.join(resp)}")
    raise RuntimeError("Nie udało się zmienić tożsamości Tor — " + "; ".join(errors) +
                       ". Port kontrolny: Tor Browser = 9151, usługa tor = 9051 (ControlPort w torrc).")


def b32_onion_ok(addr: str) -> bool:
    a = addr.lower().strip().removesuffix(".onion")
    if len(a) != 56:
        return False
    try:
        raw = base64.b32decode(a.upper())
    except (binascii.Error, ValueError):
        return False
    pub, chk, ver = raw[:32], raw[32:34], raw[34:]
    if ver != b"\x03":
        return False
    return hashlib.sha3_256(b".onion checksum" + pub + ver).digest()[:2] == chk
