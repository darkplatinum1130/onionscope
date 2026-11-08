from __future__ import annotations

import html
import json
import os
import sys
from datetime import datetime

from . import APP_NAME, __version__

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
CYAN, GREEN, RED, YELLOW, MAGENTA = "\033[36m", "\033[32m", "\033[31m", "\033[33m", "\033[35m"


def enable_ansi() -> None:
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            for std in (-11, -12):
                h = k.GetStdHandle(std)
                mode = ctypes.c_uint32()
                if k.GetConsoleMode(h, ctypes.byref(mode)):
                    k.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass


def _c(s: str, code: str, color: bool) -> str:
    return f"{code}{s}{RESET}" if color else s


def _val(v, color: bool) -> str:
    if v is True:
        return _c("tak", GREEN, color)
    if v is False:
        return _c("nie", RED, color)
    if v is None:
        return _c("—", DIM, color)
    s = str(v)
    if s.startswith(("http://", "https://")) or s.endswith(".onion"):
        return _c(s, MAGENTA, color)
    if s.startswith(("BRAK", "NIEPRAWID", "błąd", "UWAGA", "TAK —")):
        return _c(s, YELLOW, color)
    return s


def format_text(data, color: bool = True, indent: int = 0) -> str:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            key = _c(str(k), CYAN + BOLD if indent == 0 else CYAN, color)
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{key}:")
                lines.append(format_text(v, color, indent + 1))
            else:
                lines.append(f"{pad}{key}: {_val(v if v != [] and v != {} else '—', color)}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                first = True
                for k, v in item.items():
                    bullet = "- " if first else "  "
                    first = False
                    if isinstance(v, (dict, list)) and v:
                        lines.append(f"{pad}{bullet}{_c(str(k), CYAN, color)}:")
                        lines.append(format_text(v, color, indent + 2))
                    else:
                        empty = isinstance(v, (dict, list))
                        lines.append(f"{pad}{bullet}{_c(str(k), CYAN, color)}: {_val(None if empty else v, color)}")
            else:
                lines.append(f"{pad}- {_val(item, color)}")
    else:
        lines.append(pad + _val(data, color))
    return "\n".join(l for l in lines if l)


def log_line(msg: str, color: bool) -> str:
    for prefix, code in (("[+]", GREEN), ("[!]", RED), ("[-]", DIM), ("[*]", CYAN), ("[i]", YELLOW)):
        if msg.startswith(prefix):
            return _c(prefix, code, color) + msg[len(prefix):]
    return msg


def make_entry(module_key: str, module_title: str, target, mode: str, data, seconds: float) -> dict:
    return {
        "modul": module_key,
        "nazwa_modulu": module_title,
        "cel": " ".join(target) if isinstance(target, list) else target,
        "tryb": mode,
        "czas": datetime.now().isoformat(timespec="seconds"),
        "trwanie_s": round(seconds, 1),
        "wynik": data,
    }


def save_report(entries: list[dict], path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in (".html", ".htm"):
        content = to_html(entries)
    else:
        content = json.dumps({"narzedzie": f"{APP_NAME} {__version__}", "wpisy": entries},
                             ensure_ascii=False, indent=2, default=str)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _h(v) -> str:
    if isinstance(v, dict):
        if not v:
            return '<span class="dim">—</span>'
        rows = "".join(f"<tr><th>{html.escape(str(k))}</th><td>{_h(x)}</td></tr>" for k, x in v.items())
        return f"<table>{rows}</table>"
    if isinstance(v, list):
        if not v:
            return '<span class="dim">—</span>'
        return "<ol>" + "".join(f"<li>{_h(x)}</li>" for x in v) + "</ol>"
    if v is True:
        return '<span class="ok">tak</span>'
    if v is False:
        return '<span class="bad">nie</span>'
    if v is None:
        return '<span class="dim">—</span>'
    s = str(v)
    if s.startswith(("http://", "https://")) and " " not in s:
        cls = ' class="onion"' if ".onion" in s else ""
        return f'<a href="{html.escape(s)}"{cls} rel="noreferrer noopener" target="_blank">{html.escape(s)}</a>'
    if s.startswith(("BRAK", "NIEPRAWID", "błąd", "UWAGA", "TAK —")):
        return f'<span class="warn">{html.escape(s)}</span>'
    return html.escape(s)


def to_html(entries: list[dict]) -> str:
    gen = datetime.now().strftime("%Y-%m-%d %H:%M")
    sections = []
    for i, e in enumerate(entries, 1):
        sections.append(f"""
<section>
  <header><span class="badge">{html.escape(e['nazwa_modulu'])}</span>
  <h2>{html.escape(str(e['cel'] or '—'))}</h2>
  <p class="meta">{html.escape(e['czas'])} · tryb: {html.escape(e['tryb'])} · {e['trwanie_s']} s</p></header>
  {_h(e['wynik'])}
</section>""")
    return f"""<!doctype html>
<html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Raport {APP_NAME}</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--dim:#6b7385;--line:#e3e6ec;--accent:#6d3fe0;--ok:#138a52;--bad:#c23b3b;--warn:#a86b00}}
@media (prefers-color-scheme:dark){{:root{{--bg:#121418;--card:#1a1d23;--fg:#d8dbe2;--dim:#8a90a0;--line:#2a2f39;--accent:#a684ff;--ok:#3ecf8e;--bad:#ff6b6b;--warn:#f0b44c}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px}}h1{{margin:0 0 4px;font-size:24px}}
.sub{{color:var(--dim);margin:0 0 24px}}section{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin:0 0 18px;overflow-x:auto}}
h2{{margin:6px 0 2px;font-size:18px;word-break:break-all}}.meta{{color:var(--dim);margin:0 0 12px;font-size:12px}}
.badge{{display:inline-block;background:var(--accent);color:#fff;border-radius:999px;padding:2px 10px;font-size:12px}}
table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;vertical-align:top;padding:5px 8px;border-top:1px solid var(--line)}}
th{{color:var(--dim);font-weight:600;width:28%;white-space:nowrap}}td{{word-break:break-word}}td table th{{width:auto}}
ol{{margin:0;padding-left:22px}}a{{color:var(--accent)}}a.onion{{font-family:Consolas,monospace}}
.ok{{color:var(--ok)}}.bad{{color:var(--bad)}}.warn{{color:var(--warn)}}.dim{{color:var(--dim)}}
</style></head><body><main>
<h1>Raport OSINT — {APP_NAME}</h1>
<p class="sub">Wygenerowano {gen} · wpisów: {len(entries)}</p>
{''.join(sections)}
</main></body></html>"""
