from __future__ import annotations

import json
import queue
import re
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
import tkinter.font as tkfont

from . import APP_NAME, __version__
from .common import short_error
from .modules import BY_KEY, MODULES, Module
from .net import Cancelled, Net, detect_tor_port, tor_new_identity
from .report import make_entry, save_report

C = {
    "bg": "#121418", "panel": "#1a1d23", "panel2": "#242832", "line": "#2c313c", "fg": "#d8dbe2",
    "dim": "#8a90a0", "accent": "#9b6dff", "accent2": "#7c4dff", "ok": "#3ecf8e", "err": "#ff6b6b",
    "warn": "#f0b44c", "sel": "#3a2d6b", "link": "#b79bff",
}
URL_RE = re.compile(r"^(?:https?://\S+|[a-z2-7]{56}\.onion\S*)$", re.I)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {__version__} — OSINT: clearnet + Tor")
        self.geometry("1320x820")
        self.minsize(1000, 620)
        self.configure(bg=C["bg"])

        self.q: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.results: list[dict] = []
        self.node_entry: dict[str, dict] = {}
        self.opt_vars: dict[str, tuple] = {}
        self.current: Module = MODULES[0]
        self.t_start = 0.0

        self.var_tor = tk.BooleanVar(value=False)
        self.var_host = tk.StringVar(value="127.0.0.1")
        self.var_port = tk.StringVar(value="auto")
        self.var_target = tk.StringVar()
        self.var_status = tk.StringVar(value="Gotowy.")

        self._fonts()
        self._style()
        self._build()
        self._select_module(MODULES[0].key)
        self._update_mode_label()
        self.after(80, self._poll)

    def _fonts(self):
        base = "Segoe UI" if sys.platform == "win32" else "TkDefaultFont"
        self.f_ui = tkfont.Font(family=base, size=10)
        self.f_bold = tkfont.Font(family=base, size=10, weight="bold")
        self.f_h1 = tkfont.Font(family=base, size=15, weight="bold")
        self.f_small = tkfont.Font(family=base, size=9)
        self.f_mono = tkfont.Font(family="Consolas" if sys.platform == "win32" else "Monospace", size=10)

    def _style(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        rowh = self.f_ui.metrics("linespace") + 10
        st.configure(".", background=C["bg"], foreground=C["fg"], fieldbackground=C["panel2"],
                     bordercolor=C["line"], lightcolor=C["panel2"], darkcolor=C["panel2"], troughcolor=C["panel"],
                     focuscolor=C["accent"], font=self.f_ui, insertcolor=C["fg"], selectbackground=C["sel"],
                     selectforeground="#ffffff")
        st.configure("TFrame", background=C["bg"])
        st.configure("Panel.TFrame", background=C["panel"])
        st.configure("TLabel", background=C["bg"], foreground=C["fg"])
        st.configure("Panel.TLabel", background=C["panel"])
        st.configure("Dim.TLabel", foreground=C["dim"])
        st.configure("PanelDim.TLabel", background=C["panel"], foreground=C["dim"], font=self.f_small)
        st.configure("H1.TLabel", font=self.f_h1)
        st.configure("Logo.TLabel", background=C["panel"], foreground=C["accent"], font=self.f_h1)
        st.configure("TButton", background=C["panel2"], foreground=C["fg"], padding=(12, 6), borderwidth=0,
                     focusthickness=0)
        st.map("TButton", background=[("disabled", C["panel"]), ("active", "#303542")],
               foreground=[("disabled", C["dim"])])
        st.configure("Accent.TButton", background=C["accent2"], foreground="#ffffff", font=self.f_bold)
        st.map("Accent.TButton", background=[("disabled", C["panel2"]), ("active", C["accent"])])
        st.configure("Danger.TButton", background="#4a2328", foreground="#ffd5d5")
        st.map("Danger.TButton", background=[("disabled", C["panel"]), ("active", "#6b2c33")])
        for name, bg in (("TCheckbutton", C["bg"]), ("Panel.TCheckbutton", C["panel"])):
            st.configure(name, background=bg, foreground=C["fg"], indicatorbackground=C["panel2"],
                         indicatorforeground=C["accent"], focusthickness=0)
            st.map(name, background=[("active", bg)], indicatorbackground=[("selected", C["accent2"])],
                   indicatorforeground=[("selected", "#ffffff")])
        st.configure("Tor.TCheckbutton", background=C["panel"], foreground=C["fg"], font=self.f_bold,
                     indicatorbackground=C["panel2"], focusthickness=0)
        st.map("Tor.TCheckbutton", background=[("active", C["panel"])],
               indicatorbackground=[("selected", C["ok"])], indicatorforeground=[("selected", "#0b2b1d")])
        st.configure("TEntry", fieldbackground=C["panel2"], foreground=C["fg"], padding=6, borderwidth=0)
        st.configure("TSpinbox", fieldbackground=C["panel2"], foreground=C["fg"], arrowcolor=C["fg"],
                     background=C["panel2"], padding=4)
        st.configure("TCombobox", fieldbackground=C["panel2"], background=C["panel2"], foreground=C["fg"],
                     arrowcolor=C["fg"], padding=4)
        st.map("TCombobox", fieldbackground=[("readonly", C["panel2"])], foreground=[("readonly", C["fg"])],
               selectbackground=[("readonly", C["panel2"])], selectforeground=[("readonly", C["fg"])])
        self.option_add("*TCombobox*Listbox.background", C["panel2"])
        self.option_add("*TCombobox*Listbox.foreground", C["fg"])
        self.option_add("*TCombobox*Listbox.selectBackground", C["sel"])
        st.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["fg"],
                     rowheight=rowh, borderwidth=0)
        st.map("Treeview", background=[("selected", C["sel"])], foreground=[("selected", "#ffffff")])
        st.configure("Treeview.Heading", background=C["panel2"], foreground=C["dim"], relief="flat", padding=6,
                     font=self.f_bold)
        st.map("Treeview.Heading", background=[("active", C["panel2"])])
        st.configure("Nav.Treeview", background=C["panel"], fieldbackground=C["panel"],
                     rowheight=rowh + 8, font=self.f_ui)
        st.configure("TNotebook", background=C["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0))
        st.configure("TNotebook.Tab", background=C["panel"], foreground=C["dim"], padding=(16, 7), borderwidth=0)
        st.map("TNotebook.Tab", background=[("selected", C["panel2"])], foreground=[("selected", C["fg"])])
        st.configure("Horizontal.TProgressbar", background=C["accent"], troughcolor=C["panel"],
                     bordercolor=C["panel"], lightcolor=C["accent"], darkcolor=C["accent"])
        st.configure("Vertical.TScrollbar", background=C["panel2"], troughcolor=C["panel"], arrowcolor=C["dim"],
                     bordercolor=C["panel"], gripcount=0)
        st.configure("Horizontal.TScrollbar", background=C["panel2"], troughcolor=C["panel"], arrowcolor=C["dim"],
                     bordercolor=C["panel"], gripcount=0)
        st.configure("TPanedwindow", background=C["bg"])
        st.configure("Sash", sashthickness=6, background=C["bg"])

    def _build(self):
        top = ttk.Frame(self, style="Panel.TFrame", padding=(14, 10))
        top.pack(fill="x")
        ttk.Label(top, text="◉ " + APP_NAME, style="Logo.TLabel").pack(side="left", padx=(0, 18))
        ttk.Checkbutton(top, text="Przez Tor", variable=self.var_tor, style="Tor.TCheckbutton",
                        command=self._update_mode_label).pack(side="left")
        ttk.Label(top, text="SOCKS", style="PanelDim.TLabel").pack(side="left", padx=(14, 4))
        ttk.Entry(top, textvariable=self.var_host, width=12).pack(side="left")
        ttk.Label(top, text=":", style="PanelDim.TLabel").pack(side="left", padx=2)
        ttk.Entry(top, textvariable=self.var_port, width=6).pack(side="left")
        ttk.Button(top, text="Sprawdź połączenie", command=self._run_torcheck).pack(side="left", padx=(12, 6))
        ttk.Button(top, text="Nowa tożsamość Tor", command=self._newnym).pack(side="left")
        self.lbl_mode = tk.Label(top, text="", bg=C["panel"], fg=C["dim"], font=self.f_bold, padx=10)
        self.lbl_mode.pack(side="right")

        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.Frame(paned, style="Panel.TFrame", padding=(0, 8))
        ttk.Label(left, text="  MODUŁY", style="PanelDim.TLabel").pack(anchor="w", padx=8, pady=(0, 6))
        self.nav = ttk.Treeview(left, show="tree", selectmode="browse", style="Nav.Treeview")
        self.nav.column("#0", width=230)
        for m in MODULES:
            self.nav.insert("", "end", iid=m.key, text="  " + m.title)
        self.nav.pack(fill="both", expand=True)
        self.nav.bind("<<TreeviewSelect>>", lambda e: self._select_module(self.nav.selection()[0])
                      if self.nav.selection() else None)
        paned.add(left, weight=0)

        right = ttk.Frame(paned)
        paned.add(right, weight=1)

        head = ttk.Frame(right, padding=(6, 0, 6, 8))
        head.pack(fill="x")
        self.lbl_title = ttk.Label(head, text="", style="H1.TLabel")
        self.lbl_title.pack(anchor="w")
        self.lbl_desc = ttk.Label(head, text="", style="Dim.TLabel", wraplength=900, justify="left")
        self.lbl_desc.pack(anchor="w", pady=(2, 0))

        form = ttk.Frame(right, style="Panel.TFrame", padding=12)
        form.pack(fill="x", padx=6)
        row = ttk.Frame(form, style="Panel.TFrame")
        row.pack(fill="x")
        self.lbl_target = ttk.Label(row, text="Cel", style="Panel.TLabel", width=18)
        self.lbl_target.pack(side="left")
        self.ent_target = ttk.Entry(row, textvariable=self.var_target, font=self.f_mono)
        self.ent_target.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.ent_target.bind("<Return>", lambda e: self._start())
        self.btn_start = ttk.Button(row, text="▶  Start", style="Accent.TButton", command=self._start)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(row, text="■  Stop", style="Danger.TButton", command=self._stop, state="disabled")
        self.btn_stop.pack(side="left", padx=(6, 0))
        self.opts_frame = ttk.Frame(form, style="Panel.TFrame")
        self.opts_frame.pack(fill="x", pady=(10, 0))
        self.progress = ttk.Progressbar(right, mode="determinate", value=0)
        self.progress.pack(fill="x", padx=6, pady=(8, 0))

        self.nb = ttk.Notebook(right)
        self.nb.pack(fill="both", expand=True, padx=6, pady=(8, 0))

        tab_res = ttk.Frame(self.nb)
        self.nb.add(tab_res, text="Wyniki")
        tree_wrap = ttk.Frame(tab_res)
        tree_wrap.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_wrap, columns=("value",), selectmode="browse")
        self.tree.heading("#0", text="Klucz", anchor="w")
        self.tree.heading("value", text="Wartość", anchor="w")
        self.tree.column("#0", width=340, stretch=False)
        self.tree.column("value", width=640, stretch=True)
        ys = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.tree.tag_configure("run", background=C["panel2"], font=self.f_bold, foreground=C["accent"])
        self.tree.tag_configure("ok", foreground=C["ok"])
        self.tree.tag_configure("err", foreground=C["err"])
        self.tree.tag_configure("warn", foreground=C["warn"])
        self.tree.tag_configure("link", foreground=C["link"])
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", self._on_double)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.detail = tk.Text(tab_res, height=3, bg=C["panel2"], fg=C["fg"], relief="flat", wrap="word",
                              font=self.f_mono, insertbackground=C["fg"], padx=8, pady=6, highlightthickness=0)
        self.detail.pack(fill="x", pady=(6, 0))
        self.detail.insert("1.0", "Zaznacz wiersz, aby zobaczyć pełną wartość. Dwuklik na linku = otwórz; "
                                  "prawy przycisk = kopiuj / użyj jako cel w innym module.")
        self.detail.configure(state="disabled")

        tab_log = ttk.Frame(self.nb)
        self.nb.add(tab_log, text="Log")
        self.log = self._textbox(tab_log)
        for tag, col in (("ok", C["ok"]), ("err", C["err"]), ("dim", C["dim"]), ("info", C["accent"]),
                         ("warn", C["warn"])):
            self.log.tag_configure(tag, foreground=col)

        tab_json = ttk.Frame(self.nb)
        self.nb.add(tab_json, text="JSON")
        self.json_box = self._textbox(tab_json)

        bottom = ttk.Frame(self, style="Panel.TFrame", padding=(12, 8))
        bottom.pack(fill="x", side="bottom")
        ttk.Button(bottom, text="Eksport HTML", command=lambda: self._export("html")).pack(side="left")
        ttk.Button(bottom, text="Eksport JSON", command=lambda: self._export("json")).pack(side="left", padx=6)
        ttk.Button(bottom, text="Wyczyść", command=self._clear).pack(side="left")
        ttk.Label(bottom, textvariable=self.var_status, style="PanelDim.TLabel").pack(side="right")

        self.menu = tk.Menu(self, tearoff=0, bg=C["panel2"], fg=C["fg"], activebackground=C["sel"],
                            activeforeground="#ffffff", bd=0)
        self.bind("<Escape>", lambda e: self._stop())

    def _textbox(self, parent) -> tk.Text:
        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True)
        t = tk.Text(wrap, bg=C["panel"], fg=C["fg"], relief="flat", wrap="none", font=self.f_mono,
                    insertbackground=C["fg"], padx=10, pady=8, highlightthickness=0, undo=False)
        ys = ttk.Scrollbar(wrap, orient="vertical", command=t.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=t.xview)
        t.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y")
        xs.pack(side="bottom", fill="x")
        t.pack(side="left", fill="both", expand=True)
        t.configure(state="disabled")
        return t

    def _select_module(self, key: str):
        m = BY_KEY[key]
        self.current = m
        if self.nav.selection() != (key,):
            self.nav.selection_set(key)
        self.lbl_title.configure(text=m.title)
        self.lbl_desc.configure(text=m.description)
        if m.target:
            self.lbl_target.configure(text=m.target)
            self.ent_target.state(["!disabled"])
            self.ent_target.focus_set()
        else:
            self.lbl_target.configure(text="(bez celu)")
            self.ent_target.state(["disabled"])
        for w in self.opts_frame.winfo_children():
            w.destroy()
        self.opt_vars.clear()
        if m.example:
            ttk.Label(self.opts_frame, text=f"np. {m.example}", style="PanelDim.TLabel").pack(side="right")
        for o in m.opts:
            if o.kind == "bool":
                v = tk.BooleanVar(value=bool(o.default))
                ttk.Checkbutton(self.opts_frame, text=o.label, variable=v, style="Panel.TCheckbutton").pack(
                    side="left", padx=(0, 14))
            elif o.kind == "int":
                ttk.Label(self.opts_frame, text=o.label, style="Panel.TLabel").pack(side="left", padx=(0, 4))
                v = tk.StringVar(value=str(o.default))
                ttk.Spinbox(self.opts_frame, from_=o.minv, to=o.maxv, textvariable=v, width=6).pack(
                    side="left", padx=(0, 14))
            else:
                ttk.Label(self.opts_frame, text=o.label, style="Panel.TLabel").pack(side="left", padx=(0, 4))
                v = tk.StringVar(value=str(o.default))
                ttk.Combobox(self.opts_frame, values=list(o.choices), textvariable=v, state="readonly",
                             width=12).pack(side="left", padx=(0, 14))
            self.opt_vars[o.name] = (v, o)

    def _collect_opts(self) -> dict:
        out = {}
        for name, (v, o) in self.opt_vars.items():
            if o.kind == "int":
                try:
                    out[name] = max(o.minv, min(o.maxv, int(v.get())))
                except ValueError:
                    out[name] = o.default
            else:
                out[name] = v.get()
        return out

    def _make_net(self) -> Net:
        use_tor = self.var_tor.get()
        host = self.var_host.get().strip() or "127.0.0.1"
        p = self.var_port.get().strip()
        port = int(p) if p.isdigit() else 0
        if use_tor and not port:
            port = detect_tor_port(host)
            if not port:
                raise RuntimeError(f"Nie wykryto Tora na {host}:9050 ani {host}:9150.\n\n"
                                   "Uruchom Tor Browser (port 9150) lub usługę tor (port 9050) "
                                   "albo wpisz port ręcznie.")
        return Net(use_tor=use_tor, tor_host=host, tor_port=port, stop_event=self.stop_event)

    def _update_mode_label(self):
        if self.var_tor.get():
            p = self.var_port.get().strip()
            port = int(p) if p.isdigit() else detect_tor_port(self.var_host.get().strip() or "127.0.0.1")
            if port:
                self.lbl_mode.configure(text=f"● TOR  ·  SOCKS {port}", fg=C["ok"])
            else:
                self.lbl_mode.configure(text="● TOR  ·  nie wykryto proxy!", fg=C["err"])
        else:
            self.lbl_mode.configure(text="● CLEARNET  ·  bez anonimizacji", fg=C["warn"])

    def _run_torcheck(self):
        self._select_module("torcheck")
        self._start()

    def _newnym(self):
        host = self.var_host.get().strip() or "127.0.0.1"

        def job():
            try:
                self.q.put(("log", "[+] " + tor_new_identity(host)))
                self.q.put(("status", "Nowa tożsamość Tor ustawiona."))
            except Exception as e:
                self.q.put(("log", f"[!] {e}"))
                self.q.put(("popup", str(e)))

        threading.Thread(target=job, daemon=True).start()

    def _start(self):
        if self.worker and self.worker.is_alive():
            return
        m = self.current
        target = self.var_target.get().strip() if m.target else None
        if m.target and not target:
            messagebox.showwarning(APP_NAME, f"Podaj: {m.target.lower()}.", parent=self)
            return
        if m.multi and target:
            target = [t for t in re.split(r"[\s,;]+", target) if t]
        try:
            net = self._make_net()
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e), parent=self)
            self._update_mode_label()
            return
        self.stop_event.clear()
        opts = self._collect_opts()
        self._set_busy(True)
        self._log(f"[i] ── {m.title}: {target if not isinstance(target, list) else ' '.join(target)} "
                  f"({net.mode})")
        self.t_start = time.time()
        self.worker = threading.Thread(target=self._work, args=(m, target, opts, net), daemon=True)
        self.worker.start()

    def _work(self, m: Module, target, opts: dict, net: Net):
        def log(s):
            self.q.put(("log", s))
        t0 = time.time()
        try:
            data = m.func(net, target, log, **opts)
            self.q.put(("done", make_entry(m.key, m.title, target, net.mode, data, time.time() - t0)))
        except Cancelled:
            self.q.put(("cancel", None))
        except Exception as e:
            self.q.put(("error", short_error(e)))

    def _stop(self):
        if self.worker and self.worker.is_alive():
            self.stop_event.set()
            self.var_status.set("Przerywam…")

    def _set_busy(self, busy: bool):
        self.btn_start.configure(state="disabled" if busy else "normal")
        self.btn_stop.configure(state="normal" if busy else "disabled")
        if busy:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
            self.var_status.set(f"Pracuję: {self.current.title}…")
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "status":
                    self.var_status.set(payload)
                elif kind == "popup":
                    messagebox.showerror(APP_NAME, payload, parent=self)
                elif kind == "done":
                    self._set_busy(False)
                    self._add_result(payload)
                    self.var_status.set(f"Gotowe: {payload['nazwa_modulu']} · {payload['trwanie_s']} s · "
                                        f"wyników w sesji: {len(self.results)}")
                    if payload["modul"] == "torcheck":
                        self._torcheck_label(payload["wynik"])
                elif kind == "error":
                    self._set_busy(False)
                    self._log(f"[!] Błąd: {payload}")
                    self.var_status.set("Błąd — szczegóły w zakładce Log.")
                    self.nb.select(1)
                elif kind == "cancel":
                    self._set_busy(False)
                    self._log("[!] Przerwano.")
                    self.var_status.set("Przerwano.")
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _torcheck_label(self, data: dict):
        ip = data.get("Widoczny adres IP", "?")
        if data.get("Ruch przez Tor"):
            self.lbl_mode.configure(text=f"● TOR AKTYWNY  ·  IP wyjścia {ip}", fg=C["ok"])
        elif self.var_tor.get():
            self.lbl_mode.configure(text="● UWAGA: ruch NIE idzie przez Tor!", fg=C["err"])
        else:
            self.lbl_mode.configure(text=f"● CLEARNET  ·  Twoje IP {ip}", fg=C["warn"])

    def _log(self, msg: str):
        tag = {"[+]": "ok", "[!]": "err", "[-]": "dim", "[*]": "info", "[i]": "warn"}.get(msg[:3], "")
        self.log.configure(state="normal")
        self.log.insert("end", time.strftime("%H:%M:%S  "), "dim")
        self.log.insert("end", msg + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _add_result(self, entry: dict):
        self.results.append(entry)
        for iid in self.tree.get_children(""):
            self.tree.item(iid, open=False)
        tgt = entry["cel"] or "—"
        run = self.tree.insert("", 0, text=f"{entry['czas'][11:]}  {entry['nazwa_modulu']}",
                               values=(f"{tgt}   ·   {entry['tryb']}   ·   {entry['trwanie_s']} s",),
                               open=True, tags=("run",))
        self.node_entry[run] = entry
        self._insert(run, entry["wynik"], 0)
        self.tree.selection_set(run)
        self.tree.see(run)
        self._show_json(entry)
        self.nb.select(0)

    def _insert(self, parent, value, depth):
        if isinstance(value, dict):
            for k, v in value.items():
                self._insert_kv(parent, str(k), v, depth)
        elif isinstance(value, list):
            for i, v in enumerate(value, 1):
                self._insert_kv(parent, str(i), v, depth)
        else:
            self._insert_kv(parent, "", value, depth)

    def _insert_kv(self, parent, key, v, depth):
        if isinstance(v, dict) and v:
            label = self._dict_label(v)
            node = self.tree.insert(parent, "end", text=key, values=(label,), open=depth < 1 or len(v) <= 12)
            self._insert(node, v, depth + 1)
        elif isinstance(v, list) and v:
            node = self.tree.insert(parent, "end", text=key, values=(f"[{len(v)}]",),
                                    open=len(v) <= 8 or (depth < 1 and len(v) <= 30))
            self._insert(node, v, depth + 1)
        else:
            s, tag = self._fmt(v)
            self.tree.insert(parent, "end", text=key, values=(s,), tags=(tag,) if tag else ())

    @staticmethod
    def _dict_label(d: dict) -> str:
        for k in ("Tytuł", "URL", "Status", "Odcisk"):
            if k in d and isinstance(d[k], (str, int)):
                return str(d[k])[:120]
        return f"{{{len(d)}}}"

    @staticmethod
    def _fmt(v):
        if v is True:
            return "tak", "ok"
        if v is False:
            return "nie", "err"
        if v is None or v == [] or v == {}:
            return "—", ""
        s = str(v).replace("\n", " ⏎ ")
        if URL_RE.match(s):
            return s, "link"
        if s.startswith(("BRAK", "NIEPRAWID", "błąd", "UWAGA", "TAK —", "HTTP 4", "ochrona")):
            return s, "warn"
        if s in ("ONLINE", "obecny", "poprawny") or s.startswith("v3, suma"):
            return s, "ok"
        if s.startswith(("OFFLINE",)):
            return s, "err"
        return s, ""

    def _row_value(self, iid) -> str:
        vals = self.tree.item(iid, "values")
        v = str(vals[0]) if vals else ""
        return v.replace(" ⏎ ", "\n")

    def _on_tree_select(self, _e=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        key = self.tree.item(iid, "text")
        val = self._row_value(iid)
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", f"{key}: {val}" if key else val)
        self.detail.configure(state="disabled")
        root = iid
        while self.tree.parent(root):
            root = self.tree.parent(root)
        if root in self.node_entry:
            self._show_json(self.node_entry[root])

    def _show_json(self, entry):
        self.json_box.configure(state="normal")
        self.json_box.delete("1.0", "end")
        self.json_box.insert("1.0", json.dumps(entry, ensure_ascii=False, indent=2, default=str))
        self.json_box.configure(state="disabled")

    def _on_double(self, e):
        iid = self.tree.identify_row(e.y)
        if iid:
            self._open_link(self._row_value(iid))

    def _open_link(self, val: str):
        val = val.strip()
        if not URL_RE.match(val):
            return
        if ".onion" in val:
            self._copy(val)
            messagebox.showinfo(APP_NAME, "Adres .onion skopiowano do schowka.\nOtwórz go w Tor Browser.",
                                parent=self)
        else:
            webbrowser.open(val)

    def _copy(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.var_status.set("Skopiowano do schowka.")

    def _on_right_click(self, e):
        iid = self.tree.identify_row(e.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        key = self.tree.item(iid, "text")
        val = self._row_value(iid)
        self.menu.delete(0, "end")
        self.menu.add_command(label="Kopiuj wartość", command=lambda: self._copy(val))
        self.menu.add_command(label="Kopiuj klucz", command=lambda: self._copy(key))
        if URL_RE.match(val.strip()):
            self.menu.add_command(label="Otwórz link", command=lambda: self._open_link(val))
        pivot = tk.Menu(self.menu, tearoff=0, bg=C["panel2"], fg=C["fg"], activebackground=C["sel"],
                        activeforeground="#ffffff", bd=0)
        candidate = val.strip() or key
        for m in MODULES:
            if m.target:
                pivot.add_command(label=m.title, command=lambda k=m.key, c=candidate: self._pivot(k, c))
        self.menu.add_separator()
        self.menu.add_cascade(label="Użyj jako cel w…", menu=pivot)
        try:
            self.menu.tk_popup(e.x_root, e.y_root)
        finally:
            self.menu.grab_release()

    def _pivot(self, key: str, value: str):
        self._select_module(key)
        v = value
        if key in ("domain", "ip") and "://" in v:
            from urllib.parse import urlparse
            v = urlparse(v).hostname or v
        if key == "user" and v.startswith("http"):
            v = v.rstrip("/").rsplit("/", 1)[-1].lstrip("@")
        self.var_target.set(v)
        self.ent_target.focus_set()
        self.ent_target.icursor("end")

    def _export(self, kind: str):
        if not self.results:
            messagebox.showinfo(APP_NAME, "Brak wyników do eksportu.", parent=self)
            return
        ext = ".html" if kind == "html" else ".json"
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=ext, initialfile=f"raport_osint_{time.strftime('%Y%m%d_%H%M')}{ext}",
            filetypes=[("Raport HTML", "*.html")] if kind == "html" else [("JSON", "*.json")])
        if not path:
            return
        try:
            save_report(self.results, path)
            self.var_status.set(f"Zapisano: {path}")
            if kind == "html" and messagebox.askyesno(APP_NAME, "Raport zapisany. Otworzyć w przeglądarce?",
                                                      parent=self):
                webbrowser.open("file:///" + path.replace("\\", "/"))
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Nie można zapisać: {e}", parent=self)

    def _clear(self):
        if self.worker and self.worker.is_alive():
            return
        self.results.clear()
        self.node_entry.clear()
        self.tree.delete(*self.tree.get_children(""))
        for box in (self.log, self.json_box):
            box.configure(state="normal")
            box.delete("1.0", "end")
            box.configure(state="disabled")
        self.var_status.set("Wyczyszczono.")


def main() -> int:
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
