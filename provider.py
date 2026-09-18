#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography", "bcrypt"]
# ///
"""kbrelay provider: a window that captures your keyboard and sends it to a receiver.

Windows: run with `pyw provider.py` (no console window).
Linux:   python provider.py   (needs Tk: `pacman -S tk` / `apt install python3-tk`)
Self-contained (e.g. SteamOS): ./kbrelay-provider.sh, which uses uv for a private Python in $HOME.
"""
from __future__ import annotations

import argparse
import asyncio
import queue
import logging
import sys
import threading
import tkinter as tk
from tkinter import font as tkfont, messagebox, simpledialog, ttk

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from kbrelay_common import (
    KEY, NAME_RE, READ_TIMEOUT, AuthError, E2EError, Session, add_client_args, connect_and_auth, describe,
    key_name, load_authorized, load_private_key, ping_loop, raw_public_bytes, resolve_settings,
    ssh_fingerprint, valid_key_code,
)

log = logging.getLogger("kbrelay")
RELEASE_DELAY_MS = 30  # X11 sends release+press pairs for auto-repeat; wait this long before trusting a release
ALT_KEYS = {KEY["LEFTALT"], KEY["RIGHTALT"]}

# ============================================================== key mapping

_KEYSYM = {
    "Escape": "ESC", "Return": "ENTER", "KP_Enter": "KPENTER", "BackSpace": "BACKSPACE", "Tab": "TAB",
    "ISO_Left_Tab": "TAB", "space": "SPACE", "Shift_L": "LEFTSHIFT", "Shift_R": "RIGHTSHIFT",
    "Control_L": "LEFTCTRL", "Control_R": "RIGHTCTRL", "Alt_L": "LEFTALT", "Alt_R": "RIGHTALT",
    "Option_L": "LEFTALT", "Option_R": "RIGHTALT", "Meta_L": "LEFTMETA", "Meta_R": "RIGHTMETA",
    "Super_L": "LEFTMETA", "Super_R": "RIGHTMETA", "Win_L": "LEFTMETA", "Win_R": "RIGHTMETA",
    "App": "COMPOSE", "Menu": "COMPOSE", "Caps_Lock": "CAPSLOCK", "Num_Lock": "NUMLOCK",
    "Scroll_Lock": "SCROLLLOCK", "Pause": "PAUSE", "Print": "SYSRQ", "Insert": "INSERT",
    "Delete": "DELETE", "Home": "HOME", "End": "END", "Prior": "PAGEUP", "Next": "PAGEDOWN",
    "Up": "UP", "Down": "DOWN", "Left": "LEFT", "Right": "RIGHT",
    "minus": "MINUS", "underscore": "MINUS", "equal": "EQUAL", "plus": "EQUAL",
    "bracketleft": "LEFTBRACE", "braceleft": "LEFTBRACE", "bracketright": "RIGHTBRACE",
    "braceright": "RIGHTBRACE", "backslash": "BACKSLASH", "bar": "BACKSLASH",
    "semicolon": "SEMICOLON", "colon": "SEMICOLON", "apostrophe": "APOSTROPHE", "quotedbl": "APOSTROPHE",
    "grave": "GRAVE", "asciitilde": "GRAVE", "comma": "COMMA", "less": "COMMA", "period": "DOT",
    "greater": "DOT", "slash": "SLASH", "question": "SLASH", "exclam": "1", "at": "2",
    "numbersign": "3", "dollar": "4", "percent": "5", "asciicircum": "6", "ampersand": "7",
    "asterisk": "8", "parenleft": "9", "parenright": "0",
}


def keysym_to_code(keysym: str) -> int | None:
    """Portable fallback (e.g. macOS): works from the key's symbol, assumes a US layout."""
    if len(keysym) == 1 and keysym.isascii() and keysym.isalnum():
        name = keysym.upper()
    elif keysym[:1] == "F" and keysym[1:].isdigit():
        name = keysym
    else:
        name = _KEYSYM.get(keysym)
    return KEY.get(name) if name else None


_WIN_VK = {
    0x08: "BACKSPACE", 0x09: "TAB", 0x0D: "ENTER", 0x13: "PAUSE", 0x14: "CAPSLOCK", 0x1B: "ESC",
    0x20: "SPACE", 0x21: "PAGEUP", 0x22: "PAGEDOWN", 0x23: "END", 0x24: "HOME", 0x25: "LEFT",
    0x26: "UP", 0x27: "RIGHT", 0x28: "DOWN", 0x2C: "SYSRQ", 0x2D: "INSERT", 0x2E: "DELETE",
    0x5B: "LEFTMETA", 0x5C: "RIGHTMETA", 0x5D: "COMPOSE", 0x6A: "KPASTERISK", 0x6B: "KPPLUS",
    0x6C: "KPCOMMA", 0x6D: "KPMINUS", 0x6E: "KPDOT", 0x6F: "KPSLASH", 0x90: "NUMLOCK",
    0x91: "SCROLLLOCK", 0xAD: "MUTE", 0xAE: "VOLUMEDOWN", 0xAF: "VOLUMEUP", 0xB0: "NEXTSONG",
    0xB1: "PREVIOUSSONG", 0xB2: "STOPCD", 0xB3: "PLAYPAUSE", 0xBA: "SEMICOLON", 0xBB: "EQUAL",
    0xBC: "COMMA", 0xBD: "MINUS", 0xBE: "DOT", 0xBF: "SLASH", 0xC0: "GRAVE", 0xDB: "LEFTBRACE",
    0xDC: "BACKSLASH", 0xDD: "RIGHTBRACE", 0xDE: "APOSTROPHE", 0xE2: "102ND",
}
_WIN_VK.update({0x30 + i: str(i) for i in range(10)})
_WIN_VK.update({0x41 + i: chr(0x41 + i) for i in range(26)})
_WIN_VK.update({0x60 + i: f"KP{i}" for i in range(10)})
_WIN_VK.update({0x70 + i: f"F{i + 1}" for i in range(24)})
_WIN_TYPING_VKS = set(range(0x30, 0x3A)) | set(range(0x41, 0x5B)) | set(range(0xBA, 0xC1)) | set(range(0xDB, 0xE0)) | {0xE2}


def _win_scancode(vk: int) -> int:
    try:
        import ctypes
        return ctypes.windll.user32.MapVirtualKeyW(vk, 0)  # MAPVK_VK_TO_VSC
    except Exception:
        return 0


def win_vk_to_code(vk: int, keysym: str) -> int | None:
    right = keysym.endswith("_R")
    if vk in (0x10, 0xA0, 0xA1):
        return KEY["RIGHTSHIFT" if right or vk == 0xA1 else "LEFTSHIFT"]
    if vk in (0x11, 0xA2, 0xA3):
        return KEY["RIGHTCTRL" if right or vk == 0xA3 else "LEFTCTRL"]
    if vk in (0x12, 0xA4, 0xA5):
        return KEY["RIGHTALT" if right or vk == 0xA5 else "LEFTALT"]
    if vk in _WIN_TYPING_VKS:
        # Windows virtual keys follow the active layout; the set-1 scancode is the physical
        # position, and for these keys it equals the Linux key code.
        sc = _win_scancode(vk)
        if 1 < sc <= 0x35 or sc == 0x56:
            return sc
    name = _WIN_VK.get(vk)
    return KEY[name] if name else keysym_to_code(keysym)


def event_to_code(event, windowing: str) -> int | None:
    if windowing == "x11":  # X keycodes are Linux key codes + 8
        code = event.keycode - 8
        return code if valid_key_code(code) else None
    if windowing == "win32":
        return win_vk_to_code(event.keycode, event.keysym)
    return keysym_to_code(event.keysym)


# ============================================================== network thread

class NetClient(threading.Thread):
    """Runs the asyncio connection; talks to the GUI through a thread-safe queue."""

    def __init__(self, server: str, fingerprint: str, key, proxy=None):
        super().__init__(daemon=True)
        self.server, self.fingerprint, self.key, self.proxy = server, fingerprint, key, proxy
        self.events: queue.Queue = queue.Queue()
        self.loop = asyncio.new_event_loop()
        self.conn = None

    def run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._main())

    def send(self, obj: dict):
        try:
            self.loop.call_soon_threadsafe(self._send, obj)
        except RuntimeError:
            pass

    def _send(self, obj: dict):
        if self.conn is not None:
            self.conn.send(obj)

    async def _main(self):
        backoff = 1
        while True:
            self.events.put(("status", f"Connecting to {self.server}…"))
            try:
                conn, name = await connect_and_auth(self.server, self.fingerprint, self.key, "provider",
                                                    proxy=self.proxy)
            except AuthError as exc:
                delay = 30
                self.events.put(("disconnected", f"{exc}. Retrying in {delay}s."))
            except Exception as exc:
                delay, backoff = backoff, min(backoff * 2, 30)
                self.events.put(("disconnected", f"{describe(exc)}. Retrying in {delay}s."))
            else:
                backoff, delay = 1, 1
                self.conn = conn
                self.events.put(("connected", name))
                pinger = asyncio.create_task(ping_loop(conn))
                reason = "connection closed"
                try:
                    while True:
                        self.events.put(("msg", await conn.recv(READ_TIMEOUT)))
                except Exception as exc:
                    reason = describe(exc)
                finally:
                    pinger.cancel()
                    self.conn = None
                    conn.close()
                self.events.put(("disconnected", f"{reason}. Reconnecting…"))
            await asyncio.sleep(delay)


# ============================================================== GUI

COLORS = {  # background, text, border
    "idle": ("#ececf1", "#55555f", "#c9c9d3"),
    "waiting": ("#fff4d6", "#6b5000", "#e0b000"),
    "live": ("#dcf5e4", "#0f5a2a", "#1f9d4c"),
}


class ProviderApp:
    def __init__(self, root: tk.Tk, net: NetClient, windowing: str, key, peers_dir):
        self.root, self.net, self.windowing = root, net, windowing
        self.key, self.peers_dir = key, peers_dir
        self.session: Session | None = None  # end-to-end session with the current receiver
        self.in_dialog = False
        self.connected = False
        self.receivers: list[str] = []
        self.current: str | None = None     # receiver the server says we're attached to
        self.desired: str | None = None     # receiver the user picked (re-attached after reconnects)
        self.requested: str | None = None
        self.focused = False
        self.pressed: set[int] = set()
        self.pending_release: dict[int, tuple[str, int]] = {}  # code -> (after id, X event time)
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(20, self.poll)

    def _build(self):
        base = tkfont.nametofont("TkDefaultFont")
        list_font = base.copy()
        list_font.configure(size=max(12, abs(base.cget("size"))))
        pad_font = base.copy()
        pad_font.configure(size=15)
        self.fonts = (list_font, pad_font)  # keep references alive
        self.root.title("kbrelay provider")
        self.root.geometry("780x440")
        self.root.minsize(560, 320)
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(1, weight=1)

        self.status = ttk.Label(main, text="Starting…")
        self.status.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        left = ttk.Frame(main)
        left.grid(row=1, column=0, sticky="ns", padx=(0, 12))
        ttk.Label(left, text="Receivers").pack(anchor="w")
        self.listbox = tk.Listbox(left, width=26, exportselection=False, activestyle="none", font=list_font)
        self.listbox.pack(fill="both", expand=True, pady=(4, 0))
        self.listbox.bind("<<ListboxSelect>>", self.on_pick)
        ttk.Button(left, text="Stop sending", command=self.on_stop).pack(fill="x", pady=(8, 0))

        self.pad = tk.Frame(main, takefocus=1, highlightthickness=3, cursor="xterm")
        self.pad.grid(row=1, column=1, sticky="nsew")
        self.pad_label = tk.Label(self.pad, font=pad_font, justify="center")
        self.pad_label.place(relx=0.5, rely=0.5, anchor="center")
        for widget in (self.pad, self.pad_label):
            widget.bind("<Button-1>", lambda _e: self.pad.focus_set())
        self.pad.bind("<Configure>", lambda e: self.pad_label.configure(wraplength=max(200, e.width - 40)))
        self.pad.bind("<KeyPress>", self.on_key_down)
        self.pad.bind("<KeyRelease>", self.on_key_up)
        self.pad.bind("<FocusIn>", self.on_focus_in)
        self.pad.bind("<FocusOut>", self.on_focus_out)

        self.last_key = ttk.Label(main, text=" ", foreground="#777")
        self.last_key.grid(row=2, column=1, sticky="e", pady=(6, 0))
        self.update_pad()

    # ------------------------------------------------------ state & display

    @property
    def live(self) -> bool:
        return self.connected and self.current is not None and self.session is not None and self.session.recv_aead is not None

    def update_pad(self):
        if not self.focused:
            state = "idle"
            text = "Click here to start typing"
            if self.current:
                text += f"\n(keys will go to {self.current})"
        elif not self.connected:
            state, text = "waiting", "Not connected to the relay yet…"
        elif not self.current:
            state = "waiting"
            text = "Pick a receiver on the left" if self.receivers else "No receivers are online"
        elif not self.live:
            state, text = "waiting", f"Setting up the encrypted session with {self.current}…"
        else:
            state = "live"
            text = (f"Typing into {self.current}\n\nEnd-to-end encrypted, receiver key\n{self.session.peer_fingerprint}"
                    "\n\nEverything you type here is sent.\nSwitch windows or press “Stop sending” to stop.")
        bg, fg, border = COLORS[state]
        self.pad.configure(bg=bg, highlightbackground=border, highlightcolor=border)
        self.pad_label.configure(bg=bg, fg=fg, text=text)

    def refresh_list(self):
        self.listbox.delete(0, "end")
        for name in self.receivers:
            self.listbox.insert("end", f"{'»' if name == self.current else '  '} {name}")
        if self.current in self.receivers:
            self.listbox.selection_set(self.receivers.index(self.current))

    def request_select(self, name: str | None):
        self.requested = name
        self.net.send({"type": "select", "receiver": name})

    # ------------------------------------------------------ network events

    def poll(self):
        if self.in_dialog:  # a modal dialog is open; leave incoming messages queued until it closes
            self.root.after(50, self.poll)
            return
        try:
            while True:
                kind, data = self.net.events.get_nowait()
                if kind == "status":
                    self.status.configure(text=data)
                elif kind == "connected":
                    self.connected = True
                    self.status.configure(text=f"Connected to {self.net.server} as “{data}”")
                elif kind == "disconnected":
                    self.connected = False
                    self.session = None
                    self.current = self.requested = None
                    self.receivers = []
                    self.pressed.clear()
                    self.status.configure(text=f"Disconnected: {data}")
                    self.refresh_list()
                elif kind == "msg":
                    self.handle_msg(data)
                self.update_pad()
        except queue.Empty:
            pass
        self.root.after(20, self.poll)

    def handle_msg(self, msg: dict):
        kind = msg.get("type")
        if kind == "receivers":
            self.receivers = [str(n) for n in msg.get("receivers", [])]
            if self.desired in self.receivers and self.current != self.desired and self.requested != self.desired:
                self.request_select(self.desired)
            self.refresh_list()
        elif kind == "selected":
            self.current = msg.get("receiver")
            self.requested = None
            self.session = None
            if msg.get("reason"):
                self.status.configure(text=msg["reason"])
            if self.current:
                self.session = Session(self.key, "provider")
                self.net.send({"type": "e2e", "hs": self.session.hello()})
            self.refresh_list()
        elif kind == "e2e":
            self.handle_e2e(msg)
        elif kind == "error":
            self.status.configure(text=f"Server: {msg.get('message')}")

    # ------------------------------------------------------ end-to-end session

    def handle_e2e(self, msg: dict):
        if "err" in msg:
            self.status.configure(text=f"{self.current or 'Receiver'} refused: {str(msg['err'])[:200]}")
            self.give_up_receiver()
            return
        if "hs" not in msg or self.session is None or self.session.recv_aead is not None or not self.current:
            return
        try:
            receiver_key = self.session.finish(msg["hs"])
        except E2EError as exc:
            self.status.configure(text=f"Handshake with {self.current} failed: {exc}")
            self.give_up_receiver()
            return
        if not self.trusted(self.current, receiver_key):
            self.give_up_receiver()
            return
        # First encrypted message confirms the session on the receiver's side.
        self.net.send(self.session.encrypt({"type": "release_all"}))
        self.status.configure(text=f"Encrypted session with {self.current} ({self.session.peer_fingerprint})")

    def give_up_receiver(self):
        self.session = None
        self.desired = None
        self.request_select(None)

    def trusted(self, name: str, receiver_key) -> bool:
        """known_hosts-style pinning: accept a pinned key, ask on first contact, refuse a changed key."""
        pinned = load_authorized(self.peers_dir)
        raw = raw_public_bytes(receiver_key)
        fingerprint = ssh_fingerprint(receiver_key)
        if raw in pinned:
            return True
        pinned_for_name = {n: r for r, n in pinned.items()}.get(name)
        self.in_dialog = True
        try:
            if pinned_for_name is not None:
                log.warning("receiver %r presented key %s, but %s is pinned to a different key", name, fingerprint, self.peers_dir)
                messagebox.showerror("kbrelay: receiver key changed",
                    f"“{name}” presented the key\n{fingerprint}\n\nwhich is NOT the key you trusted for it before. "
                    f"Someone may be impersonating that receiver to capture what you type.\n\n"
                    f"If you really did replace its key, delete {self.peers_dir / (name + '.pub')} and try again.",
                    parent=self.root)
                return False
            ok = messagebox.askyesno("kbrelay: new receiver",
                f"You haven't trusted “{name}” before. It presented the key\n\n{fingerprint}\n\n"
                f"Compare this with the output of\n  ssh-keygen -lf ~/.config/kbrelay/id_ed25519.pub\n"
                f"on that machine. Trust this key and remember it?", parent=self.root, default="no")
        finally:
            self.in_dialog = False
        if not ok:
            return False
        if not NAME_RE.match(name):
            messagebox.showerror("kbrelay", f"Can't save a key for the name {name!r}; add it manually to {self.peers_dir}.",
                                 parent=self.root)
            return False
        self.peers_dir.mkdir(parents=True, exist_ok=True)
        (self.peers_dir / f"{name}.pub").write_text(
            receiver_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode() + f" {name}\n")
        log.info("pinned receiver %r as %s", name, fingerprint)
        return True

    # ------------------------------------------------------ user actions

    def on_pick(self, _event):
        selection = self.listbox.curselection()
        if not selection or selection[0] >= len(self.receivers):
            return
        name = self.receivers[selection[0]]
        self.desired = name
        if name != self.current:
            self.request_select(name)
        self.root.after(1, self.pad.focus_set)  # after the Listbox's own click binding, which grabs focus

    def on_stop(self):
        self.desired = None
        self.session = None
        self.request_select(None)
        self.listbox.focus_set()

    def on_close(self):
        if self.focused and self.pressed & ALT_KEYS:
            return  # Alt+F4 while capturing: it was forwarded to the receiver, don't close this window
        self.root.destroy()

    # ------------------------------------------------------ keyboard capture

    def send_key(self, code: int, down: bool):
        if self.live:
            self.net.send(self.session.encrypt({"type": "key", "code": code, "down": down}))
            self.last_key.configure(text=f"{key_name(code)} {'↓' if down else '↑'}")

    def flush_releases(self, except_code: int | None = None):
        """Commit delayed releases now. Auto-repeat pairs are always the same key back to back,
        so any event for a different key means those releases were real (keeps Shift+h, i in order)."""
        for code in [c for c in self.pending_release if c != except_code]:
            self.root.after_cancel(self.pending_release[code][0])
            self._commit_release(code)

    def on_key_down(self, event):
        code = event_to_code(event, self.windowing)
        if code is None:
            self.last_key.configure(text=f"unmapped key: {event.keysym}")
            return "break"
        self.flush_releases(except_code=code)
        pending = self.pending_release.pop(code, None)
        if pending is not None:
            after_id, release_time = pending
            self.root.after_cancel(after_id)
            if event.time == release_time:  # X11 auto-repeat: synthetic release + press share a timestamp
                return "break"
            self._commit_release(code)  # a genuine quick double press
        if code not in self.pressed:  # ignore OS auto-repeat; the receiver's desktop repeats on its own
            self.pressed.add(code)
            self.send_key(code, True)
        return "break"  # stop Tk's own bindings (Tab focus traversal, Alt menu, etc.)

    def on_key_up(self, event):
        code = event_to_code(event, self.windowing)
        if code is None:
            return "break"
        self.flush_releases(except_code=code)
        if code not in self.pressed:
            if code == KEY["SYSRQ"]:  # Windows only reports PrintScreen on release
                self.send_key(code, True)
                self.send_key(code, False)
            return "break"
        if self.windowing == "x11":
            if code not in self.pending_release:
                after_id = self.root.after(RELEASE_DELAY_MS, self._commit_release, code)
                self.pending_release[code] = (after_id, event.time)
        else:
            self._commit_release(code)
        return "break"

    def _commit_release(self, code: int):
        self.pending_release.pop(code, None)
        if code in self.pressed:
            self.pressed.discard(code)
            self.send_key(code, False)

    def on_focus_in(self, _event):
        self.focused = True
        self.update_pad()

    def on_focus_out(self, _event):
        self.focused = False
        for after_id, _time in self.pending_release.values():
            self.root.after_cancel(after_id)
        self.pending_release.clear()
        self.pressed.clear()
        if self.live:  # e.g. Alt+Tab away: make sure Alt doesn't stay held on the receiver
            self.net.send(self.session.encrypt({"type": "release_all"}))
        self.update_pad()


def main():
    parser = argparse.ArgumentParser(description="kbrelay provider")
    add_client_args(parser)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    root = tk.Tk()
    root.withdraw()
    try:
        settings = resolve_settings(args, "provider")
        key = load_private_key(settings["key"], prompt=lambda p: simpledialog.askstring(
            "kbrelay", f"Passphrase for {p}:", show="*", parent=root))
    except Exception as exc:
        messagebox.showerror("kbrelay", describe(exc))
        root.destroy()
        return 1

    net = NetClient(settings["server"], settings["fingerprint"], key, proxy=settings["proxy"])
    net.start()
    ProviderApp(root, net, root.tk.call("tk", "windowingsystem"), key, settings["peers"])
    root.deiconify()
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
