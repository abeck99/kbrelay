#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography"]
# ///
"""kbrelay receiver: connects to the relay and replays key events on a virtual keyboard.

It uses /dev/uinput, so it works below the display server: X11, any Wayland
compositor, the login screen and text consoles all see a normal keyboard.

Only providers whose .pub files are in ~/.config/kbrelay/providers/ may type here;
their key events arrive end-to-end encrypted, so the relay can neither read nor
inject keystrokes.
"""
from __future__ import annotations

import argparse
import asyncio
import fcntl
import logging
import os
import shutil
import struct
import sys
import time

from kbrelay_common import (
    KEY, READ_TIMEOUT, AuthError, E2EError, Session, add_client_args, connect_and_auth, describe,
    e2e_error, key_name, load_authorized, load_private_key, ping_loop, resolve_settings, valid_key_code,
)

log = logging.getLogger("kbrelay")
TAP_DELAY = 0.004

# Characters from "text" messages (e.g. an iOS on-screen keyboard) -> (key, needs shift).
# Assumes a US layout on the receiver; anything else goes through wtype/xdotool.
_US_ROWS = [
    ("`1234567890-=", "~!@#$%^&*()_+", "GRAVE 1 2 3 4 5 6 7 8 9 0 MINUS EQUAL"),
    ("qwertyuiop[]\\", "QWERTYUIOP{}|", "Q W E R T Y U I O P LEFTBRACE RIGHTBRACE BACKSLASH"),
    ("asdfghjkl;'", 'ASDFGHJKL:"', "A S D F G H J K L SEMICOLON APOSTROPHE"),
    ("zxcvbnm,./", "ZXCVBNM<>?", "Z X C V B N M COMMA DOT SLASH"),
]
CHAR_MAP = {" ": (KEY["SPACE"], False), "\n": (KEY["ENTER"], False),
            "\t": (KEY["TAB"], False), "\b": (KEY["BACKSPACE"], False)}
for _plain, _shifted, _names in _US_ROWS:
    for _p, _s, _n in zip(_plain, _shifted, _names.split(), strict=True):
        CHAR_MAP[_p] = (KEY[_n], False)
        CHAR_MAP[_s] = (KEY[_n], True)


class UInputBackend:
    """Virtual keyboard through /dev/uinput using only the standard library (no python-evdev,
    so nothing needs compiling). Constants and struct layouts match <linux/uinput.h>."""

    UI_DEV_CREATE = 0x5501
    UI_DEV_DESTROY = 0x5502
    UI_DEV_SETUP = 0x405C5503    # _IOW('U', 3, struct uinput_setup), 92 bytes
    UI_SET_EVBIT = 0x40045564    # _IOW('U', 100, int)
    UI_SET_KEYBIT = 0x40045565   # _IOW('U', 101, int)
    EV_SYN, EV_KEY, SYN_REPORT = 0, 1, 0
    BUS_USB = 0x03
    SETUP_FORMAT = "HHHH80sI"    # struct input_id {bustype, vendor, product, version}; name; ff_effects_max
    EVENT_FORMAT = "llHHi"       # struct input_event {timeval; type; code; value}

    def __init__(self, device_name: str, path: str = "/dev/uinput"):
        try:
            self.fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as exc:
            sys.exit(f"cannot open {path}: {exc.strerror}\n"
                     "Check that the uinput module is loaded and /dev/uinput is writable (see README).")
        try:
            fcntl.ioctl(self.fd, self.UI_SET_EVBIT, self.EV_KEY)
            for code in range(1, 0x2C0):
                if valid_key_code(code):
                    fcntl.ioctl(self.fd, self.UI_SET_KEYBIT, code)
            setup = struct.pack(self.SETUP_FORMAT, self.BUS_USB, 0x1, 0x1, 0x1, device_name.encode()[:79], 0)
            fcntl.ioctl(self.fd, self.UI_DEV_SETUP, setup)
            fcntl.ioctl(self.fd, self.UI_DEV_CREATE)
        except OSError as exc:
            os.close(self.fd)
            sys.exit(f"cannot create the virtual keyboard: {exc.strerror or exc}")
        time.sleep(0.3)  # give udev and the compositor a moment to pick up the new device

    def emit(self, code: int, down: bool):
        os.write(self.fd, struct.pack(self.EVENT_FORMAT, 0, 0, self.EV_KEY, code, 1 if down else 0)
                 + struct.pack(self.EVENT_FORMAT, 0, 0, self.EV_SYN, self.SYN_REPORT, 0))

    def close(self):
        try:
            fcntl.ioctl(self.fd, self.UI_DEV_DESTROY)
        except OSError:
            pass
        os.close(self.fd)


class PrintBackend:
    def emit(self, code: int, down: bool):
        print(f"{key_name(code)} {'down' if down else 'up'}", flush=True)

    def close(self):
        pass


class Keyboard:
    def __init__(self, backend, dry_run: bool = False):
        self.backend = backend
        self.dry_run = dry_run
        self.down: set[int] = set()

    def key(self, code: int, down: bool):
        if down == (code in self.down):
            return  # duplicate press, or release of a key that isn't down
        (self.down.add if down else self.down.discard)(code)
        self.backend.emit(code, down)

    def release_all(self):
        for code in list(self.down):
            self.key(code, False)

    async def type_text(self, text: str):
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        other: list[str] = []
        for ch in text:
            if ch not in CHAR_MAP:
                other.append(ch)
                continue
            if other:
                await self._type_external("".join(other))
                other.clear()
            code, shift = CHAR_MAP[ch]
            add_shift = shift and not self.down & {KEY["LEFTSHIFT"], KEY["RIGHTSHIFT"]}
            if add_shift:
                self.backend.emit(KEY["LEFTSHIFT"], True)
            self.backend.emit(code, True)
            self.backend.emit(code, False)
            if add_shift:
                self.backend.emit(KEY["LEFTSHIFT"], False)
            await asyncio.sleep(TAP_DELAY)
        if other:
            await self._type_external("".join(other))

    async def _type_external(self, s: str):
        if self.dry_run:
            print(f"[external text] {s!r}", flush=True)
            return
        if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wtype"):
            cmd = ["wtype", "--", s]
        elif os.environ.get("DISPLAY") and shutil.which("xdotool"):
            cmd = ["xdotool", "type", "--clearmodifiers", "--", s]
        else:
            log.warning("can't type %d non-ASCII character(s): install wtype (Wayland) or xdotool (X11)", len(s))
            return
        proc = await asyncio.create_subprocess_exec(*cmd)
        await proc.wait()


class Receiver:
    def __init__(self, settings: dict, key, kb: Keyboard):
        self.settings, self.key, self.kb = settings, key, kb
        self.session: Session | None = None
        self.provider: str | None = None

    def end_session(self):
        self.kb.release_all()  # never leave a modifier held when the provider goes away
        self.session = None

    async def handle(self, conn, msg: dict):
        kind = msg.get("type")
        if kind == "attached":
            self.end_session()
            self.provider = msg.get("provider")
            log.info("relay attached provider %r; waiting for its handshake", self.provider)
        elif kind == "detached":
            log.info("provider %r detached", self.provider)
            self.end_session()
        elif kind == "e2e":
            if "hs" in msg:
                self.handshake(conn, msg["hs"])
            elif "ct" in msg:
                await self.receive(conn, msg)
            elif "err" in msg:
                log.warning("provider reported: %s", str(msg["err"])[:200])

    def handshake(self, conn, hs):
        self.end_session()
        session = Session(self.key, "receiver")
        try:
            reply, name = session.accept(hs, load_authorized(self.settings["peers"]))
        except E2EError as exc:
            log.warning("rejected handshake: %s (add the provider's .pub to %s to allow it)", exc, self.settings["peers"])
            conn.send(e2e_error(str(exc)))
            return
        self.session = session
        conn.send({"type": "e2e", "hs": reply})
        log.info("handshake with provider %r (%s) ok, waiting for confirmation", name, session.peer_fingerprint)

    async def receive(self, conn, msg):
        if self.session is None:
            return
        try:
            first = not self.session.confirmed
            obj = self.session.decrypt(msg)
        except E2EError as exc:
            log.warning("dropped message: %s", exc)
            return
        if first:
            log.info("end-to-end session established with %s; typing enabled", self.session.peer_fingerprint)
        kind = obj.get("type")
        if kind == "key":
            code, down = obj.get("code"), obj.get("down")
            if valid_key_code(code) and isinstance(down, bool):
                self.kb.key(code, down)
        elif kind == "text" and isinstance(obj.get("text"), str):
            await self.kb.type_text(obj["text"][:4096])
        elif kind == "release_all":
            self.kb.release_all()

    async def run_connection(self, conn):
        pinger = asyncio.create_task(ping_loop(conn))
        try:
            while True:
                await self.handle(conn, await conn.recv(READ_TIMEOUT))
        except (ConnectionError, OSError, asyncio.TimeoutError, ValueError) as exc:
            log.warning("disconnected: %s", describe(exc))
        finally:
            pinger.cancel()
            self.end_session()
            conn.close()

    async def run(self):
        server, fingerprint = self.settings["server"], self.settings["fingerprint"]
        if not load_authorized(self.settings["peers"]):
            log.warning("no provider keys in %s: every provider will be refused until you add one", self.settings["peers"])
        backoff = 1
        while True:
            try:
                conn, name = await connect_and_auth(server, fingerprint, self.key, "receiver",
                                                    proxy=self.settings["proxy"])
            except AuthError as exc:
                log.error("%s (retrying in 60s)", exc)
                delay = 60
            except (OSError, asyncio.TimeoutError, ConnectionError, ValueError) as exc:
                log.warning("connecting to %s failed: %s (retrying in %ds)", server, describe(exc), backoff)
                delay, backoff = backoff, min(backoff * 2, 30)
            else:
                log.info("connected to %s as receiver %r", server, name)
                backoff = 1
                await self.run_connection(conn)
                delay = 1
            await asyncio.sleep(delay)


def main():
    parser = argparse.ArgumentParser(description="kbrelay receiver (virtual keyboard)")
    add_client_args(parser)
    parser.add_argument("--dry-run", action="store_true", help="print key events instead of typing them")
    parser.add_argument("--device-name", default="kbrelay virtual keyboard")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        settings = resolve_settings(args, "receiver")
        key = load_private_key(settings["key"])
    except Exception as exc:
        sys.exit(describe(exc))

    backend = PrintBackend() if args.dry_run else UInputBackend(args.device_name)
    kb = Keyboard(backend, dry_run=args.dry_run)
    try:
        asyncio.run(Receiver(settings, key, kb).run())
    except KeyboardInterrupt:
        pass
    finally:
        kb.release_all()
        backend.close()


if __name__ == "__main__":
    main()
