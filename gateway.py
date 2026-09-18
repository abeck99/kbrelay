#!/usr/bin/env python3
"""kbrelay web gateway: a headless provider with a browser-based keyboard.

It connects to the relay like any provider (its own key, end-to-end encrypted to the receiver),
and serves a small password-protected web page so a phone or tablet on your tailnet can type into
a receiver. Intended to run in Docker on an always-on box (e.g. a NAS) reachable only over Tailscale.

Because the gateway holds a provider key and does the encryption in Python, it can see what is typed
through it: it is a *trusted* node, unlike the relay. Keep it off the public internet (Tailscale +
the login below), and give it its own key you can revoke.

Config comes from environment variables (see the README / Dockerfile):
  KBRELAY_SERVER, KBRELAY_FINGERPRINT, KBRELAY_KEY, KBRELAY_PEERS, KBRELAY_NAME, KBRELAY_PROXY
  GATEWAY_HOST, GATEWAY_PORT, GATEWAY_PASSWORD or GATEWAY_PASSWORD_HASH,
  GATEWAY_SECRET, GATEWAY_SESSION_HOURS, GATEWAY_COOKIE_SECURE

  python gateway.py hash-password        # print a GATEWAY_PASSWORD_HASH value
  python gateway.py run                   # run the gateway (default)
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
from pathlib import Path

from aiohttp import WSMsgType, web

from kbrelay_common import (
    KEY, NAME_RE, READ_TIMEOUT, AuthError, E2EError, Session, connect_and_auth, describe,
    load_authorized, load_private_key, parse_proxy, ping_loop, raw_public_bytes, ssh_fingerprint,
)

log = logging.getLogger("kbrelay.gateway")
COOKIE = "kbgw_session"

# ------------------------------------------------------------------ JS KeyboardEvent.code -> KEY name

def _build_js_map() -> dict[str, int]:
    names = {
        "Escape": "ESC", "Minus": "MINUS", "Equal": "EQUAL", "Backspace": "BACKSPACE", "Tab": "TAB",
        "BracketLeft": "LEFTBRACE", "BracketRight": "RIGHTBRACE", "Enter": "ENTER",
        "ControlLeft": "LEFTCTRL", "Semicolon": "SEMICOLON", "Quote": "APOSTROPHE", "Backquote": "GRAVE",
        "ShiftLeft": "LEFTSHIFT", "Backslash": "BACKSLASH", "Comma": "COMMA", "Period": "DOT",
        "Slash": "SLASH", "ShiftRight": "RIGHTSHIFT", "NumpadMultiply": "KPASTERISK", "AltLeft": "LEFTALT",
        "Space": "SPACE", "CapsLock": "CAPSLOCK", "NumLock": "NUMLOCK", "ScrollLock": "SCROLLLOCK",
        "NumpadSubtract": "KPMINUS", "NumpadAdd": "KPPLUS", "NumpadDecimal": "KPDOT",
        "NumpadEnter": "KPENTER", "ControlRight": "RIGHTCTRL", "NumpadDivide": "KPSLASH",
        "PrintScreen": "SYSRQ", "AltRight": "RIGHTALT", "Home": "HOME", "ArrowUp": "UP", "PageUp": "PAGEUP",
        "ArrowLeft": "LEFT", "ArrowRight": "RIGHT", "End": "END", "ArrowDown": "DOWN", "PageDown": "PAGEDOWN",
        "Insert": "INSERT", "Delete": "DELETE", "MetaLeft": "LEFTMETA", "MetaRight": "RIGHTMETA",
        "ContextMenu": "COMPOSE", "Pause": "PAUSE",
    }
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        names[f"Key{c}"] = c
    for d in "0123456789":
        names[f"Digit{d}"] = d
        names[f"Numpad{d}"] = f"KP{d}"
    for i in range(1, 25):
        names[f"F{i}"] = f"F{i}"
    return {js: KEY[k] for js, k in names.items() if k in KEY}


JS_TO_CODE = _build_js_map()


# ------------------------------------------------------------------ config

class Config:
    def __init__(self):
        env = os.environ.get
        self.server = env("KBRELAY_SERVER")
        self.fingerprint = env("KBRELAY_FINGERPRINT")
        self.key = env("KBRELAY_KEY", "/config/id_ed25519")
        self.peers = Path(env("KBRELAY_PEERS", "/config/receivers"))
        self.name = env("KBRELAY_NAME") or None
        self.proxy = parse_proxy(env("KBRELAY_PROXY"))
        self.host = env("GATEWAY_HOST", "0.0.0.0")
        self.port = int(env("GATEWAY_PORT", "8384"))
        self.password = env("GATEWAY_PASSWORD")
        self.password_hash = env("GATEWAY_PASSWORD_HASH")
        self.secret = env("GATEWAY_SECRET")
        self.session_seconds = int(float(env("GATEWAY_SESSION_HOURS", "12")) * 3600)
        self.cookie_secure = env("GATEWAY_COOKIE_SECURE", "true").lower() not in ("0", "false", "no")
        if self.name and not NAME_RE.match(self.name):
            raise ValueError(f"invalid KBRELAY_NAME {self.name!r}")
        for field in ("server", "fingerprint"):
            if not getattr(self, field):
                raise ValueError(f"missing required env KBRELAY_{field.upper()}")
        if not self.password and not self.password_hash:
            raise ValueError("set GATEWAY_PASSWORD (or GATEWAY_PASSWORD_HASH) so the page requires a login")
        if not self.secret:
            self.secret = secrets.token_hex(32)
            log.warning("GATEWAY_SECRET not set; using a random one, so logins won't survive a restart")


# ------------------------------------------------------------------ password + session cookie

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(cfg: Config, attempt: str) -> bool:
    if cfg.password_hash:
        try:
            _, salt_b64, hash_b64 = cfg.password_hash.split("$")
            salt, expected = base64.b64decode(salt_b64), base64.b64decode(hash_b64)
        except Exception:
            log.error("GATEWAY_PASSWORD_HASH is malformed")
            return False
        dk = hashlib.scrypt(attempt.encode(), salt=salt, n=2**14, r=8, p=1, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    return hmac.compare_digest(attempt.encode(), (cfg.password or "").encode())


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_token(cfg: Config) -> str:
    payload = _b64u(json.dumps({"exp": int(time.time()) + cfg.session_seconds}).encode())
    sig = _b64u(hmac.new(cfg.secret.encode(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def valid_token(cfg: Config, token: str | None) -> bool:
    if not token or token.count(".") != 1:
        return False
    payload, sig = token.split(".")
    expected = _b64u(hmac.new(cfg.secret.encode(), payload.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        return json.loads(_b64u_dec(payload)).get("exp", 0) > time.time()
    except Exception:
        return False


# ------------------------------------------------------------------ relay provider (headless)

class RelayProvider:
    """One persistent provider connection to the relay; drives the currently selected receiver."""

    def __init__(self, cfg: Config, key):
        self.cfg, self.identity = cfg, key
        self.conn = None
        self.receivers: list[str] = []
        self.desired: str | None = None
        self.current: str | None = None
        self.session: Session | None = None
        self.secure = False
        self.status = "starting"
        self.listeners: set = set()

    # -- state broadcast ------------------------------------------------------
    def state(self) -> dict:
        return {"t": "state", "connected": self.conn is not None, "receivers": self.receivers,
                "current": self.current, "secure": self.secure, "status": self.status,
                "fingerprint": self.session.peer_fingerprint if (self.session and self.secure) else None}

    def broadcast(self):
        msg = self.state()
        for push in list(self.listeners):
            push(msg)

    # -- actions from the browser --------------------------------------------
    def send(self, obj):
        if self.conn is not None and not self.conn.closed:
            self.conn.send(obj)

    def select(self, name):
        name = name if isinstance(name, str) and name in self.receivers else None
        self.desired = name
        self.session = None
        self.secure = False
        self.send({"type": "select", "receiver": name})

    def key(self, js_code: str, down: bool):
        code = JS_TO_CODE.get(js_code)
        if code is not None and self.secure and self.session is not None:
            self.send(self.session.encrypt({"type": "key", "code": code, "down": bool(down)}))

    def text(self, s: str):
        if isinstance(s, str) and s and self.secure and self.session is not None:
            self.send(self.session.encrypt({"type": "text", "text": s[:4096]}))

    def release_all(self):
        if self.secure and self.session is not None:
            self.send(self.session.encrypt({"type": "release_all"}))

    # -- relay message handling ----------------------------------------------
    def handle(self, msg: dict):
        kind = msg.get("type")
        if kind == "receivers":
            self.receivers = [str(n) for n in msg.get("receivers", [])]
            if self.desired in self.receivers and self.current != self.desired:
                self.send({"type": "select", "receiver": self.desired})
            self.broadcast()
        elif kind == "selected":
            self.current = msg.get("receiver")
            self.session = None
            self.secure = False
            if msg.get("reason"):
                self.status = str(msg["reason"])
            if self.current:
                self.session = Session(self.identity, "provider")
                self.send({"type": "e2e", "hs": self.session.hello()})
                self.status = f"securing session with {self.current}"
            self.broadcast()
        elif kind == "e2e":
            self.handle_e2e(msg)

    def handle_e2e(self, msg: dict):
        if "err" in msg:
            self.status = f"{self.current or 'receiver'} refused: {str(msg['err'])[:200]}"
            self.give_up()
            return
        if "hs" not in msg or self.session is None or self.session.recv_aead is not None:
            return
        try:
            receiver_key = self.session.finish(msg["hs"])
        except E2EError as exc:
            self.status = f"handshake failed: {exc}"
            self.give_up()
            return
        if raw_public_bytes(receiver_key) not in load_authorized(self.cfg.peers):
            self.status = (f"{self.current}: key {ssh_fingerprint(receiver_key)} is not trusted; "
                           f"add its .pub to {self.cfg.peers} on the gateway")
            log.warning(self.status)
            self.give_up()
            return
        self.secure = True
        self.status = f"encrypted session with {self.current}"
        self.send(self.session.encrypt({"type": "release_all"}))  # confirms the session on the receiver
        log.info("secure session with %r (%s)", self.current, self.session.peer_fingerprint)
        self.broadcast()

    def give_up(self):
        self.session = None
        self.secure = False
        self.desired = None
        self.send({"type": "select", "receiver": None})
        self.broadcast()

    # -- connection loop ------------------------------------------------------
    async def run(self):
        backoff = 1
        while True:
            try:
                self.status = f"connecting to {self.cfg.server}"
                self.broadcast()
                conn, name = await connect_and_auth(self.cfg.server, self.cfg.fingerprint, self.identity,
                                                    "provider", proxy=self.cfg.proxy, name=self.cfg.name)
            except AuthError as exc:
                self.status = f"{exc}"
                log.error("%s (retry 30s)", exc)
                delay = 30
            except Exception as exc:
                self.status = f"connection failed: {describe(exc)}"
                log.warning("connect failed: %s (retry %ds)", describe(exc), backoff)
                delay, backoff = backoff, min(backoff * 2, 30)
            else:
                log.info("connected to relay as provider %r", name)
                self.conn, backoff = conn, 1
                self.current = None
                self.status = f"connected as {name}"
                self.broadcast()
                pinger = asyncio.create_task(ping_loop(conn))
                try:
                    while True:
                        self.handle(await conn.recv(READ_TIMEOUT))
                except Exception as exc:
                    self.status = f"disconnected: {describe(exc)}"
                finally:
                    pinger.cancel()
                    self.conn = None
                    self.session = None
                    self.secure = False
                    conn.close()
                    self.broadcast()
                delay = 1
            await asyncio.sleep(delay)


# ------------------------------------------------------------------ web layer

def require_auth(handler):
    async def wrapper(request):
        cfg = request.app["cfg"]
        if not valid_token(cfg, request.cookies.get(COOKIE)):
            raise web.HTTPFound("/login")
        return await handler(request)
    return wrapper


async def index(request):
    cfg = request.app["cfg"]
    if not valid_token(cfg, request.cookies.get(COOKIE)):
        raise web.HTTPFound("/login")
    return web.Response(text=PAGE_HTML, content_type="text/html")


async def login_page(request):
    return web.Response(text=LOGIN_HTML.replace("{{error}}", ""), content_type="text/html")


async def login_submit(request):
    cfg = request.app["cfg"]
    gate = request.app["login_gate"]
    now = time.monotonic()
    if gate["until"] > now:
        return web.Response(text=LOGIN_HTML.replace("{{error}}",
                            "Too many attempts, wait a moment."), content_type="text/html", status=429)
    data = await request.post()
    if verify_password(cfg, str(data.get("password", ""))):
        gate["fails"] = 0
        resp = web.HTTPFound("/")
        resp.set_cookie(COOKIE, make_token(cfg), max_age=cfg.session_seconds, httponly=True,
                        samesite="Strict", secure=cfg.cookie_secure)
        return resp
    gate["fails"] += 1
    if gate["fails"] >= 5:
        gate["until"] = now + min(2 ** (gate["fails"] - 4), 60)
    await asyncio.sleep(0.5)
    return web.Response(text=LOGIN_HTML.replace("{{error}}", "Wrong password."),
                        content_type="text/html", status=401)


async def logout(request):
    resp = web.HTTPFound("/login")
    resp.del_cookie(COOKIE)
    return resp


async def websocket(request):
    cfg = request.app["cfg"]
    if not valid_token(cfg, request.cookies.get(COOKIE)):
        return web.Response(status=401, text="log in first")
    ws = web.WebSocketResponse(heartbeat=25)
    await ws.prepare(request)
    provider: RelayProvider = request.app["provider"]

    loop = asyncio.get_running_loop()

    def push(msg):
        loop.call_soon(lambda: asyncio.ensure_future(ws.send_json(msg)))

    provider.listeners.add(push)
    try:
        await ws.send_json(provider.state())
        async for raw in ws:
            if raw.type != WSMsgType.TEXT:
                continue
            try:
                msg = json.loads(raw.data)
            except ValueError:
                continue
            t = msg.get("t")
            if t == "select":
                provider.select(msg.get("receiver"))
            elif t == "key":
                provider.key(str(msg.get("code", "")), bool(msg.get("down")))
            elif t == "text":
                provider.text(msg.get("text", ""))
            elif t == "release":
                provider.release_all()
    finally:
        provider.listeners.discard(push)
        provider.release_all()   # don't leave keys held when the browser goes away
    return ws


async def on_startup(app):
    app["provider_task"] = asyncio.create_task(app["provider"].run())


async def on_cleanup(app):
    task = app.get("provider_task")
    if task is not None:
        task.cancel()


def build_app(cfg: Config) -> web.Application:
    key = load_private_key(cfg.key)
    app = web.Application()
    app["cfg"] = cfg
    app["provider"] = RelayProvider(cfg, key)
    app["login_gate"] = {"fails": 0, "until": 0.0}
    app.add_routes([
        web.get("/", index),
        web.get("/login", login_page),
        web.post("/login", login_submit),
        web.post("/logout", logout),
        web.get("/ws", websocket),
    ])
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    argv = sys.argv[1:]
    if argv and argv[0] == "hash-password":
        import getpass
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Repeat: "):
            sys.exit("passwords did not match")
        print(hash_password(pw))
        return
    if argv and argv[0] not in ("run",):
        sys.exit(__doc__)
    try:
        cfg = Config()
    except Exception as exc:
        sys.exit(f"configuration error: {describe(exc)}")
    if not cfg.peers.is_dir() or not load_authorized(cfg.peers):
        log.warning("no receiver keys in %s; add each receiver's .pub there or the gateway will "
                    "refuse to type into them", cfg.peers)
    app = build_app(cfg)
    log.info("gateway on http://%s:%d (put it behind Tailscale; log in with your password)",
             cfg.host, cfg.port)
    web.run_app(app, host=cfg.host, port=cfg.port, print=None)


# ------------------------------------------------------------------ pages

LOGIN_HTML = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1">
<title>kbrelay gateway</title><style>
body{font-family:system-ui,sans-serif;background:#12131a;color:#e8e8ef;display:flex;
min-height:100vh;align-items:center;justify-content:center;margin:0}
form{background:#1c1e28;padding:28px;border-radius:14px;width:min(90vw,320px);box-shadow:0 8px 30px #0006}
h1{font-size:18px;margin:0 0 16px}input{width:100%;box-sizing:border-box;padding:12px;font-size:16px;
border-radius:8px;border:1px solid #33354a;background:#12131a;color:#e8e8ef;margin-bottom:12px}
button{width:100%;padding:12px;font-size:16px;border:0;border-radius:8px;background:#3b82f6;color:#fff}
.err{color:#ff8080;font-size:14px;margin-bottom:10px;min-height:18px}
</style></head><body><form method=post action=/login>
<h1>kbrelay gateway</h1><div class=err>{{error}}</div>
<input type=password name=password placeholder=Password autofocus autocomplete=current-password>
<button type=submit>Log in</button></form></body></html>"""

PAGE_HTML = r"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>kbrelay</title><style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#12131a;color:#e8e8ef;margin:0;padding:10px;
-webkit-user-select:none;user-select:none}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
select,button,textarea{font-size:16px;border-radius:8px;border:1px solid #33354a;background:#1c1e28;color:#e8e8ef}
select{padding:8px;flex:1;min-width:140px}
button{padding:10px 12px;min-width:44px}
button:active{background:#3b82f6}
button.on{background:#3b82f6;border-color:#3b82f6}
#status{font-size:13px;color:#9aa0b4;flex:1;min-width:100%}
#status.secure{color:#5fd08a}#status.bad{color:#ff8080}
#pad{width:100%;height:120px;font-size:16px;padding:10px;resize:none;line-height:1.4}
.keys{display:grid;grid-template-columns:repeat(auto-fill,minmax(64px,1fr));gap:6px;margin-top:8px}
.mods{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.hint{font-size:12px;color:#7a8098;margin-top:8px;line-height:1.5}
a{color:#7aa2ff}
</style></head><body>
<div class=row>
  <select id=recv><option value="">— choose a receiver —</option></select>
  <button id=logout title="Log out">⎋</button>
</div>
<div class=row><div id=status>connecting…</div></div>

<textarea id=pad placeholder="Tap here and type. What you type is sent to the selected receiver." autocapitalize=off autocorrect=off autocomplete=off spellcheck=false></textarea>

<div class=mods>
  <button data-mod=LEFTCTRL>Ctrl</button>
  <button data-mod=LEFTALT>Alt</button>
  <button data-mod=LEFTSHIFT>Shift</button>
  <button data-mod=LEFTMETA>Super</button>
</div>
<div class=keys>
  <button data-key=Escape>Esc</button>
  <button data-key=Tab>Tab</button>
  <button data-key=Enter>Enter</button>
  <button data-key=Backspace>Bksp</button>
  <button data-key=Delete>Del</button>
  <button data-key=ArrowUp>↑</button>
  <button data-key=ArrowDown>↓</button>
  <button data-key=ArrowLeft>←</button>
  <button data-key=ArrowRight>→</button>
  <button data-key=Home>Home</button>
  <button data-key=End>End</button>
  <button data-key=PageUp>PgUp</button>
  <button data-key=PageDown>PgDn</button>
  <button id=release title="Release all held keys">Release</button>
</div>
<div class=hint>
Sticky modifiers apply to the next key or typed character (tap again to hold on/off). A hardware
keyboard paired to this device also works: its keys are captured and sent live while this page has
focus. Non-ASCII characters are typed via the receiver's helper if installed.
</div>
<script>
const $=s=>document.querySelector(s);
let ws, sticky=new Set(), secure=false;
function connect(){
  ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws');
  ws.onmessage=e=>{const m=JSON.parse(e.data); if(m.t==='state') render(m);};
  ws.onclose=()=>{setStatus('disconnected — reconnecting',false,true); setTimeout(connect,1500);};
}
function send(o){ if(ws&&ws.readyState===1) ws.send(JSON.stringify(o)); }
function setStatus(t,sec,bad){const s=$('#status'); s.textContent=t; s.className=sec?'secure':(bad?'bad':'');}
function render(m){
  const sel=$('#recv'), cur=sel.value;
  const opts=['<option value="">— choose a receiver —</option>']
    .concat(m.receivers.map(r=>`<option value="${r}"${r===m.current?' selected':''}>${r}</option>`));
  sel.innerHTML=opts.join(''); if(m.current) sel.value=m.current;
  secure=m.secure;
  let t=m.status||''; if(m.secure&&m.fingerprint) t='🔒 '+m.current+'  ·  '+m.fingerprint;
  setStatus(t,m.secure,!m.connected);
}
$('#recv').onchange=e=>send({t:'select',receiver:e.target.value});
$('#logout').onclick=()=>{fetch('/logout',{method:'POST'}).then(()=>location.href='/login');};
$('#release').onclick=()=>{sticky.clear();updateMods();send({t:'release'});};

// sticky modifiers
document.querySelectorAll('[data-mod]').forEach(b=>b.onclick=()=>{
  const code=b.dataset.mod;
  if(sticky.has(code)){sticky.delete(code); send({t:'key',code,down:false});}
  else{sticky.add(code); send({t:'key',code,down:true});}
  updateMods();
});
function updateMods(){document.querySelectorAll('[data-mod]').forEach(b=>
  b.classList.toggle('on',sticky.has(b.dataset.mod)));}
function tap(code){ send({t:'key',code,down:true}); send({t:'key',code,down:false}); dropSticky(); }
function dropSticky(){ if(sticky.size){ for(const c of sticky) send({t:'key',code:c,down:false}); sticky.clear(); updateMods(); } }
document.querySelectorAll('[data-key]').forEach(b=>b.onclick=()=>tap(b.dataset.key));

// hardware keyboard: capture raw key events while the pad has focus
const pad=$('#pad');
pad.addEventListener('keydown',e=>{
  if(e.isComposing) return;
  e.preventDefault();
  send({t:'key',code:e.code,down:true});
});
pad.addEventListener('keyup',e=>{ e.preventDefault(); send({t:'key',code:e.code,down:false}); if(sticky.size) dropSticky(); });
// soft keyboard: characters that don't produce useful key events arrive as input
pad.addEventListener('beforeinput',e=>{
  if(e.inputType==='insertText'&&e.data){ e.preventDefault(); send({t:'text',text:e.data}); dropSticky(); }
  else if(e.inputType==='insertLineBreak'||e.inputType==='insertParagraph'){ e.preventDefault(); tap('Enter'); }
  else if(e.inputType==='deleteContentBackward'){ e.preventDefault(); tap('Backspace'); }
});
pad.addEventListener('blur',()=>{ if(sticky.size){for(const c of sticky) send({t:'key',code:c,down:false}); sticky.clear(); updateMods();} });
window.addEventListener('pagehide',()=>send({t:'release'}));
connect();
</script></body></html>"""


if __name__ == "__main__":
    main()
