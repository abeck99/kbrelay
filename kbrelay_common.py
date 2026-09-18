"""Shared protocol, crypto, framing and key-code helpers for kbrelay.

Wire format: newline-delimited JSON over TLS to the relay. Key events travel
inside an end-to-end encrypted session between provider and receiver (see the
Session class), so the relay only routes opaque blobs. Key events carry Linux
evdev key codes (e.g. 30 = KEY_A), which describe *physical key positions*, so
the receiver's own keyboard layout decides which character is produced.
"""
from __future__ import annotations

import asyncio
import base64
import getpass
import hashlib
import hmac
import json
import re
import ssl
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_ssh_private_key,
    load_ssh_public_key,
)

PROTOCOL = "kbrelay-1"
DEFAULT_PORT = 7433
MAX_LINE = 64 * 1024
PING_INTERVAL = 20
READ_TIMEOUT = 60
CONFIG_DIR = Path.home() / ".config" / "kbrelay"
DEFAULT_CONFIG = CONFIG_DIR / "config.json"
DEFAULT_KEY = CONFIG_DIR / "id_ed25519"
DEFAULT_PEERS = {"provider": CONFIG_DIR / "receivers", "receiver": CONFIG_DIR / "providers"}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
E2E_PROTOCOL = b"kbrelay-e2e-1"
MAX_E2E_BLOB = 16 * 1024


class AuthError(Exception):
    """Authentication or server-identity failure."""


class E2EError(Exception):
    """End-to-end handshake or decryption failure."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text, expected_len: int | None = None) -> bytes:
    try:
        data = base64.b64decode(str(text), validate=True)
    except (ValueError, TypeError):
        raise E2EError("malformed base64") from None
    if expected_len is not None and len(data) != expected_len:
        raise E2EError("malformed field")
    return data


def describe(exc: BaseException) -> str:
    return str(exc) or type(exc).__name__


# --------------------------------------------------------------------------- keys

def parse_public_key(line: str) -> Ed25519PublicKey:
    key = load_ssh_public_key(line.strip().encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("only ssh-ed25519 keys are supported")
    return key


def raw_public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def openssh_public_line(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()


def ssh_fingerprint(key: Ed25519PublicKey) -> str:
    """Same format as `ssh-keygen -lf key.pub`."""
    blob = base64.b64decode(key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).split()[1])
    return "SHA256:" + b64e(hashlib.sha256(blob).digest()).rstrip("=")


def load_private_key(path, prompt=None) -> Ed25519PrivateKey:
    path = Path(path).expanduser()
    data = path.read_bytes()
    try:
        key = load_ssh_private_key(data, None)
    except (TypeError, ValueError) as exc:
        if "password" not in str(exc).lower() and "encrypt" not in str(exc).lower():
            raise
        prompt = prompt or (lambda p: getpass.getpass(f"Passphrase for {p}: "))
        passphrase = prompt(path)
        if passphrase is None:
            raise AuthError("no passphrase given") from None
        key = load_ssh_private_key(data, passphrase.encode())  # needs the `bcrypt` package
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an ed25519 key (use ssh-keygen -t ed25519)")
    return key


def load_authorized(directory: Path) -> dict[bytes, str]:
    """Map raw public key -> name (the .pub file's name without extension)."""
    result: dict[bytes, str] = {}
    if not directory.is_dir():
        return result
    for pub_file in sorted(directory.glob("*.pub")):
        for line in pub_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                result[raw_public_bytes(parse_public_key(line))] = pub_file.stem
            except Exception:
                pass
    return result


def auth_payload(role: str, nonce: bytes, server_fingerprint: str) -> bytes:
    """What the client signs: binds the signature to this protocol, role and server certificate."""
    return b"\n".join([PROTOCOL.encode(), b"client-auth", role.encode(), server_fingerprint.encode(), nonce])


def cert_fingerprint(der: bytes) -> str:
    return "SHA256:" + b64e(hashlib.sha256(der).digest()).rstrip("=")


def normalize_fingerprint(fp: str) -> str:
    fp = fp.strip()
    if not fp.startswith("SHA256:"):
        fp = "SHA256:" + fp
    return fp.rstrip("=")


# --------------------------------------------------------------------------- end-to-end encryption

def _hs_payload(step: bytes, *parts: bytes) -> bytes:
    return b"\n".join([E2E_PROTOCOL, step, *parts])


class Session:
    """End-to-end encrypted session between one provider and one receiver.

    Handshake (relayed as {"type":"e2e","hs":{...}} messages the relay can't read into):
      1. provider -> receiver: identity pubkey, ephemeral X25519 pubkey, ed25519 signature over it
      2. receiver -> provider: its identity pubkey, its ephemeral pubkey, signature over
         (provider ephemeral, receiver ephemeral, provider identity)
    Both sides derive two ChaCha20-Poly1305 keys (one per direction) with HKDF from the X25519
    shared secret and a transcript hash of both identities and both ephemerals. Every message
    carries a strictly increasing counter that doubles as the nonce, so nothing can be replayed
    or reordered. The relay learns who talks to whom, but not what is typed.
    """

    def __init__(self, identity: Ed25519PrivateKey, role: str):
        assert role in ("provider", "receiver")
        self.identity, self.role = identity, role
        self.my_raw = raw_public_bytes(identity.public_key())
        self.eph = X25519PrivateKey.generate()
        self.eph_pub = self.eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.peer_key: Ed25519PublicKey | None = None
        self.send_aead = self.recv_aead = None
        self.send_counter = 0
        self.recv_counter = 0
        self.confirmed = False  # a message from the peer has decrypted correctly

    # -- provider side ------------------------------------------------------------------------
    def hello(self) -> dict:
        sig = self.identity.sign(_hs_payload(b"hs1", self.eph_pub))
        return {"step": 1, "pub": openssh_public_line(self.identity), "epk": b64e(self.eph_pub), "sig": b64e(sig)}

    def finish(self, hs: dict) -> Ed25519PublicKey:
        """Verify the receiver's reply and derive keys. Returns the receiver's identity key;
        the caller must decide whether that key is trusted before using the session."""
        peer_key, peer_raw = self._peer_identity(hs)
        peer_epk = b64d(hs.get("epk"), 32)
        try:
            peer_key.verify(b64d(hs.get("sig")), _hs_payload(b"hs2", self.eph_pub, peer_epk, self.my_raw))
        except InvalidSignature:
            raise E2EError("bad receiver signature") from None
        self._derive(peer_epk, provider_raw=self.my_raw, receiver_raw=peer_raw)
        self.peer_key = peer_key
        return peer_key

    # -- receiver side ------------------------------------------------------------------------
    def accept(self, hs: dict, authorized: dict[bytes, str]) -> tuple[dict, str]:
        """Check the provider against the allowlist, derive keys, return (reply, provider name)."""
        peer_key, peer_raw = self._peer_identity(hs)
        name = authorized.get(peer_raw)
        if name is None:
            raise E2EError(f"provider key {ssh_fingerprint(peer_key)} is not authorized on this receiver")
        peer_epk = b64d(hs.get("epk"), 32)
        try:
            peer_key.verify(b64d(hs.get("sig")), _hs_payload(b"hs1", peer_epk))
        except InvalidSignature:
            raise E2EError("bad provider signature") from None
        sig = self.identity.sign(_hs_payload(b"hs2", peer_epk, self.eph_pub, peer_raw))
        self._derive(peer_epk, provider_raw=peer_raw, receiver_raw=self.my_raw)
        self.peer_key = peer_key
        reply = {"step": 2, "pub": openssh_public_line(self.identity), "epk": b64e(self.eph_pub), "sig": b64e(sig)}
        return reply, name

    # -- both sides ---------------------------------------------------------------------------
    def encrypt(self, obj) -> dict:
        if self.send_aead is None:
            raise E2EError("session not established")
        counter = self.send_counter
        self.send_counter += 1
        ct = self.send_aead.encrypt(counter.to_bytes(12, "big"), Connection.encode(obj), E2E_PROTOCOL)
        return {"type": "e2e", "ct": b64e(counter.to_bytes(8, "big") + ct)}

    def decrypt(self, msg: dict) -> dict:
        if self.recv_aead is None:
            raise E2EError("session not established")
        data = b64d(msg.get("ct"))
        if len(data) < 8 + 16:
            raise E2EError("malformed ciphertext")
        counter = int.from_bytes(data[:8], "big")
        if counter < self.recv_counter:
            raise E2EError("replayed or reordered message")
        try:
            plain = self.recv_aead.decrypt(counter.to_bytes(12, "big"), data[8:], E2E_PROTOCOL)
        except Exception:
            raise E2EError("message failed authentication") from None
        self.recv_counter = counter + 1
        self.confirmed = True
        obj = json.loads(plain)
        if not isinstance(obj, dict):
            raise E2EError("malformed message")
        return obj

    @property
    def peer_fingerprint(self) -> str:
        return ssh_fingerprint(self.peer_key) if self.peer_key else "?"

    @staticmethod
    def _peer_identity(hs: dict) -> tuple[Ed25519PublicKey, bytes]:
        if not isinstance(hs, dict):
            raise E2EError("malformed handshake")
        try:
            key = parse_public_key(str(hs.get("pub", "")))
        except Exception:
            raise E2EError("malformed peer public key") from None
        return key, raw_public_bytes(key)

    def _derive(self, peer_epk: bytes, provider_raw: bytes, receiver_raw: bytes) -> None:
        shared = self.eph.exchange(X25519PublicKey.from_public_bytes(peer_epk))
        p_epk, r_epk = (self.eph_pub, peer_epk) if self.role == "provider" else (peer_epk, self.eph_pub)
        transcript = hashlib.sha256(b"\n".join([E2E_PROTOCOL, provider_raw, receiver_raw, p_epk, r_epk])).digest()
        okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=transcript, info=b"kbrelay-e2e-1 keys").derive(shared)
        k_p2r, k_r2p = okm[:32], okm[32:]
        if self.role == "provider":
            self.send_aead, self.recv_aead = ChaCha20Poly1305(k_p2r), ChaCha20Poly1305(k_r2p)
        else:
            self.send_aead, self.recv_aead = ChaCha20Poly1305(k_r2p), ChaCha20Poly1305(k_p2r)


def e2e_error(message: str) -> dict:
    return {"type": "e2e", "err": message[:200]}


# --------------------------------------------------------------------------- transport

class Connection:
    """JSON-lines connection with a single writer task (so slow peers never block the sender)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, max_queue: int = 5000):
        self.reader = reader
        self.writer = writer
        self.max_queue = max_queue
        self.closed = False
        self._queue: asyncio.Queue = asyncio.Queue()
        self._task = asyncio.get_running_loop().create_task(self._writer_loop())

    @staticmethod
    def encode(obj) -> bytes:
        return json.dumps(obj, separators=(",", ":")).encode() + b"\n"

    def send(self, obj) -> None:
        if self.closed:
            return
        if self._queue.qsize() >= self.max_queue:
            self.close()  # peer isn't reading; drop it rather than buffer forever
            return
        self._queue.put_nowait(obj)

    async def send_now(self, obj) -> None:
        """Direct write; only used during the handshake, before anything is queued."""
        self.writer.write(self.encode(obj))
        await self.writer.drain()

    async def recv(self, timeout: float | None = None) -> dict:
        line = await asyncio.wait_for(self.reader.readline(), timeout)
        if not line:
            raise ConnectionError("connection closed")
        msg = json.loads(line)
        if not isinstance(msg, dict):
            raise ValueError("malformed message")
        return msg

    async def _writer_loop(self) -> None:
        try:
            while True:
                obj = await self._queue.get()
                self.writer.write(self.encode(obj))
                await self.writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            pass
        finally:
            self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if asyncio.current_task() is not self._task:
            self._task.cancel()
        try:
            self.writer.close()
        except Exception:
            pass


async def ping_loop(conn: Connection) -> None:
    while not conn.closed:
        await asyncio.sleep(PING_INTERVAL)
        conn.send({"type": "ping"})


def split_host_port(server: str) -> tuple[str, int]:
    server = server.strip()
    if server.startswith("["):
        host, _, rest = server[1:].partition("]")
        return host, int(rest.lstrip(":") or DEFAULT_PORT)
    if server.count(":") == 1:
        host, port = server.split(":")
        return host, int(port)
    return server, DEFAULT_PORT


def client_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # The server uses a self-signed certificate; instead of CA validation we pin its
    # SHA-256 fingerprint in connect_and_auth() before sending anything.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def connect_and_auth(server: str, fingerprint: str, key: Ed25519PrivateKey, role: str,
                           timeout: float = 15) -> tuple[Connection, str]:
    host, port = split_host_port(server)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=client_ssl_context(), limit=MAX_LINE), timeout)
    conn = Connection(reader, writer)
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        actual = cert_fingerprint(der)
        if not hmac.compare_digest(actual, normalize_fingerprint(fingerprint)):
            raise AuthError(f"server certificate fingerprint mismatch (server presented {actual})")
        await conn.send_now({"type": "hello", "protocol": PROTOCOL, "role": role,
                             "pubkey": openssh_public_line(key)})
        msg = await conn.recv(timeout)
        if msg.get("type") != "challenge":
            raise AuthError(msg.get("message") or "unexpected reply from server")
        nonce = base64.b64decode(msg.get("nonce", ""))
        if len(nonce) != 32:
            raise AuthError("malformed challenge")
        await conn.send_now({"type": "auth", "sig": b64e(key.sign(auth_payload(role, nonce, actual)))})
        msg = await conn.recv(timeout)
        if msg.get("type") != "welcome":
            raise AuthError(msg.get("message") or "authentication failed")
        return conn, str(msg.get("name", "?"))
    except BaseException:
        conn.close()
        raise


# --------------------------------------------------------------------------- config

def add_client_args(parser) -> None:
    parser.add_argument("--config", help=f"JSON config file (default {DEFAULT_CONFIG})")
    parser.add_argument("--server", help="relay address, e.g. 203.0.113.10:7433")
    parser.add_argument("--fingerprint", help="server certificate fingerprint (SHA256:...)")
    parser.add_argument("--key", help=f"ed25519 private key (default {DEFAULT_KEY})")
    parser.add_argument("--peers", help="directory of trusted peer .pub files "
                        "(default ~/.config/kbrelay/receivers for the provider, .../providers for the receiver)")


def resolve_settings(args, role: str) -> dict:
    path = Path(args.config).expanduser() if args.config else DEFAULT_CONFIG
    config = {}
    if path.exists():
        config = json.loads(path.read_text())
    elif args.config:
        raise FileNotFoundError(f"config file not found: {path}")
    settings = {
        "server": args.server or config.get("server"),
        "fingerprint": args.fingerprint or config.get("fingerprint"),
        "key": args.key or config.get("key") or str(DEFAULT_KEY),
        "peers": Path(args.peers or config.get("peers") or DEFAULT_PEERS[role]).expanduser(),
    }
    missing = [k for k in ("server", "fingerprint") if not settings[k]]
    if missing:
        raise ValueError(f"missing setting(s): {', '.join(missing)}. "
                         f"Pass --{missing[0]} or create {path} (see README).")
    return settings


# --------------------------------------------------------------------------- key codes

_KEY_TABLE = """
1 ESC 2 1 3 2 4 3 5 4 6 5 7 6 8 7 9 8 10 9 11 0 12 MINUS 13 EQUAL 14 BACKSPACE 15 TAB
16 Q 17 W 18 E 19 R 20 T 21 Y 22 U 23 I 24 O 25 P 26 LEFTBRACE 27 RIGHTBRACE 28 ENTER 29 LEFTCTRL
30 A 31 S 32 D 33 F 34 G 35 H 36 J 37 K 38 L 39 SEMICOLON 40 APOSTROPHE 41 GRAVE 42 LEFTSHIFT
43 BACKSLASH 44 Z 45 X 46 C 47 V 48 B 49 N 50 M 51 COMMA 52 DOT 53 SLASH 54 RIGHTSHIFT
55 KPASTERISK 56 LEFTALT 57 SPACE 58 CAPSLOCK 59 F1 60 F2 61 F3 62 F4 63 F5 64 F6 65 F7 66 F8
67 F9 68 F10 69 NUMLOCK 70 SCROLLLOCK 71 KP7 72 KP8 73 KP9 74 KPMINUS 75 KP4 76 KP5 77 KP6
78 KPPLUS 79 KP1 80 KP2 81 KP3 82 KP0 83 KPDOT 86 102ND 87 F11 88 F12 96 KPENTER 97 RIGHTCTRL
98 KPSLASH 99 SYSRQ 100 RIGHTALT 102 HOME 103 UP 104 PAGEUP 105 LEFT 106 RIGHT 107 END 108 DOWN
109 PAGEDOWN 110 INSERT 111 DELETE 113 MUTE 114 VOLUMEDOWN 115 VOLUMEUP 117 KPEQUAL 119 PAUSE
121 KPCOMMA 125 LEFTMETA 126 RIGHTMETA 127 COMPOSE 163 NEXTSONG 164 PLAYPAUSE 165 PREVIOUSSONG
166 STOPCD
"""
_tokens = _KEY_TABLE.split()
KEY: dict[str, int] = {_tokens[i + 1]: int(_tokens[i]) for i in range(0, len(_tokens), 2)}
KEY.update({f"F{13 + i}": 183 + i for i in range(12)})
KEY_NAMES: dict[int, str] = {code: name for name, code in KEY.items()}


def valid_key_code(code) -> bool:
    """Only the keys in KEY_NAMES: no mouse/joystick BTN_* codes and none of the power/sleep/
    suspend/restart keys, which a compromised relay or provider could otherwise use to turn the
    receiver off."""
    return isinstance(code, int) and not isinstance(code, bool) and code in KEY_NAMES


def key_name(code: int) -> str:
    return "KEY_" + KEY_NAMES.get(code, str(code))
