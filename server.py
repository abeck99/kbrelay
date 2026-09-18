#!/usr/bin/env python3
"""kbrelay relay server.

  server.py init [--dir DIR]         create the TLS certificate and key folders
  server.py run  [--dir DIR]         run the relay
  server.py fingerprint [--dir DIR]  print the certificate fingerprint clients must pin

Authorized keys live in DIR/providers/*.pub and DIR/receivers/*.pub. The file name
(without .pub) is the name shown to providers. New keys work without a restart;
send SIGHUP to also disconnect sessions whose key file was removed.

Key events are end-to-end encrypted between provider and receiver: this relay only
learns who is attached to whom and forwards opaque "e2e" blobs between them.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import logging
import os
import signal
import ssl
import sys
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from kbrelay_common import (
    DEFAULT_PORT, MAX_E2E_BLOB, MAX_LINE, PROTOCOL, READ_TIMEOUT, Connection, auth_payload, b64e,
    cert_fingerprint, describe, load_authorized, parse_public_key, raw_public_bytes, ssh_fingerprint,
)

log = logging.getLogger("kbrelay")
ROLE_DIRS = {"provider": "providers", "receiver": "receivers"}
HANDSHAKE_TIMEOUT = 10


class Peer:
    def __init__(self, conn: Connection, role: str, name: str, raw_key: bytes, addr: str):
        self.conn, self.role, self.name, self.raw_key, self.addr = conn, role, name, raw_key, addr
        self.target: Peer | None = None    # providers: the receiver they're attached to
        self.provider: Peer | None = None  # receivers: the provider attached to them (at most one)


class Hub:
    def __init__(self, root: Path, fingerprint: str):
        self.root = root
        self.fingerprint = fingerprint
        self.receivers: dict[str, Peer] = {}
        self.providers: set[Peer] = set()

    def authorized(self, role: str) -> dict[bytes, str]:
        return load_authorized(self.root / ROLE_DIRS[role])

    # ---------------------------------------------------------------- connection lifecycle

    async def handle(self, reader, writer):
        peername = writer.get_extra_info("peername")
        addr = f"{peername[0]}:{peername[1]}" if peername else "?"
        conn = Connection(reader, writer)
        try:
            peer = await self.handshake(conn, addr)
            if peer is None:
                return
            if peer.role == "receiver":
                await self.run_receiver(peer)
            else:
                await self.run_provider(peer)
        except (ConnectionError, OSError, asyncio.TimeoutError, ValueError, TypeError) as exc:
            log.debug("connection %s ended: %s", addr, describe(exc))
        finally:
            conn.close()

    async def handshake(self, conn: Connection, addr: str) -> Peer | None:
        hello = await conn.recv(HANDSHAKE_TIMEOUT)
        role = hello.get("role")
        if hello.get("type") != "hello" or hello.get("protocol") != PROTOCOL or role not in ROLE_DIRS:
            await conn.send_now({"type": "error", "message": f"expected a {PROTOCOL} hello"})
            return None
        try:
            pub = parse_public_key(str(hello.get("pubkey", "")))
        except Exception:
            await conn.send_now({"type": "error", "message": "invalid public key (ssh-ed25519 required)"})
            return None

        nonce = os.urandom(32)
        await conn.send_now({"type": "challenge", "nonce": b64e(nonce)})
        reply = await conn.recv(HANDSHAKE_TIMEOUT)

        raw = raw_public_bytes(pub)
        name = self.authorized(role).get(raw)
        try:
            sig = base64.b64decode(str(reply.get("sig", "")), validate=True)
            pub.verify(sig, auth_payload(role, nonce, self.fingerprint))
            sig_ok = reply.get("type") == "auth"
        except (InvalidSignature, ValueError):
            sig_ok = False

        if name is None or not sig_ok:
            reason = f"unknown key {ssh_fingerprint(pub)}" if name is None else "bad signature"
            log.warning("rejected %s from %s: %s", role, addr, reason)
            await conn.send_now({"type": "error", "message": f"not authorized as {role}"})
            return None

        log.info("%s %r connected from %s", role, name, addr)
        conn.send({"type": "welcome", "name": name, "role": role})
        return Peer(conn, role, name, raw, addr)

    # ---------------------------------------------------------------- receivers

    async def run_receiver(self, peer: Peer):
        old = self.receivers.get(peer.name)
        self.receivers[peer.name] = peer
        if old is not None:
            log.info("receiver %r reconnected, replacing previous session", peer.name)
            self.detach_receiver(old, f"{peer.name} reconnected")
            old.conn.close()
        self.broadcast_receivers()  # providers that wanted this receiver re-select and re-handshake
        try:
            while True:
                msg = await peer.conn.recv(READ_TIMEOUT)
                kind = msg.get("type")
                if kind == "e2e":
                    self.forward_e2e(peer, peer.provider, msg)
                elif kind == "ping":
                    peer.conn.send({"type": "pong"})
        finally:
            if self.receivers.get(peer.name) is peer:
                del self.receivers[peer.name]
                self.detach_receiver(peer, f"{peer.name} went offline")
                self.broadcast_receivers()
            log.info("receiver %r disconnected", peer.name)

    def detach_receiver(self, receiver: Peer, reason: str):
        provider = receiver.provider
        receiver.provider = None
        if provider is not None and provider.target is receiver:
            provider.target = None
            provider.conn.send({"type": "selected", "receiver": None, "reason": reason})

    def receivers_msg(self) -> dict:
        return {"type": "receivers", "receivers": sorted(self.receivers)}

    def broadcast_receivers(self):
        msg = self.receivers_msg()
        for provider in self.providers:
            provider.conn.send(msg)

    # ---------------------------------------------------------------- providers

    async def run_provider(self, peer: Peer):
        self.providers.add(peer)
        peer.conn.send(self.receivers_msg())
        try:
            while True:
                msg = await peer.conn.recv(READ_TIMEOUT)
                kind = msg.get("type")
                if kind == "e2e":
                    self.forward_e2e(peer, peer.target, msg)
                elif kind == "select":
                    self.select(peer, msg.get("receiver"))
                elif kind == "ping":
                    peer.conn.send({"type": "pong"})
        finally:
            self.providers.discard(peer)
            self.select(peer, None, notify=False)
            log.info("provider %r disconnected", peer.name)

    @staticmethod
    def forward_e2e(sender: Peer, target: Peer | None, msg: dict):
        """Pass an end-to-end blob through untouched (only its known fields, size-capped)."""
        if target is None:
            return
        out = {"type": "e2e"}
        for field in ("hs", "ct", "err"):
            if field in msg:
                out[field] = msg[field]
        if len(out) > 1 and len(Connection.encode(out)) <= MAX_E2E_BLOB:
            target.conn.send(out)

    def select(self, peer: Peer, name, notify: bool = True):
        new = self.receivers.get(name) if isinstance(name, str) else None
        if new is not peer.target:
            if peer.target is not None:
                old = peer.target
                peer.target = None
                if old.provider is peer:
                    old.provider = None
                    old.conn.send({"type": "detached", "provider": peer.name})
            if new is not None:
                if new.provider is not None and new.provider is not peer:  # take over from another provider
                    other = new.provider
                    other.target = None
                    other.conn.send({"type": "selected", "receiver": None,
                                     "reason": f"{new.name} was taken over by provider {peer.name}"})
                    log.info("provider %r took %r over from provider %r", peer.name, new.name, other.name)
                new.provider = peer
                peer.target = new
                new.conn.send({"type": "attached", "provider": peer.name})
                log.info("provider %r attached to %r", peer.name, new.name)
        if notify:
            reply = {"type": "selected", "receiver": new.name if new else None}
            if name and new is None:
                reply["reason"] = f"{name} is not online"
            peer.conn.send(reply)

    def revalidate(self):
        auth = {role: self.authorized(role) for role in ROLE_DIRS}
        for peer in [*self.receivers.values(), *self.providers]:
            if auth[peer.role].get(peer.raw_key) != peer.name:
                log.warning("key for %s %r no longer authorized, disconnecting", peer.role, peer.name)
                peer.conn.close()
        log.info("authorized keys reloaded")


# -------------------------------------------------------------------- CLI

def generate_certificate(cert_path: Path, key_path: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kbrelay")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    pem_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem_key)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def read_fingerprint(cert_path: Path) -> str:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert_fingerprint(cert.public_bytes(serialization.Encoding.DER))


def cmd_init(args):
    root = Path(args.dir)
    root.mkdir(parents=True, exist_ok=True)
    for sub in ROLE_DIRS.values():
        (root / sub).mkdir(exist_ok=True)
    cert, key = root / "server.crt", root / "server.key"
    if cert.exists() and not args.force:
        print(f"{cert} already exists (use --force to replace it; clients would need the new fingerprint)")
    else:
        generate_certificate(cert, key)
        print(f"created {cert} and {key}")
    print(f"put provider keys in  {root / 'providers'}/<name>.pub")
    print(f"put receiver keys in  {root / 'receivers'}/<name>.pub")
    print(f"fingerprint: {read_fingerprint(cert)}")


async def serve(args):
    root = Path(args.dir)
    cert, key = root / "server.crt", root / "server.key"
    if not cert.exists():
        sys.exit(f"{cert} not found; run `server.py init --dir {root}` first")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    fingerprint = read_fingerprint(cert)
    hub = Hub(root, fingerprint)

    loop = asyncio.get_running_loop()

    def quiet_tls_errors(loop, context):  # port scanners cause a lot of handshake noise
        if isinstance(context.get("exception"), (ssl.SSLError, ConnectionError, TimeoutError)):
            log.debug("%s", context.get("message"))
            return
        loop.default_exception_handler(context)

    loop.set_exception_handler(quiet_tls_errors)
    try:
        loop.add_signal_handler(signal.SIGHUP, hub.revalidate)
    except (NotImplementedError, AttributeError):
        pass

    server = await asyncio.start_server(hub.handle, args.host, args.port, ssl=ctx,
                                        limit=MAX_LINE, ssl_handshake_timeout=HANDSHAKE_TIMEOUT)
    log.info("listening on %s:%d, certificate fingerprint %s", args.host, args.port, fingerprint)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="kbrelay relay server")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "run", "fingerprint"):
        p = sub.add_parser(name)
        p.add_argument("--dir", default="/etc/kbrelay", help="data directory (default /etc/kbrelay)")
        if name == "init":
            p.add_argument("--force", action="store_true", help="replace an existing certificate")
        if name == "run":
            p.add_argument("--host", default="0.0.0.0")
            p.add_argument("--port", type=int, default=DEFAULT_PORT)
            p.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if args.command == "init":
        cmd_init(args)
    elif args.command == "fingerprint":
        print(read_fingerprint(Path(args.dir) / "server.crt"))
    else:
        try:
            asyncio.run(serve(args))
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
