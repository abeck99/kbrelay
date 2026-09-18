# kbrelay: type into a remote Arch desktop from any machine

```
 provider (Windows/Linux GUI)  ──TLS──►  relay server (droplet)  ◄──TLS──  receiver (Arch)
   captures keys in a window             checks .pub keys,                  replays keys on a
   picks a receiver by name              routes opaque blobs                virtual uinput keyboard
                     └───── end-to-end encrypted (the relay can't read it) ─────┘
```

Both sides connect **out** to the relay, so neither machine needs an open port or a static IP.
Keys travel as Linux key codes (physical key positions), including Ctrl/Alt/Shift/Super, arrows,
F-keys and so on. The receiver is a kernel-level virtual keyboard, so it works on X11, any Wayland
compositor, lock screens and TTYs alike.

| File | Runs on | Needs |
|---|---|---|
| `server.py` | the relay (e.g. a DigitalOcean droplet) | `cryptography` |
| `receiver.py` | the Arch/SteamOS machine being typed into | `cryptography`, write access to `/dev/uinput` |
| `provider.py` | Windows / Linux, the machine you type on | `cryptography`, Tk |
| `kbrelay_common.py` | everywhere (copy it next to the script) | |
| `kbrelay-receiver.sh`, `kbrelay-provider.sh` | optional self-contained launchers | nothing: they fetch Python via uv into `$HOME` |

### Security model

There are two independent layers, so the relay is **not** a trusted party for your keystrokes:

1. **Connection to the relay (TLS + key auth).** The relay has a self-signed TLS certificate whose
   SHA-256 fingerprint every client pins. Each client then proves it owns an ed25519 key by signing a
   challenge; the relay checks the key against the `.pub` files you placed in `providers/` or
   `receivers/`. **The file name is the display name.** This decides *who may connect*.

2. **Provider ↔ receiver (end-to-end encryption).** Once a provider selects a receiver, the two run
   an authenticated key exchange *through* the relay: each generates a throwaway X25519 key, signs it
   with its ed25519 identity key, and they derive a shared secret (ECDH → HKDF). Every keystroke is
   then sealed with ChaCha20-Poly1305 under a per-message counter. The relay only forwards sealed
   blobs, so **it cannot read what you type or inject keystrokes**, and because the X25519 keys are
   thrown away after each session, a later theft of the relay's data *and* your identity keys still
   can't decrypt past sessions (forward secrecy). Replayed or reordered frames are rejected.

   For this to hold, each side must know the other's real identity key without asking the relay:
   - The **receiver** only accepts providers whose `.pub` is in its own trust folder
     (`~/.config/kbrelay/providers/` by default — the client's, not the server's).
   - The **provider** pins each receiver's key the first time it sees it (like SSH's known_hosts) and
     refuses to type if that key ever changes, which is what would happen if a malicious relay tried
     to impersonate the receiver. It shows the receiver's fingerprint in its window so you can compare.

So a compromised relay can drop or delay traffic, but it can't read keystrokes, forge them, or
silently stand in the middle. The private keys are the crown jewels: a stolen provider key is a
remote keyboard into the receiver; a stolen receiver key lets someone receive what a provider types.
Treat both like SSH keys, and put a passphrase on the provider key (it prompts).

---

## 1. Relay server (Ubuntu droplet)

```bash
sudo apt install python3-cryptography
sudo useradd --system --no-create-home kbrelay
sudo mkdir -p /opt/kbrelay && sudo cp server.py kbrelay_common.py /opt/kbrelay/
sudo chmod -R a+rX /opt/kbrelay     # let the kbrelay service user read the code (root's umask may not)
sudo python3 /opt/kbrelay/server.py init --dir /etc/kbrelay     # prints the fingerprint
sudo chgrp -R kbrelay /etc/kbrelay && sudo chmod -R g+rX,o-rwx /etc/kbrelay
sudo ufw allow 7433/tcp        # and allow 7433/tcp in any DigitalOcean Cloud Firewall
```

(The code in `/opt/kbrelay` is world-readable, which is fine — it's not secret. The keys and
certificate in `/etc/kbrelay` are the sensitive part, and the `chgrp`/`chmod` line above keeps
those readable only by the `kbrelay` group. If you ever see `Permission denied` opening
`/opt/kbrelay/server.py` in the logs, it means the service user can't read the code — rerun the
`chmod -R a+rX /opt/kbrelay` line.)

`/etc/systemd/system/kbrelay.service`:

```ini
[Unit]
Description=kbrelay relay
After=network-online.target
Wants=network-online.target

[Service]
User=kbrelay
ExecStart=/usr/bin/python3 /opt/kbrelay/server.py run --dir /etc/kbrelay
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now kbrelay
journalctl -u kbrelay -f          # rejected keys are logged with their SHA256 fingerprint
```

### Managing access

```bash
# approve (takes effect on the next connection, no restart needed)
sudo cp laptop.pub       /etc/kbrelay/providers/laptop.pub
sudo cp arch-desktop.pub /etc/kbrelay/receivers/arch-desktop.pub
sudo chgrp kbrelay /etc/kbrelay/*/*.pub

# revoke: delete the file, then kick live sessions
sudo rm /etc/kbrelay/providers/laptop.pub && sudo systemctl reload kbrelay
```

## 2. Client config (all machines)

Generate a key per device (Windows 10/11 has `ssh-keygen` built in):

```bash
mkdir -p ~/.config/kbrelay
ssh-keygen -t ed25519 -C my-device -f ~/.config/kbrelay/id_ed25519
```

Copy `id_ed25519.pub` to the server as shown above. Then create `~/.config/kbrelay/config.json`
(on Windows: `C:\Users\<you>\.config\kbrelay\config.json`):

```json
{
  "server": "203.0.113.10:7433",
  "fingerprint": "SHA256:paste-the-fingerprint-from-server-init",
  "key": "~/.config/kbrelay/id_ed25519"
}
```

Passphrase-protected keys work too (the provider asks in a dialog) but need `pip install bcrypt`.
The receiver runs unattended, so give it a key without a passphrase.

The `"server"` value can be a bare IP, `host:port`, or a URL — `203.0.113.10:7433`,
`relay.example.com:7433` and `kbrelay://203.0.113.10:7433` all work — so you can move the relay to a
new IP or give it a DNS name later by editing this one line. The port defaults to 7433 if omitted.

**Display name.** By default a receiver shows up in the provider's list under the name of its `.pub`
file on the server. If several devices share a machine name, or you'd rather set the label on the
device itself, add `"name"` to that device's config (or pass `--name`):

```json
{ "server": "…", "fingerprint": "…", "key": "…", "name": "living-room-deck" }
```

Names allow letters, digits, `.`, `_` and `-`. This only changes the label — the device is still
authorized by its key (its `.pub` must be on the server), and the provider still pins receivers by
key, so a name can't be used to impersonate another device. Keep names unique across your receivers;
two live receivers with the same name will fight over the slot (each kicks the other off). The same
option works for a provider if you want to relabel it too.

**Behind a proxy (e.g. a Windows work machine).** If the provider can't reach the relay directly, add
an HTTP CONNECT proxy. It can go in the config or, if you'd rather not store the password in a file,
in the `HTTPS_PROXY` environment variable, or on the command line with `--proxy`:

```json
{
  "server": "203.0.113.10:7433",
  "fingerprint": "SHA256:…",
  "key": "~/.config/kbrelay/id_ed25519",
  "proxy": "http://USER:PASSWORD@proxy.corp.example:8080"
}
```

Drop the `USER:PASSWORD@` part if your proxy doesn't need credentials; include the port (many proxies
use 8080 or 3128). The TLS to the relay still runs end to end *through* the tunnel, so the proxy — like
the relay — sees only encrypted bytes and never your keystrokes or the relay's certificate contents.
Two caveats: this supports **HTTP CONNECT proxies with Basic auth only**. It does **not** do SOCKS, or
the NTLM/Kerberos ("Negotiate") auth many corporate proxies require — if yours challenges with those,
run a small local adapter like [cntlm](http://cntlm.sourceforge.net/) or `px` and point `"proxy"` at
`http://127.0.0.1:3128` instead. Using a proxy needs Python 3.11 or newer on the client.

**The end-to-end trust folder.** Besides the key you copy *to the server*, each client keeps a local
folder of peer `.pub` files it trusts directly (defaulting to `~/.config/kbrelay/providers` on the
receiver and `~/.config/kbrelay/receivers` on the provider, override with `"peers"` in the config or
`--peers`). This is what makes the relay untrusted:

- **On the receiver**, put every provider's `.pub` here. A provider whose key isn't listed is
  refused even if the relay lets it connect. This is required — with an empty folder the receiver
  refuses everyone.
- **On the provider**, this folder is filled automatically: the first time you connect to a receiver
  it shows the receiver's fingerprint and, if you accept, saves it here. After that, a receiver whose
  key doesn't match is refused. You can also pre-fill it by copying the receiver's `id_ed25519.pub`
  in as `<receiver-name>.pub` to skip the first-time prompt.

## 3. Receiver

The receiver talks to `/dev/uinput` with plain Python (no `python-evdev`), so its only library is
`cryptography`.

### SteamOS, or any machine where you'd rather not install system packages

`kbrelay-receiver.sh` keeps everything in your home directory, which SteamOS updates leave alone:
a private Python from [uv](https://docs.astral.sh/uv/), `cryptography`, and a systemd *user* service.
In Desktop Mode, open Konsole:

```bash
mkdir -p ~/kbrelay && cp receiver.py kbrelay_common.py kbrelay-receiver.sh ~/kbrelay/
chmod +x ~/kbrelay/kbrelay-receiver.sh
~/kbrelay/kbrelay-receiver.sh --setup
```

Setup installs uv to `~/.local/bin`, downloads Python, checks that you can write to `/dev/uinput`
and installs a user service that starts when you log in. Then create the key and `config.json`
(step 2), **authorize your provider(s)** by copying each provider's public key into the receiver's
own trust folder, and test with `--dry-run` (it prints keys instead of typing them):

```bash
mkdir -p ~/.config/kbrelay/providers
cp /path/to/laptop.pub ~/.config/kbrelay/providers/laptop.pub   # do this for each provider device
~/kbrelay/kbrelay-receiver.sh --dry-run
```

Then start the service:

```bash
systemctl --user start kbrelay-receiver
journalctl --user -u kbrelay-receiver -f
```

**uinput access:** Steam installs a udev rule that already lets the logged-in user write to
`/dev/uinput` (Steam Input uses it for controller emulation), so on SteamOS this usually just works.
If setup reports it isn't writable, it prints a one-time fix. That fix needs `sudo` (set a password
with `passwd` first) and writes to `/etc`, which SteamOS preserves across updates, unlike packages.

### Regular Arch with pacman

```bash
sudo pacman -S python-cryptography
echo uinput | sudo tee /etc/modules-load.d/uinput.conf && sudo modprobe uinput
echo 'KERNEL=="uinput", SUBSYSTEM=="misc", OPTIONS+="static_node=uinput", TAG+="uaccess"' \
  | sudo tee /etc/udev/rules.d/60-kbrelay-uinput.rules
sudo udevadm control --reload && sudo udevadm trigger --name-match=uinput
```

The `uaccess` tag gives the logged-in desktop user access to `/dev/uinput` (log out and back in if
you get a permission error). Test with `python receiver.py --dry-run`, which prints events instead
of typing them. To run it as a service, use `kbrelay-receiver.sh --setup` as above, or write the
same user unit by hand with `ExecStart=/usr/bin/python %h/kbrelay/receiver.py`.

## 4. Provider

**Windows:** install Python from python.org (it includes Tk), then `py -m pip install cryptography`
and start it with `pyw provider.py` (or make a shortcut to that).
**Linux:** `sudo pacman -S tk python-cryptography` (Debian/Ubuntu: `python3-tk python3-cryptography`),
then `python provider.py`.

**SteamOS, or any Linux where you don't want system packages:** use `kbrelay-provider.sh`. It uses
[uv](https://docs.astral.sh/uv/) to fetch a standalone Python (with its own Tk) plus the libraries,
all inside your home directory, which SteamOS updates leave alone. No pacman, no
`steamos-readonly disable`. In Desktop Mode, open Konsole:

```bash
mkdir -p ~/kbrelay && cp provider.py kbrelay_common.py kbrelay-provider.sh ~/kbrelay/
chmod +x ~/kbrelay/kbrelay-provider.sh
~/kbrelay/kbrelay-provider.sh --setup      # installs uv to ~/.local/bin, downloads Python, adds a menu entry
```

Then create the key and `config.json` as in step 2 (`ssh-keygen` is included in SteamOS) and start
**kbrelay provider** from the application menu. When started from the menu, errors are logged to
`~/.cache/kbrelay/provider.log`. To remove everything, delete `~/kbrelay`, `~/.local/bin/uv`,
`~/.local/share/uv`, `~/.cache/uv` and the `.desktop` file in `~/.local/share/applications`.

Click a receiver in the list, and everything typed while the green area has focus goes to it.
Switching windows, clicking the list or pressing **Stop sending** releases all held keys on the
receiver. It reconnects automatically and re-attaches to the receiver you last picked.

---

## Limitations and notes

- **Shortcuts the provider's OS keeps for itself** never reach the window: on Windows,
  Ctrl+Alt+Del, Win+L, Alt+Tab and most Win+key combos; on Linux, whatever your compositor binds
  (often Super and Alt+Tab). Alt+F4 is forwarded and doesn't close the provider window.
- **Layout:** keys are physical positions, so set the receiver's layout to match the keyboard you're
  typing on. On Windows, AltGr arrives as Ctrl+Right Alt (that's how Windows reports it).
- **Stuck modifiers:** if a Shift/Ctrl/Alt/Meta ever seems held on the receiver (e.g. everything types
  as capitals), clicking off the green area and back releases all held keys. The provider already
  matches a modifier's release to whichever left/right variant is actually held, which is the usual
  cause on Windows, so this should be rare.
- **`text` messages** (for on-screen keyboards) type ASCII assuming a US layout on the receiver;
  other characters use `wtype` (Wayland) or `xdotool` (X11) if installed (SteamOS has neither).
- **The relay can't read keystrokes.** Provider↔receiver traffic is end-to-end encrypted, so a
  compromised relay can drop or delay traffic but can't read or inject keystrokes (see Security model).
- **A provider key can type anything into the receiver**, including commands in a terminal, so
  treat provider private keys like SSH keys to that machine.
- **Power/sleep keys are not forwarded.** The receiver only accepts ordinary keyboard keys, so a
  buggy or hostile provider can't suspend or power off the machine.

## Protocol (for writing more clients, e.g. iOS)

Newline-delimited JSON over TLS 1.2+. The client pins the server certificate's SHA-256 fingerprint.
(If a proxy is configured, the client first opens an HTTP `CONNECT` tunnel to it and then runs the
same TLS session through that tunnel; nothing else changes.)

1. client → `{"type":"hello","protocol":"kbrelay-1","role":"provider"|"receiver","pubkey":"ssh-ed25519 AAAA…"}`
   (an optional `"name"` field overrides the display label; the server uses it only if it matches
   `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, and authorization is always by key regardless)
2. server → `{"type":"challenge","nonce":"<base64 32 bytes>"}`
3. client signs `"kbrelay-1\nclient-auth\n<role>\n<server fingerprint>\n" + nonce` with ed25519 →
   `{"type":"auth","sig":"<base64>"}`
4. server → `{"type":"welcome","name":"<name>"}` or `{"type":"error","message":…}`

| Direction | Message |
|---|---|
| server → provider | `{"type":"receivers","receivers":["arch-desktop"]}`, `{"type":"selected","receiver":name\|null,"reason"?}` |
| provider → server | `{"type":"select","receiver":name\|null}` |
| server → receiver | `{"type":"attached"/"detached","provider":name}` |
| either → server | `{"type":"ping"}` every 20 s (server answers `pong`; idle connections drop after 60 s) |

Once a provider is attached to a receiver, everything else rides inside end-to-end blobs the relay
copies through verbatim (only the `hs`, `ct` and `err` fields, size-capped):
`{"type":"e2e", ...}` from a provider goes to its receiver, and from a receiver to its provider.

1. provider → receiver `{"type":"e2e","hs":{"step":1,"pub":"ssh-ed25519 …","epk":"<b64 X25519>","sig":"<b64>"}}`
   where `sig` is ed25519 over `"kbrelay-e2e-1\nhs1\n"+epk`.
2. receiver checks the provider's `pub` against its own trust folder, then replies
   `{"type":"e2e","hs":{"step":2,"pub":…,"epk":…,"sig":…}}` with `sig` over
   `"kbrelay-e2e-1\nhs2\n"+provider_epk+"\n"+receiver_epk+"\n"+provider_identity_raw`.
3. Both derive two ChaCha20-Poly1305 keys via `HKDF-SHA256(x25519_shared, salt=SHA256(transcript))`,
   transcript = the protocol tag, both identity keys and both ephemerals; one key per direction.
4. Each keystroke is `{"type":"e2e","ct":"<b64: 8-byte counter ‖ ciphertext>"}`; the counter is the
   nonce (big-endian, left-padded to 12 bytes) and must strictly increase. Plaintext is a JSON
   `{"type":"key","code":30,"down":true}`, `{"type":"text","text":"hi"}` or `{"type":"release_all"}`.
   `err` carries a short reason string (e.g. an unauthorized or unpinned key).

An iOS client would implement the same two layers: pin the relay cert, sign the auth challenge, then
run this handshake and seal `text` (or `key`) messages. All the primitives are in `kbrelay_common.py`.
