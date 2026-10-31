# efan-native

[![CI](https://github.com/iDestro/efan-linux/actions/workflows/ci.yml/badge.svg)](https://github.com/iDestro/efan-linux/actions/workflows/ci.yml)

A native Linux client for an existing **Efan VPN / 饿饭加速器** subscription.

There is no official Linux build. This project talks to the same API as the
official Windows client, decrypts the account's `x365://` node list with the
RSA key embedded in `client.dll`, and runs a native X365 adapter. You get a
local SOCKS5 proxy and an HTTP/CONNECT proxy; optionally it points the GNOME
system proxy at them.

It does **not** create, extend, or bypass a subscription. Use it only with an
account you already paid for. The node configuration contains your account
UUID; keep `~/.config/efan/config.yaml` private.

## What works

- Email/password login against `https://api.efanapp.com`
- Account-session refresh and app-data fetch
- One-time WHMCS client-area login with `efan whmcs`
- Direct Clash/Mihomo subscription URL export with `efan clash`
- RSA + zlib decryption of the encrypted `proxy` payload
- X365 / REALITY / multipath transport (the same protocol used by `efanadp`)
- Local SOCKS5 listener (default `127.0.0.1:10865`)
- Local HTTP proxy with `CONNECT` support (default `127.0.0.1:10866`)
- GNOME system proxy integration, restored when the tunnel exits
- Node health/latency probing with `efan test`
- Background daemon with `efan start`, `stop`, `restart`, and `status`
- One-switch daily use with `efan on` / `efan off` (daemon, GNOME, and terminal)
- Interactive node picker (`efan node`) with a reachability check before switching
- Daemon log tailing with `efan log`
- No root required; no TUN capture

The API/decryption/adapter path has been tested end-to-end against a local mock
API and against a real paid account. The X365 transport reaches the official
edge server; actual internet traffic requires your account UUID from the
decrypted node list.

## Requirements

- Linux x86_64 or arm64
- Go 1.26.4+ to build from source (`make` or `./setup.sh`)
- `gsettings` only if you want automatic GNOME proxy changes
- No sudo, no TUN, no kernel modules

## Build

```bash
git clone https://github.com/iDestro/efan-linux.git
cd efan-linux
make                 # produces ./efan
```

For a static build and local installation (binary, desktop launchers, shell
wrapper), use `./setup.sh` instead; see [Install a launcher](#install-a-launcher).

Prebuilt binaries, when available, are attached to
[GitHub Releases](https://github.com/iDestro/efan-linux/releases).

## First run

The RSA key is the same universal key embedded in the official Windows client.
Extract it once from the `client.dll` you already have:

```bash
cd efan-linux
./efan extract-key --dll /path/to/client.dll
```

Then log in (the password prompt does not echo):

```bash
./efan login
```

This writes, with mode `0600`:

```text
~/.config/efan/key.pem       embedded client RSA key
~/.config/efan/session.json  account tokens and API session cookie
~/.config/efan/settings.json device id, selected node, ports
~/.config/efan/config.yaml   decrypted x365 nodes (private!)
```

Inspect the available nodes:

```bash
./efan list
```

`list` only shows what is in the subscription. To find which nodes are actually
reachable right now, probe them:

```bash
./efan test
```

This opens an independent X365 connection per node, sends a minimal HTTP request
to `example.com:80`, and reports working nodes sorted by latency. It does not
touch a running daemon/`connect`, the system proxy, or your selected node. A
first pass can have transient failures; retry those:

```bash
./efan test --filter 泰国 --retries 2
```

Every result has an `IDX` number. The summary also prints the current default
node, the node the daemon is actually using, and the exact command to switch:

```text
Fastest: 美国04 (445ms)
Default: 美国06
Daemon:  美国06 (running)
Next:    efan node use "美国04"
Or:      efan node use 4 --filter "美国"
         (efan test does not change the current node)
```

`IDX` is the position within the tested set, so it can be used with the same
`--filter`. Switching by name always works and is less error-prone.

Useful options:

```bash
./efan test --filter 香港            # only names containing 香港
./efan test --limit 10              # quick sample
./efan test --concurrency 8         # more parallel probes
./efan test --target 1.1.1.1:80     # different egress check target
./efan test --json                  # machine-readable result
./efan test --save                  # make the fastest working node the default
```

`--save` changes the default only; it does not restart a running daemon. Use
`efan node use NAME` to save and restart in one step, or `efan restart` to apply
an already-saved default.

## Daily use

One command turns on the daemon, the GNOME system proxy, and the terminal
proxy:

```bash
eval "$(./efan on)"
./efan status
```

With the shell wrapper, `eval` is not needed:

```bash
source ~/.config/efan/shell/efan.sh
efan on
efan off
```

`./setup.sh --shell` adds that source line to `~/.bashrc` or `~/.zshrc`.
Without the wrapper, `efan on` prints the `export` lines to stdout and a hint to
stderr.

`efan on` starts the daemon if necessary, enables the GNOME system proxy, and
exports the terminal variables. `efan off` does the reverse: it stops the
daemon, restores the GNOME proxy, and clears the terminal variables. Use
`efan off --keep-daemon` when you only want to turn off the two proxy layers
but keep the daemon warm for a fast restart.

For a terminal-only session, skip the system proxy:

```bash
eval "$(./efan on --no-system-proxy)"
curl https://ifconfig.me
eval "$(./efan off)"
```

`efan start` / `efan stop` manage only the background daemon, and
`efan proxy on` / `efan proxy off` manage only the GNOME proxy. For daily use,
`efan on` / `efan off` is the single switch.

Pick a node interactively:

```bash
./efan node
./efan node --filter 香港
./efan node ls
./efan node use 香港04
```

If the daemon is running, `efan node use` first probes the selected node and
then restarts the daemon. If the probe fails, the existing daemon is left
untouched. Use `--no-test` to skip the probe, or `--no-restart` to only change
the saved default.

Watch the daemon log:

```bash
./efan log -n 50
./efan log -f
```

The foreground mode is still available when you want to watch the connection
directly:

```bash
./efan connect --system-proxy
```

`Ctrl-C` stops the tunnel and restores the previous GNOME proxy settings.

Use either proxy explicitly:

```bash
curl --socks5-hostname 127.0.0.1:10865 https://ifconfig.me
curl -x http://127.0.0.1:10866 https://ifconfig.me
```

## Commands

```text
efan login [--email EMAIL] [--password-stdin] [--no-device-headers]
efan refresh
efan fetch
efan list [--json]
efan start [--node NAME|INDEX] [--listen ADDR] [--http-listen ADDR]
           [--no-http] [--system-proxy] [--debug]
efan stop [--force]
efan restart [--node NAME|INDEX] [--listen ADDR] [--http-listen ADDR]
             [--no-http] [--system-proxy] [--debug]
efan on [--node NAME|INDEX] [--no-system-proxy]
efan off [--keep-daemon]
efan node [--filter TEXT] [--no-restart]
efan node ls [--filter TEXT]
efan node use [NAME|INDEX] [--filter TEXT] [--no-restart] [--no-test]
efan log [-f] [-n LINES]
efan connect [--node NAME|INDEX] [--listen ADDR] [--http-listen ADDR]
             [--no-http] [--system-proxy] [--debug]
efan test [--node NAME|INDEX] [--filter TEXT] [--limit N]
          [--concurrency N] [--timeout DURATION] [--retries N]
          [--target HOST:PORT] [--json] [--save]
efan proxy on [--http-port PORT] [--socks-port PORT]
efan proxy off
efan proxy status
efan proxy env
efan status
efan clash [--json] [--base URL]
efan whmcs
efan logout [--all]
efan extract-key [--dll PATH] [--out PATH]
efan version
```

Useful environment variables:

```text
EFAN_CONFIG_DIR   override ~/.config/efan
EFAN_CLIENT_DLL   path to client.dll for automatic key extraction
EFAN_API_BASE     override https://api.efanapp.com
EFAN_CLASH_BASE   override https://api.efanyunapi.com/clash
EFAN_APP_VERSION  app version reported to the API (default 1.0.68)
EFAN_DID          reuse a device id (if your plan has a device limit)
```

## Install a launcher

```bash
./setup.sh
./setup.sh --shell   # optional: add the shell integration to your rc file
```

This builds a static binary, installs it to `~/.local/bin/efan`, and adds
desktop launchers: **Efan Native Login**, **Efan Native Start**, **Efan Native
Stop**, and the foreground **Efan Native Connect**. It also installs the shell
integration file to `~/.config/efan/shell/efan.sh`.

## How it works

1. `POST /v1/login` with `{email,password}` returns two different tokens:
   `data.my_services[].access_token` (the bearer token for `/v1/app`) and
   `data.token` (the account-session token used by `/v1/session/refresh` and
   `/v1/whmcs/sso-login`). It also establishes an HttpOnly
   `server_session_*` cookie. `efan` stores all three in the private session
   file.
2. `GET /v1/app?flag=wassvpn` with `Authorization: Bearer <access_token>`
   returns an app-data object containing an encrypted `proxy` string and the
   account's `subscribe_token`.
3. The `proxy` string is base64 of RSA-2048 PKCS#1 v1.5 blocks. Decrypting the
   blocks and decompressing the result with zlib yields a YAML node list:
   `proxies: {name: [x365://<uuid>@host:443?...]}`.
4. The native adapter parses each `x365://` URI and implements the X365 frame,
   REALITY TLS handshake, xhttp transport, and multipath stream protocol.
5. A local SOCKS5 listener exposes that transport; a small HTTP proxy forwards
   `CONNECT`/plain HTTP requests through the SOCKS listener so desktop apps and
   GNOME's system proxy can use it without TUN.

`efan clash` uses `whm_hosting_id` and `subscribe_token` from the same
`/v1/app` response to build the official Clash subscription URL. It does not
need to scrape the WHMCS page.

The device headers `x-did` and `x-sig` are reproduced as well: `x-sig` is the
`DeviceInfo` JSON RSA-encrypted with the public half of the same embedded key,
exactly like `api.encodeWithP` in `client.dll`.

## Troubleshooting

**`邮箱或密码错误`** — wrong email/password.

**`服务不存在或无权访问` or “no available service”** — the account has no
active plan, or the subscription has expired. Renew it in the official client
area; this tool cannot add a service.

**Device limit / `设备` error** — some plans bind to a device ID. The native
client generates a new one. If the plan is full, unbind an old device in the
official client area, or reuse the Windows app's ID. The Windows client stores
it base64-encoded in the registry; in PowerShell:

```powershell
$k = Get-Item 'HKCU:\SOFTWARE\365INTERNET\efanapp'
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($k.GetValue('did')))
```

Then use the printed 32-character value:

```bash
EFAN_DID=<32-hex-id> efan login
```

**`decrypt proxy payload: RSA decrypt block ...`** — the key came from a
different app version. Re-extract `client.dll` from the installed version and
run `efan extract-key --dll ...`.

**`node ... has an invalid UUID`** — the decrypted config is malformed. Check
`~/.config/efan/config.yaml`; you can re-run `efan fetch`.

**`listen ... address already in use` when running `efan start`** — a
foreground `efan connect` or another process is using the proxy ports. Stop the
old process first (`Ctrl-C` in its terminal), then run `efan start` again.

**`efan node use` says the new node is unreachable** — the preflight probe
failed and the running daemon was left on its current node. Try another node,
run `efan test --filter ...`, or use `--no-test` if you intentionally want to
switch anyway.

**`efan on` printed exports but the shell is unchanged** — run
`eval "$(efan on)"`, or source the wrapper:
`source ~/.config/efan/shell/efan.sh`.

**`efan status` says `Terminal: other proxy`** — the current shell has proxy
variables pointing somewhere else (for example an old `127.0.0.1:7897`). Run
`efan on` in that shell to replace them, or `efan off` to clear them.

**Browser cannot open Google, but `curl -x http://127.0.0.1:10866 ...` works**
— the tunnel is fine; the browser is not using it. Browsers use the GNOME
system proxy, while `efan on` only changes the current terminal. Check:

```bash
efan status | grep GNOME
```

If it says `none` or `not managed by efan`, enable it and reload the page:

```bash
efan on
```

`efan on` enables both the terminal and the GNOME system proxy. To change only
the browser side, use `efan proxy on`. Both record the setting in the daemon
state, so later `efan node use` switches keep the system proxy enabled. If
Chrome still uses old direct connections from before the change, restart it
with `chrome://restart`.

**GNOME proxy not changing** — `gsettings`/D-Bus is unavailable. Use
`eval "$(efan proxy env)"` in the terminal instead.

**DNS leaks / fake-IP errors** — use `socks5h://` (remote DNS), which is what
`efan proxy env` sets. The HTTP proxy forwards domain names to the tunnel.

**`efan test` reports EOF/timeouts** — a single probe can be transient; retry
the failed nodes with `--retries 2`. If everything fails, try
`--target 1.1.1.1:80`; if that also fails while `connect` still works, the
server may be rate-limiting parallel probes — lower `--concurrency`.

**`efan whmcs` says 登录已过期 immediately after login** — versions before
0.2.4 confused the service access token (`data.my_services[].access_token`)
with the account session token (`data.token`). Run `efan login` once with 0.2.4
or newer; it stores the two tokens separately and the WHMCS SSO link works. An
old session cannot be repaired offline because it never stored `data.token`.

**No TUN mode** — TUN needs root/CAP_NET_ADMIN. This client is intentionally
rootless and uses a proxy instead. If you need TUN, run a separate mihomo
instance with a SOCKS outbound to `127.0.0.1:10865`.

## Official Clash fallback

If you prefer Clash Verge / Clash Meta / Mihomo, print the account's direct
subscription URL:

```bash
./efan clash
```

It prints only the URL, so it can be piped into another tool. Use `--json` for
`{"service_id":...,"url":...}`, or `--base URL` (also `EFAN_CLASH_BASE`) if
Efan changes the subscription host. Import the URL as a remote profile in your
Clash client. The URL contains your account's subscription token; treat it as
a credential and do not share it.

The native client above does not need that subscription; it uses the same
nodes directly.

## Project layout

```text
cmd/efan/          CLI entrypoints, daemon lifecycle, login/refresh/clash
internal/efan/     API client, session store, crypto, HTTP proxy, GNOME proxy
internal/x365/     X365/REALITY transport and SOCKS5 adapter
shell/             bash/zsh wrapper for `efan on` / `efan off`
scripts/           desktop launcher helper
*.desktop          desktop-entry templates installed by setup.sh
```

## Security

- Tokens, the API cookie, the embedded RSA key, and decrypted nodes live under
  `~/.config/efan` with mode `0600`.
- Never commit `session.json`, `key.pem`, `config.yaml`, logs, or a Clash
  subscription URL. `.gitignore` covers the usual local paths.
- The password is prompted interactively by default and is never stored.
- `efan clash` prints a credential-bearing URL. Treat it like a password.

## Contributing

Run `go test ./...` before opening a pull request. Keep secrets and generated
node data out of commits; use the placeholder config in `config-example.yaml`
when documenting configuration.

## Credits

The X365 transport package is based on
[`rbee3u/efanadp`](https://github.com/rbee3u/efanadp). Protocol notes and the
reverse-engineering approach were informed by
[`hackeris/efanrev`](https://github.com/hackeris/efanrev). This project is for
personal interoperability with a paid account.
