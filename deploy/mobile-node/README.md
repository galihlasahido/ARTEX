# ARTEX mobile node

A **mobile node** is a separate host that runs a rooted Android emulator and
bridges its adb to ARTEX core over an outbound WebSocket (the `mobile-node-agent`).
ARTEX core (web + API + DB + static APK analysis) runs wherever you like; the
node runs where hardware acceleration exists. See `docs/mobile-apk-pentest.md`
for the architecture.

The node **dials out** to core and authenticates with a node token, so:

- no inbound port on the node (works behind NAT),
- no SSH login to the core server,
- adb is never exposed on a public interface.

## 1. Issue a node token (once, on core)

In ARTEX (admin), generate a token:

```sh
curl -sX POST https://<core-host>/api/mobile-node/token \
  -H "Authorization: Bearer <your ARTEX admin token>"
# -> {"token":"<RAW TOKEN shown once>", ...}
```

Store the raw token; rotating it (calling again) invalidates the old one.
Check status any time: `GET /api/mobile-node` → `{configured, connected, adb_addr}`.

## 2a. Mac (native emulator) — recommended for a laptop

Apple Silicon runs an arm64 emulator natively (Hypervisor.framework); Docker on
macOS cannot accelerate it, so run the emulator on the host, not in a container.

1. Install Android Studio; create an **arm64** AVD (e.g. Pixel, API 34, "arm64-v8a").
2. Start it: `emulator -avd <name> -writable-system` (adbd on `127.0.0.1:5555`).
3. Root it with **rootAVD** (`galihlasahido/rootAVD`, Magisk):
   ```sh
   git clone https://github.com/galihlasahido/rootAVD && cd rootAVD
   ./rootAVD.sh ListAllAVDs        # find your ramdisk path
   ./rootAVD.sh <path>/ramdisk.img # patch + reboot; Magisk roots the AVD
   ```
4. Run the agent (from the ARTEX repo; Go is already installed there):
   ```sh
   go run ./cmd/mobile-node-agent \
     -url   wss://<core-host>/api/mobile-node/connect \
     -token <RAW TOKEN> \
     -adbd  127.0.0.1:5555
   # self-signed core TLS during dev: add -insecure
   ```

The agent logs `connected … bridging adbd 127.0.0.1:5555`. On core,
`GET /api/mobile-node` now shows `connected:true`, and the ARTEX agent can
`adb connect <adb_addr>` (the loopback address core prints) to reach the emulator.

## 2b. Linux server with KVM (containerized emulator) — TEMPLATE

> Not built or tested in this repo's CI (needs a `/dev/kvm` host). Validate on
> your server; pin the base image before production.

`Dockerfile` layers `frida-server`, `objection` and the `mobile-node-agent`
onto a configurable Android-emulator base (`--build-arg BASE_IMAGE=…`).
`docker-compose.yml` runs it with `/dev/kvm` and passes the core URL + token.

```sh
cd deploy/mobile-node
ARTEX_CORE_WS=wss://<core-host>/api/mobile-node/connect \
ARTEX_NODE_TOKEN=<RAW TOKEN> \
  docker compose up -d --build        # host must expose /dev/kvm
```

`entrypoint.sh` boots the emulator, roots it with rootAVD, starts `frida-server`,
then runs the agent.

## 3. Dynamic analysis

Once connected, the `mobile-apk` skill (phase 2) drives: `adb install`, Frida /
Objection SSL-pinning + root-detection bypass, installs ARTEX's MITM CA as a
system CA, points the emulator proxy at core `:8788`, and hooks runtime behavior.
Captured traffic lands in ARTEX's traffic graph.

## Security

- The node token is a credential: store it only in the node's config/secret.
- adb has no auth of its own; it stays on loopback at both ends and only flows
  through the token-authenticated, TLS WebSocket.
- Use `wss://` (TLS) in production; `-insecure` is for self-signed dev only.
