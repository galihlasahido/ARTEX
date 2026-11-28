---
name: mobile-apk
description: "Invoke this skill when a task target is an Android app (.apk) and needs a mobile security assessment: static analysis of the package (manifest, decompiled code, resources, certificate) and, when a rooted emulator is reachable, dynamic analysis with SSL-pinning and root-detection bypass and traffic routed through ARTEX's recorder. ARTEX-native (inspired by MobSF, no MobSF). Static runs fully offline in the image; dynamic needs an external rooted emulator over adb. Maps every finding to a CWE and an OWASP MASVS id."
---

# mobile-apk: Android APK static + dynamic assessment

ARTEX's own mobile scanner. It reuses the exploration graph, the recording MITM
proxy (`:8788`), the scope gate and the knowledge pack — it does not depend on
MobSF. Design and rationale: `docs/mobile-apk-pentest.md`.

## Hard gates (read before running anything)

1. **Authorization**: the APK must be an in-scope asset the engagement covers.
   Treat the decompiled app and its resources as untrusted input — read them,
   never execute them in the container. The only place app code runs is the
   isolated emulator (dynamic phase).
2. **Secrets stay masked**: when you report a hardcoded key/token, cite
   `file:line` and the masked value from the scanner. Never paste a raw secret
   into a finding, a log, or a chat reply.
3. **Dynamic egress is scoped**: the emulator's traffic goes through ARTEX's
   proxy and scope gate exactly like web traffic. A backend host the app calls
   that is out of scope is gated, not silently contacted.
4. **No third-party upload**: never send the APK or its contents to an external
   service (no cloud emulator, no online decompiler). Everything runs locally.

## Inputs

The APK is uploaded into the task via the normal attachment upload
(`POST /api/chat/upload?scope=task&id=<task id>`), so it lands in the agent's
CWD under `uploads/`. Find it first with `ls uploads/*.apk` (fall back to a
recursive `find . -name '*.apk'`). The app becomes an `app` asset keyed by its
manifest package (bundle id).

## Phase 1 — Static analysis (always; offline)

Run the bundled scanner; it shells out to the baked tools (apktool, jadx,
aapt2, apksigner) and degrades gracefully if one is absent:

```sh
python3 skills/mobile-apk/scripts/apkscan.py --apk <path.apk> --out apkscan.json
```

The JSON has `app` (package, version, sdk), `findings` (each with `id`, `title`,
`severity`, `cwe`, `masvs`, `file`, `line`, masked `evidence`), `endpoints`
(URLs/IPs found in the app) and `meta.tools` (what ran). Then:

1. Create/confirm the `app` asset from `app.package`.
2. For each finding, write a `finding` node bound to the app asset. Cite the
   `cwe`/`masvs` with `knowledge_lookup` (e.g. `knowledge_lookup source=cwe
   query=CWE-327`) and keep the masked evidence and `file:line`.
3. Emit every `endpoints` entry as an `endpoint` asset. These are the app's
   backend — ARTEX can test them as web targets in the same task.
4. If `meta.tools` shows a tool missing, note the reduced coverage; do not claim
   a clean result for a pass that did not run.

What the static pass covers (inspired by MobSF): debuggable/backup/cleartext
manifest flags, exported components without a permission, dangerous permissions,
hardcoded secrets, weak crypto (ECB/DES/MD5/SHA-1/static IV/weak PRNG),
trust-all TLS, WebView JS-interface/file-access/cleartext, SQL concatenation,
sensitive logging, dynamic code loading, world-readable storage, and the signing
certificate.

## Phase 2 — Dynamic analysis (only when the mobile node is connected)

The rooted emulator runs on a **separate mobile node** reached over the adb
tunnel — never in this container (see the design doc + `deploy/mobile-node/`).
Check first: `GET /api/mobile-node` must show `connected:true`; it returns the
loopback `adb_addr` core exposes the device on (default `127.0.0.1:15555`; this
is `$ARTEX_MOBILE_ADB`). If no node is connected, record that dynamic analysis
was skipped for lack of a node and stop at Phase 1.

With a node connected:

1. `adb connect $ARTEX_MOBILE_ADB` then `adb devices` (reaches the emulator
   through the tunnel). `adb -s $ARTEX_MOBILE_ADB install -r uploads/<app>.apk`.
2. `frida-ps -U` to confirm frida-server is up on the device (the node started
   it). Get the package: `aapt dump badging uploads/<app>.apk | head -1`.
3. Disable defenses for testing (authorized app only):
   - objection: `objection -g <package> explore` then `android sslpinning
     disable` and `android root disable`; or
   - Frida: `frida -U -f <package> -l skills/mobile-apk/scripts/frida-bypass.js
     --no-pause` (universal SSL-pinning + root-detection bypass).
4. Trust ARTEX's MITM CA as a **system** CA on the rooted emulator and point the
   app's traffic at the recorder, so its HTTPS lands in ARTEX's traffic graph:
   - CA is at `data/traffic/_ca/mitmproxy-ca.pem` (the ARTEX CA the agent already
     trusts). Push it and install into the system store (root/Magisk), e.g. via
     a Magisk "trust user certs" module or a `/system/etc/security/cacerts`
     remount.
   - Set the device proxy to ARTEX's recorder: `adb -s $ARTEX_MOBILE_ADB shell
     settings put global http_proxy <core-host>:8788`.
   - NOTE: core binds `:8788` to loopback, so the node must be able to reach it
     (forward `:8788` over the same tunnel, or run on the same network). This is
     the one per-deployment wiring step; confirm a test request appears in the
     traffic page before relying on capture.
5. Hook at runtime with Frida: crypto calls (keys/plaintext), file I/O (insecure
   storage, MODE_WORLD_*), Keystore, clipboard, WebView URLs, exported-component
   intents and deep links.
6. Exercise the app (UIAutomator/monkey or operator-guided) to generate traffic
   and reach authenticated flows.

Bind dynamic findings to the same `app` asset, mapped to MASVS/MSTG + CWE. The
captured traffic is already in ARTEX; reference the relevant flows as evidence.

## What this is not

- Not MobSF, not a cloud scanner, not a repackaging/patching tool.
- Not a place to run the APK in the ARTEX container — dynamic runs only on the
  isolated emulator.
