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

The APK sits in the task workspace (uploaded via `POST /api/tasks/{id}/apk` or
dropped in). Resolve its path first (`ls` the workspace). The app becomes an
`app` asset keyed by its manifest package (bundle id).

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

## Phase 2 — Dynamic analysis (only when an emulator is reachable)

Requires an **external rooted Android emulator** over adb (it is never run in
this container — see the design doc for why and for host setup with rootAVD).
Check reachability first: `adb connect $ANDROID_ADB` then `adb devices`. If no
device, record that dynamic analysis was skipped for lack of an emulator and
stop at Phase 1.

With a device:

1. `adb install -r <path.apk>`.
2. Push and start the matching `frida-server`; confirm `frida-ps -U` works.
3. Disable defenses for testing: `objection -g <package> explore` then
   `android sslpinning disable` and `android root disable`, or load the
   equivalent Frida scripts.
4. Trust ARTEX's MITM CA as a **system** CA (root) and set the emulator proxy to
   the ARTEX recorder (`:8788`). The app's HTTPS now flows through ARTEX's
   traffic graph and is scored by the existing findings/evidence pipeline.
5. Hook at runtime (Frida): crypto calls (keys/plaintext), file I/O (insecure
   storage), Keystore, clipboard, WebView URLs, exported-component intents and
   deep links.
6. Exercise the app (UIAutomator/monkey or operator-guided) to generate traffic
   and reach authenticated flows.

Bind dynamic findings to the same `app` asset, mapped to MASVS/MSTG + CWE. The
captured traffic is already in ARTEX; reference the relevant flows as evidence.

## What this is not

- Not MobSF, not a cloud scanner, not a repackaging/patching tool.
- Not a place to run the APK in the ARTEX container — dynamic runs only on the
  isolated emulator.
