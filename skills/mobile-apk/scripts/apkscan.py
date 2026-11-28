#!/usr/bin/env python3
# apkscan.py — ARTEX-native static APK analysis (inspired by MobSF, no MobSF).
#
# Decodes an APK with the baked tools (apktool, jadx, aapt2, apksigner) and runs
# a pattern pass over the manifest, decompiled code and resources, emitting one
# JSON document the mobile-apk skill turns into findings. Each finding carries a
# CWE and an OWASP MASVS id so the agent can cite it with knowledge_lookup.
#
# Design notes:
#   - stdlib only; every external tool is optional. A missing tool degrades the
#     scan (meta.tools lists what ran) instead of failing.
#   - secrets are reported masked, with file:line, never the raw value.
#   - the pattern engine (CODE_RULES / scan_text) is pure and self-testable:
#         python3 apkscan.py --selftest
#   - the APK is never executed; it is only unpacked and read.
#
# Usage:
#   python3 apkscan.py --apk app.apk --out report.json [--work /tmp/apkscan]
#   python3 apkscan.py --selftest

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# --- severities ---
HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"


def _finding(fid, title, severity, cwe, masvs, evidence="", file="", line=0):
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "masvs": masvs,
        "evidence": evidence,
        "file": file,
        "line": line,
    }


def mask(value, keep=4):
    """Mask a secret: keep a short prefix, hide the rest."""
    value = value.strip().strip("\"'")
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "…" + "*" * min(6, len(value) - keep)


# --- code pattern rules -----------------------------------------------------
# Each rule: (id, title, severity, cwe, masvs, compiled regex, secret?)
# secret=True masks group(1) (or the whole match) in the evidence.

def _rx(p):
    return re.compile(p)


CODE_RULES = [
    # Hardcoded secrets (CWE-798, MASVS-CRYPTO/STORAGE)
    ("secret-google-api", "Hardcoded Google API key", HIGH, "CWE-798", "MASVS-STORAGE-1",
     _rx(r"AIza[0-9A-Za-z\-_]{35}"), True),
    ("secret-aws-akid", "Hardcoded AWS access key id", HIGH, "CWE-798", "MASVS-STORAGE-1",
     _rx(r"AKIA[0-9A-Z]{16}"), True),
    ("secret-private-key", "Embedded private key", HIGH, "CWE-321", "MASVS-CRYPTO-1",
     _rx(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"), True),
    ("secret-slack", "Hardcoded Slack token", HIGH, "CWE-798", "MASVS-STORAGE-1",
     _rx(r"xox[baprs]-[0-9A-Za-z-]{10,}"), True),
    ("secret-jwt", "Embedded JWT", MEDIUM, "CWE-522", "MASVS-STORAGE-1",
     _rx(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), True),
    ("secret-assignment", "Hardcoded credential in source", MEDIUM, "CWE-798", "MASVS-STORAGE-1",
     _rx(r"(?i)(?:password|passwd|secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*[\"'][^\"']{6,}[\"']"), True),
    # Weak crypto (CWE-327/326, MASVS-CRYPTO)
    ("crypto-ecb", "AES/DES in ECB mode", HIGH, "CWE-327", "MASVS-CRYPTO-2",
     _rx(r"Cipher\.getInstance\(\s*[\"'][A-Za-z0-9]+/ECB"), False),
    ("crypto-des", "Weak cipher (DES/3DES/RC4)", HIGH, "CWE-327", "MASVS-CRYPTO-2",
     _rx(r"Cipher\.getInstance\(\s*[\"'](?:DES|DESede|RC4|ARCFOUR)"), False),
    ("crypto-hash", "Weak hash (MD5/SHA-1)", MEDIUM, "CWE-328", "MASVS-CRYPTO-4",
     _rx(r"MessageDigest\.getInstance\(\s*[\"'](?:MD5|SHA-?1)[\"']"), False),
    ("crypto-static-iv", "Static IV for encryption", MEDIUM, "CWE-329", "MASVS-CRYPTO-2",
     _rx(r"IvParameterSpec\(\s*(?:new byte\[\]\s*\{[^}]*\}|[\"'])"), False),
    ("crypto-weak-random", "Insecure PRNG (java.util.Random)", MEDIUM, "CWE-330", "MASVS-CRYPTO-6",
     _rx(r"new\s+java\.util\.Random\("), False),
    # TLS (CWE-295, MASVS-NETWORK)
    ("tls-trust-all", "Trust-all TrustManager", HIGH, "CWE-295", "MASVS-NETWORK-3",
     _rx(r"checkServerTrusted\([^)]*\)\s*\{\s*\}"), False),
    ("tls-allow-all-host", "Hostname verification disabled", HIGH, "CWE-295", "MASVS-NETWORK-3",
     _rx(r"ALLOW_ALL_HOSTNAME_VERIFIER|verify\([^)]*\)\s*\{\s*return\s+true"), False),
    # WebView (CWE-749, MASVS-PLATFORM)
    ("webview-jsinterface", "WebView addJavascriptInterface", MEDIUM, "CWE-749", "MASVS-PLATFORM-2",
     _rx(r"addJavascriptInterface\("), False),
    ("webview-file-access", "WebView file access enabled", MEDIUM, "CWE-749", "MASVS-PLATFORM-2",
     _rx(r"setAllow(?:File|UniversalAccessFromFile|FileAccessFromFileURLs)[A-Za-z]*\(\s*true"), False),
    ("webview-cleartext-load", "WebView loads cleartext URL", MEDIUM, "CWE-319", "MASVS-NETWORK-1",
     _rx(r"loadUrl\(\s*[\"']http://"), False),
    # Injection / storage / logging
    ("sql-concat", "SQL built by concatenation", MEDIUM, "CWE-89", "MASVS-CODE-8",
     _rx(r"(?:rawQuery|execSQL)\([^)]*\+"), False),
    ("log-sensitive", "Sensitive data logged", LOW, "CWE-532", "MASVS-STORAGE-3",
     _rx(r"(?i)Log\.[dviwe]\([^)]*(?:password|token|secret|session)"), False),
    ("dynamic-load", "Dynamic code loading", MEDIUM, "CWE-494", "MASVS-CODE-2",
     _rx(r"DexClassLoader\(|PathClassLoader\("), False),
    ("world-rw", "World-readable/writable storage", MEDIUM, "CWE-276", "MASVS-STORAGE-2",
     _rx(r"MODE_WORLD_(?:READABLE|WRITEABLE)"), False),
]

URL_RE = _rx(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
# noise: android schema/resource/doc URLs that are not app endpoints.
URL_IGNORE = _rx(r"(?:schemas\.android\.com|w3\.org|apache\.org|example\.com"
                 r"|developer\.android\.com|xmlpull\.org|json\.org|github\.com)")


def scan_text(path, text, max_per_rule=20):
    """Pure pattern pass over one file's text. Returns (findings, urls)."""
    findings, urls = [], set()
    lines = text.splitlines()
    for ln, line in enumerate(lines, 1):
        for fid, title, sev, cwe, masvs, rx, is_secret in CODE_RULES:
            m = rx.search(line)
            if not m:
                continue
            raw = m.group(0)
            ev = mask(raw) if is_secret else raw.strip()[:160]
            findings.append(_finding(fid, title, sev, cwe, masvs, ev, path, ln))
        for um in URL_RE.finditer(line):
            u = um.group(0).rstrip('".,);')
            if not URL_IGNORE.search(u):
                urls.add(u)
    # cap per rule so one generated file cannot flood the report.
    capped, counts = [], {}
    for f in findings:
        counts[f["id"]] = counts.get(f["id"], 0) + 1
        if counts[f["id"]] <= max_per_rule:
            capped.append(f)
    return capped, urls


# --- external tools ---------------------------------------------------------

def have(tool):
    return shutil.which(tool) is not None


def run(cmd, cwd=None, timeout=600):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return 1, "", str(e)


def decode_apktool(apk, workdir):
    out = os.path.join(workdir, "apktool")
    if not have("apktool"):
        return None
    code, _, err = run(["apktool", "d", "-f", "-o", out, apk])
    if code != 0:
        return None
    return out


def decompile_jadx(apk, workdir):
    out = os.path.join(workdir, "jadx")
    if not have("jadx"):
        return None
    # -d output, --no-res (code only, faster), -r skip resources decode errors.
    code, _, _ = run(["jadx", "-d", out, "--no-res", apk], timeout=1200)
    # jadx returns non-zero on partial failures but still writes sources.
    if os.path.isdir(os.path.join(out, "sources")):
        return out
    return out if os.path.isdir(out) else None


def badging(apk):
    """package / version / sdk from aapt2."""
    info = {}
    if not have("aapt2"):
        return info
    code, so, _ = run(["aapt2", "dump", "badging", apk])
    if code != 0:
        return info
    m = re.search(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'", so)
    if m:
        info["package"], info["version_code"], info["version_name"] = m.group(1), m.group(2), m.group(3)
    m = re.search(r"sdkVersion:'(\d+)'", so)
    if m:
        info["min_sdk"] = int(m.group(1))
    m = re.search(r"targetSdkVersion:'(\d+)'", so)
    if m:
        info["target_sdk"] = int(m.group(1))
    return info


def cert_info(apk):
    if not have("apksigner"):
        return []
    code, so, _ = run(["apksigner", "verify", "--print-certs", apk])
    out = []
    if code == 0:
        for m in re.finditer(r"Signer #\d+ certificate DN: (.+)", so):
            out.append(m.group(1).strip())
    return out


# --- manifest analysis ------------------------------------------------------

def _attr(el, name):
    return el.get("{%s}%s" % (ANDROID_NS, name))


def analyze_manifest(path):
    findings = []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return findings, {}
    app = root.find("application")
    meta = {"package": root.get("package", "")}
    if app is not None:
        if _attr(app, "debuggable") == "true":
            findings.append(_finding("manifest-debuggable", "App is debuggable", HIGH,
                                     "CWE-489", "MASVS-RESILIENCE-2", 'android:debuggable="true"', path))
        if _attr(app, "allowBackup") in (None, "true"):
            findings.append(_finding("manifest-allowbackup", "App data backup allowed", MEDIUM,
                                     "CWE-530", "MASVS-STORAGE-2", 'android:allowBackup="true"', path))
        if _attr(app, "usesCleartextTraffic") == "true":
            findings.append(_finding("manifest-cleartext", "Cleartext traffic permitted", HIGH,
                                     "CWE-319", "MASVS-NETWORK-1", 'usesCleartextTraffic="true"', path))
        # Exported components without a permission.
        for tag in ("activity", "service", "receiver", "provider"):
            for el in app.iter(tag):
                exported = _attr(el, "exported")
                has_filter = el.find("intent-filter") is not None
                name = _attr(el, "name") or "?"
                if exported == "true" or (exported is None and has_filter):
                    if not _attr(el, "permission"):
                        sev = HIGH if tag == "provider" else MEDIUM
                        findings.append(_finding(
                            "manifest-exported-" + tag,
                            "Exported %s without permission: %s" % (tag, name),
                            sev, "CWE-926", "MASVS-PLATFORM-1",
                            name, path))
    # Dangerous permissions.
    for el in root.iter("uses-permission"):
        pname = _attr(el, "name") or ""
        if pname in DANGEROUS_PERMS:
            findings.append(_finding("perm-" + pname.split(".")[-1].lower(),
                                     "Dangerous permission: " + pname, LOW,
                                     "CWE-250", "MASVS-PLATFORM-1", pname, path))
    return findings, meta


DANGEROUS_PERMS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_PHONE_STATE",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW",
}


# --- code / resource walk ---------------------------------------------------

def walk_scan(root, exts, max_files=20000):
    findings, urls = [], set()
    n = 0
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(exts):
                continue
            n += 1
            if n > max_files:
                return findings, urls, True
            full = os.path.join(dirpath, fn)
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            rel = os.path.relpath(full, root)
            f, u = scan_text(rel, text)
            findings.extend(f)
            urls.update(u)
    return findings, urls, False


# --- orchestration ----------------------------------------------------------

def analyze(apk, workdir):
    tools = {t: have(t) for t in ("apktool", "jadx", "aapt2", "apksigner")}
    report = {"app": {}, "findings": [], "endpoints": [], "certificates": [],
              "meta": {"tools": tools, "truncated": False}}

    report["app"].update(badging(apk))
    report["certificates"] = cert_info(apk)
    if report["certificates"] and any("debug" in c.lower() or "android debug" in c.lower()
                                      for c in report["certificates"]):
        report["findings"].append(_finding("cert-debug", "Signed with a debug certificate",
                                            MEDIUM, "CWE-295", "MASVS-RESILIENCE-1",
                                            report["certificates"][0], ""))

    apktool_dir = decode_apktool(apk, workdir)
    if apktool_dir:
        mpath = os.path.join(apktool_dir, "AndroidManifest.xml")
        if os.path.exists(mpath):
            mf, mmeta = analyze_manifest(mpath)
            report["findings"].extend(mf)
            report["app"].setdefault("package", mmeta.get("package", ""))
        # resources + assets for secrets/urls
        for sub in ("res/values", "res/raw", "assets", "res/xml"):
            d = os.path.join(apktool_dir, sub)
            if os.path.isdir(d):
                f, u, _ = walk_scan(d, (".xml", ".json", ".txt", ".properties", ".js"))
                report["findings"].extend(f)
                report["endpoints"].extend(sorted(u))

    jadx_dir = decompile_jadx(apk, workdir)
    if jadx_dir:
        f, u, trunc = walk_scan(jadx_dir, (".java",))
        report["findings"].extend(f)
        report["endpoints"].extend(sorted(u))
        report["meta"]["truncated"] = report["meta"]["truncated"] or trunc

    report["endpoints"] = sorted(set(report["endpoints"]))
    # severity ordering for the agent.
    order = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}
    report["findings"].sort(key=lambda f: order.get(f["severity"], 9))
    report["summary"] = {
        "findings": len(report["findings"]),
        "endpoints": len(report["endpoints"]),
        "by_severity": {s: sum(1 for f in report["findings"] if f["severity"] == s)
                        for s in (HIGH, MEDIUM, LOW, INFO)},
    }
    return report


# --- self test --------------------------------------------------------------

SELFTEST_CODE = r'''
public class Sample {
  String apiKey = "AIzaSyB1234567890abcdefghijklmnopqrstuv1";
  String pw = "password = \"hunter2secret\"";
  void c() { Cipher.getInstance("AES/ECB/PKCS5Padding"); }
  void h() { MessageDigest.getInstance("MD5"); }
  void w(WebView v) { v.addJavascriptInterface(o, "x"); v.loadUrl("http://api.internal/x"); }
  void q(String id) { db.rawQuery("SELECT * FROM t WHERE id=" + id, null); }
  String url = "https://backend.bankaceh.co.id/api/v1";
}
'''


def selftest():
    findings, urls = scan_text("Sample.java", SELFTEST_CODE)
    ids = {f["id"] for f in findings}
    expect = {"secret-google-api", "secret-assignment", "crypto-ecb", "crypto-hash",
              "webview-jsinterface", "webview-cleartext-load", "sql-concat"}
    missing = expect - ids
    ok = not missing and "https://backend.bankaceh.co.id/api/v1" in urls
    # secrets must be masked, never raw.
    for f in findings:
        if f["id"].startswith("secret-") and "hunter2secret" in f["evidence"]:
            ok = False
            print("FAIL: secret leaked unmasked:", f["evidence"])
    if missing:
        print("FAIL: missing rules:", missing)
    if "schemas.android.com" in " ".join(urls):
        ok = False
        print("FAIL: noise URL not filtered")
    print("selftest:", "PASS" if ok else "FAIL",
          "(%d findings, %d urls)" % (len(findings), len(urls)))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="ARTEX static APK analysis")
    ap.add_argument("--apk")
    ap.add_argument("--out")
    ap.add_argument("--work")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not args.apk:
        ap.error("--apk is required (or --selftest)")
    if not os.path.isfile(args.apk):
        ap.error("apk not found: " + args.apk)

    cleanup = False
    workdir = args.work
    if not workdir:
        workdir = tempfile.mkdtemp(prefix="apkscan-")
        cleanup = True
    else:
        os.makedirs(workdir, exist_ok=True)
    try:
        report = analyze(args.apk, workdir)
    finally:
        if cleanup:
            shutil.rmtree(workdir, ignore_errors=True)

    data = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(data)
        print("wrote", args.out, "—", report["summary"])
    else:
        print(data)


if __name__ == "__main__":
    main()
