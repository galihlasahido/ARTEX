// frida-bypass.js — universal Android SSL-pinning + root-detection bypass for
// ARTEX dynamic analysis. Load on the rooted emulator so the app's HTTPS can be
// recorded through ARTEX's MITM proxy and so anti-tamper checks don't block the
// test. Objection's `android sslpinning disable` / `android root disable` cover
// most apps; use this when an app pins or root-checks in a way objection misses.
//
//   frida -U -f <package> -l frida-bypass.js --no-pause
//   # or against a running app:  frida -U -n <app> -l frida-bypass.js
//
// Authorized testing only, on an app in the engagement scope.

Java.perform(function () {
  function log(m) { console.log("[bypass] " + m); }

  // ---- 1. SSL / TLS pinning ----------------------------------------------

  // 1a. Default TrustManager: install an all-trusting one so custom pins and
  //     self-/MITM certs validate. This covers the common SSLContext.init path.
  try {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManager = Java.registerClass({
      name: "org.artex.TrustAll",
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; },
      },
    });
    var tms = [TrustManager.$new()];
    var init = SSLContext.init.overload(
      "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
    init.implementation = function (km, tm, sr) { init.call(this, km, tms, sr); };
    log("SSLContext.init pinned to all-trusting TrustManager");
  } catch (e) { log("TrustManager hook skipped: " + e); }

  // 1b. Android TrustManagerImpl.verifyChain (API 24+ pins land here).
  try {
    var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TMI.verifyChain.implementation = function (chain, authType, host, clientAuth, ocsp, tlsSct) {
      return chain; // accept as-is
    };
    log("conscrypt TrustManagerImpl.verifyChain bypassed");
  } catch (e) {}

  // 1c. OkHttp CertificatePinner.
  try {
    var CP = Java.use("okhttp3.CertificatePinner");
    CP.check.overload("java.lang.String", "java.util.List").implementation = function () {};
    log("okhttp3 CertificatePinner.check bypassed");
  } catch (e) {}

  // 1d. HostnameVerifier allow-all (defensive; MITM CA usually makes this moot).
  try {
    var HV = Java.use("javax.net.ssl.HttpsURLConnection");
    HV.setDefaultHostnameVerifier.implementation = function () {};
  } catch (e) {}

  // ---- 2. Root detection --------------------------------------------------

  // 2a. File.exists() for the usual su / Magisk / busybox paths returns false.
  try {
    var File = Java.use("java.io.File");
    var rootPaths = ["su", "magisk", "busybox", "/sbin/su", "superuser", "/system/xbin/su", "/system/bin/su"];
    File.exists.implementation = function () {
      var p = this.getAbsolutePath().toLowerCase();
      for (var i = 0; i < rootPaths.length; i++) {
        if (p.indexOf(rootPaths[i]) !== -1) { return false; }
      }
      return this.exists.call(this);
    };
    log("File.exists root-path checks neutralized");
  } catch (e) {}

  // 2b. Runtime.exec("su"/"which su") throws, as on an unrooted device.
  try {
    var Runtime = Java.use("java.lang.Runtime");
    var exec1 = Runtime.exec.overload("java.lang.String");
    exec1.implementation = function (cmd) {
      if (cmd && (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1 || cmd.indexOf("magisk") !== -1)) {
        throw Java.use("java.io.IOException").$new("not found");
      }
      return exec1.call(this, cmd);
    };
    log("Runtime.exec(su/which/magisk) blocked");
  } catch (e) {}

  // 2c. RootBeer library, if present.
  try {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    ["isRooted", "isRootedWithoutBusyBoxCheck", "checkForSuBinary", "checkForMagiskBinary"].forEach(function (m) {
      if (RootBeer[m]) { RootBeer[m].implementation = function () { return false; }; }
    });
    log("RootBeer checks return false");
  } catch (e) {}

  log("bypass installed");
});
