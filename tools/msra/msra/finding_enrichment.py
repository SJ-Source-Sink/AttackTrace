"""
Finding enrichment — adds reviewer-grade context to each finding.

For every finding we generate:
  - why_it_matters       : business/security impact with real-world context
  - how_to_verify        : exact step-by-step verification on a real device
  - code_analysis        : what the regex/AST matched and why it's risky
  - false_positive_check : conditions that would invalidate this finding
  - references           : authoritative external links (OWASP, CVEs, research)
  - confidence           : 'high' | 'medium' | 'low' rating
  - reviewer_priority    : 1-5 (1 = drop everything, look at this now)
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

from .code_filter import classify_path, confidence_for_path
from .utils import Finding


# ──────────────────────────────────────────────────────────────────────
# Per-vulnerability-type templates
# ──────────────────────────────────────────────────────────────────────

ENRICHMENT_RULES: Dict[str, Dict] = {

    # === SQL INJECTION ==================================================
    "sql_injection": {
        "match_keywords": ["sql injection"],
        "why_it_matters": (
            "SQL injection in a ContentProvider is one of the most critical Android "
            "vulnerabilities. Any installed app — even one with no declared permissions — "
            "can query an exported ContentProvider directly using `adb shell content query`. "
            "Exploitation is typically one-liner: a UNION SELECT can dump every table "
            "including session tokens, account credentials, PII, and transaction history. "
            "In apps with backups enabled, this data can be exfiltrated even without "
            "interaction. Google's Project Zero (2014) demonstrated this attack class "
            "against major apps including a major banking platform whose provider exposed "
            "full account data through a single crafted URI query."
        ),
        "how_to_verify": [
            "Open the decompiled source at `{file}:{line}` and confirm the SQL is built "
            "via string concatenation or `String.format`, not parameterized `selectionArgs`.",
            "Check AndroidManifest.xml — if `<provider android:exported=\"true\">` is "
            "present, any app can reach it.",
            "Run the UNION injection: `adb shell content query "
            "--uri \"content://{authority}/\" "
            "--where \"1=1) UNION SELECT name,sql,3 FROM sqlite_master--\"`",
            "If the response includes table names, escalate to data extraction: "
            "`--where \"1=2) UNION SELECT username,password,3 FROM users--\"`",
            "If the provider is not directly exported but reachable via deeplink, "
            "use `adb shell am start -a android.intent.action.VIEW -d \"<scheme>://<host>?q=1=1)UNION...\"`",
        ],
        "code_analysis": (
            "The scanner matched a `rawQuery()`, `execSQL()`, or `query()` call where "
            "the SQL WHERE clause is assembled with `+` concatenation or `String.format`. "
            "Neither operator binds parameters — user-supplied text lands inside SQL "
            "grammar verbatim. Correct code uses the `selectionArgs` parameter of "
            "`ContentProvider.query()`, which the SQLite driver quotes and escapes "
            "automatically. Pay attention to `getLastPathSegment()` and `getQueryParameter()` "
            "as common taint sources that flow directly into the SQL string."
        ),
        "false_positive_check": [
            "Every concatenated value is a compile-time constant with no runtime input.",
            "The class is a JUnit/Espresso test fixture (`/androidTest/`, `/test/`).",
            "A sibling overload with `selectionArgs` array is actually the called path.",
            "The input passes through a strict allow-list (e.g., only `[a-zA-Z0-9_]`) "
            "before concatenation.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m7-client-code-quality",
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://blog.oversecured.com/Content-Providers-and-the-potential-weak-spots-they-can-have/",
            "https://securitylab.github.com/research/android-content-providers-sql-injection/",
            "https://developer.android.com/guide/topics/providers/content-provider-basics#Permissions",
        ],
        "priority": 1,
    },

    # === PATH TRAVERSAL =================================================
    "path_traversal": {
        "match_keywords": ["path traversal"],
        "why_it_matters": (
            "A path-traversal bug in a ContentProvider lets any installed app escape "
            "the provider's intended file root and read arbitrary files from the app's "
            "private sandbox — including SharedPreferences (session tokens, account IDs), "
            "SQLite databases, and TLS certificate pins. The attack requires no special "
            "permissions and works on non-rooted devices. Oversecured's research (2021) "
            "showed that several top-100 Play Store apps were vulnerable; one banking app "
            "exposed its full OAuth token store through a single malformed URI. On API 29+ "
            "this also covers `content://` file-descriptor leaks via `openFile()`."
        ),
        "how_to_verify": [
            "Confirm the provider is exported: check `android:exported` or presence of "
            "`<intent-filter>` in the `<provider>` block of AndroidManifest.xml.",
            "Send a traversal URI: `adb shell content read "
            "--uri \"content://{authority}/../../shared_prefs/auth.xml\"`",
            "If file contents come back, the finding is confirmed.",
            "Try additional targets: "
            "`content://{authority}/../../databases/app_database.db` "
            "and `content://{authority}/../../files/tokens.json`",
            "Variant encodings: `..%2f`, `..%252f`, `%2e%2e/`, `..\\..\\` — "
            "providers that URL-decode before validation are bypassed differently.",
        ],
        "code_analysis": (
            "The matched code passes `uri.getLastPathSegment()` or `uri.getPath()` "
            "directly to `new File(baseDir, segment)` or `ParcelFileDescriptor.open()` "
            "without canonicalization. The correct fix is: "
            "`String canon = new File(baseDir, segment).getCanonicalPath(); "
            "if (!canon.startsWith(baseDir.getCanonicalPath())) { throw new SecurityException(); }` "
            "Note: `File.getPath()` and `File.getAbsolutePath()` do NOT resolve `..` — "
            "only `getCanonicalPath()` does."
        ),
        "false_positive_check": [
            "The code calls `getCanonicalPath()` and asserts the result starts with the "
            "allowed prefix before opening the file.",
            "The URI segment is validated against `[a-zA-Z0-9._-]+` (no `/` or `.`) "
            "before use.",
            "The provider is not exported and not reachable via any exported component.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://blog.oversecured.com/Content-Providers-and-the-potential-weak-spots-they-can-have/",
            "https://blog.oversecured.com/Oversecured-detects-dangerous-vulnerabilities-in-the-TikTok-Android-app/",
            "https://developer.android.com/reference/android/content/ContentProvider#openFile(android.net.Uri,%20java.lang.String)",
        ],
        "priority": 1,
    },

    # === HARDCODED CREDENTIALS ==========================================
    "hardcoded_credentials": {
        "match_keywords": ["hardcoded credentials", "hardcoded encryption", "hardcoded key", "hardcoded iv"],
        "why_it_matters": (
            "Credentials or cryptographic keys compiled into an APK are immediately "
            "recoverable by anyone who downloads the app from the Play Store. `jadx` "
            "recovers them in under 30 seconds with no special tools. If the key signs "
            "API requests, the attacker can forge transactions at will. If it encrypts "
            "user data at rest, the attacker can decrypt any backup. Notable real-world "
            "cases: in 2022 a major fintech app shipped its Stripe secret key in the APK; "
            "in 2023 researchers found Firebase API keys in hundreds of banking apps. "
            "Even keys stored in native libraries (.so) are recoverable with `strings` "
            "or Frida."
        ),
        "how_to_verify": [
            "Open `{file}:{line}` in the decompiled output and copy the literal value.",
            "Confirm it is not a placeholder (`your_key`, `changeme`, `test123`).",
            "Identify the service it authenticates to from the surrounding variable name "
            "or API call.",
            "For AWS keys: `aws sts get-caller-identity --aws-access-key-id <key>`",
            "For Firebase: `curl -s 'https://<project>.firebaseio.com/.json?auth=<key>'`",
            "For generic API keys: search GitHub/Shodan for the key to see if others have "
            "already exploited it.",
            "Rotate the credential immediately if confirmed — even before the app is patched.",
        ],
        "code_analysis": (
            "A field whose name matches a credential keyword (`password`, `secret`, "
            "`api_key`, `token`, `private_key`, `auth`, `apiKey`, ...) is assigned "
            "a non-trivial string literal at declaration time. The scanner excludes "
            "known placeholder strings and `BuildConfig.*` references. Pay attention "
            "to Base64-encoded strings near crypto calls — these are often hidden keys."
        ),
        "false_positive_check": [
            "The literal is a known test/placeholder value (`changeme`, `password123`, "
            "`test`, `YOUR_KEY_HERE`).",
            "The field is populated at runtime from `BuildConfig`, environment variables, "
            "or a secure secrets manager — the literal in source is only a fallback "
            "never reached in production.",
            "The string is a public OAuth client ID (not a secret) — client IDs are "
            "designed to be public; client *secrets* are not.",
            "The string is a fixed salt for a KDF, stored alongside the algorithm params "
            "— review whether the salt alone is sufficient for an attack.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://blog.gitguardian.com/hardcoded-secrets-in-android-apps/",
            "https://developer.android.com/training/articles/keystore",
            "https://cloud.google.com/secret-manager/docs/overview",
        ],
        "priority": 2,
    },

    # === WEAK CRYPTO ====================================================
    "weak_crypto": {
        "match_keywords": ["aes ecb", "des", "3des", "rc4", "md5", "sha-1", "sha1", "weak crypto"],
        "why_it_matters": (
            "Weak cryptographic algorithms give a false sense of security. "
            "AES/ECB leaks block patterns — encrypting two identical 16-byte blocks "
            "produces identical ciphertext, enabling chosen-plaintext attacks and "
            "structural analysis. MD5 and SHA-1 have fully demonstrated chosen-prefix "
            "collisions (SHAttered, 2017; HashClash); a collision takes minutes on "
            "consumer hardware. DES's 56-bit key was broken by a $250,000 machine in "
            "1998 and is now crackable in hours on rented cloud compute. RC4 has "
            "statistical biases in its output that leak keystream. If any of these "
            "protect session integrity, user data, or code signing, the protection "
            "should be treated as absent."
        ),
        "how_to_verify": [
            "Open `{file}:{line}` and trace *what* is being encrypted or hashed — "
            "session token? stored password? file integrity check?",
            "For ECB: encrypt a payload with two identical 16-byte blocks; if both "
            "output blocks are identical, ECB is confirmed.",
            "For MD5/SHA-1 (integrity): use `hashcat` or an online rainbow table "
            "to reverse a captured hash.",
            "For DES/3DES: dump the encrypted file from the app sandbox "
            "(`adb shell run-as {package} cp /data/data/{package}/files/enc.dat /sdcard/`) "
            "and decrypt with a known key from decompiled code.",
            "If the algorithm is used only as a cache key or ETag (no security function), "
            "mark as informational.",
        ],
        "code_analysis": (
            "The scanner matched a `Cipher.getInstance()` call with an ECB-mode or "
            "legacy algorithm, or a `MessageDigest.getInstance(\"MD5\"|\"SHA-1\")` call. "
            "For Cipher: `\"AES\"` without a mode defaults to `\"AES/ECB/PKCS5Padding\"` "
            "in the JCA provider — this is NOT the same as AES/GCM. The expected "
            "replacement is `\"AES/GCM/NoPadding\"` with a random 12-byte IV per "
            "encryption and a 128-bit authentication tag."
        ),
        "false_positive_check": [
            "The hash is used purely as a cache key or ETag with no security function.",
            "The cipher is used to interoperate with a legacy server you don't control "
            "and cannot upgrade — note this as a known risk.",
            "The code is in a third-party library; fix is an upstream version bump.",
            "The MD5 call is computing a checksum for a progress indicator, not an HMAC.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m5-insufficient-cryptography",
            "https://cwe.mitre.org/data/definitions/327.html",
            "https://shattered.io/",
            "https://nvd.nist.gov/vuln/detail/CVE-2004-2761",
            "https://developer.android.com/guide/topics/security/cryptography",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        ],
        "priority": 3,
    },

    # === EXPORTED COMPONENT =============================================
    "exported_component": {
        "match_keywords": ["exported activity", "exported service", "exported broadcastreceiver",
                           "exported contentprovider", "exported provider"],
        "why_it_matters": (
            "Exported Android components with no permission requirement are reachable by "
            "any installed app — no user interaction needed. The real impact depends entirely "
            "on what the component does: if it loads a URL supplied via Intent extras (common "
            "in Activities), any app can redirect a victim user's WebView to an attacker-controlled "
            "page. If it reads/writes files, it's a file read gadget. If it starts other activities "
            "based on an extra, it may enable intent redirect attacks that bypass "
            "`android:exported=\"false\"`. Google's 2023 Android Vulnerability Report cites "
            "component exposure as the top privilege-escalation class in apps above 100M installs."
        ),
        "how_to_verify": [
            "Locate the component class in `{file}` and read its `onCreate()`/`onReceive()`/`onStartCommand()`.",
            "Identify which Intent extras or URI parameters it reads.",
            "Invoke it directly: `adb shell am start -n {package}/{fqcn}` "
            "(use `am broadcast` for receivers, `am startservice` for services).",
            "Pass crafted extras: `--es url 'https://attacker.example' --ez admin true`",
            "Confirm the component performs a sensitive action with attacker input.",
        ],
        "code_analysis": (
            "AndroidManifest.xml declares this component with `android:exported=\"true\"` "
            "or with an `<intent-filter>` (which implicitly exports on API < 31) and no "
            "`android:permission` attribute. On API 31+ the implicit-export rule was tightened, "
            "but an explicit `exported=\"true\"` without a permission is always a risk regardless "
            "of API level. The component's handler class must be reviewed manually — this rule "
            "flags the exposure, not the exploitation."
        ),
        "false_positive_check": [
            "The component is intentionally public (deeplink target, OAuth redirect, "
            "home-screen shortcut, share receiver) and performs no privileged operation.",
            "A custom permission with `android:protectionLevel=\"signature\"` or "
            "`\"signatureOrSystem\"` guards the component — only apps signed with the "
            "same certificate can invoke it.",
            "The component is a `BroadcastReceiver` for system broadcasts "
            "(e.g., `BOOT_COMPLETED`) where the OS is the only sender.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
            "https://cwe.mitre.org/data/definitions/926.html",
            "https://developer.android.com/guide/topics/manifest/activity-element#exported",
            "https://blog.oversecured.com/Android-Access-to-app-protected-components/",
            "https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-felt.pdf",
        ],
        "priority": 3,
    },

    # === WEBVIEW FAMILY =================================================
    "webview": {
        "match_keywords": ["webview", "addjavascriptinterface", "setjavascriptenabled",
                           "webview ssl", "webview file access", "webview javascript"],
        "why_it_matters": (
            "WebViews are full Chromium-based browsers embedded inside the app. They share "
            "the app's process, can access Java objects exposed via `@JavascriptInterface`, "
            "and (with file access enabled) can read the app's private storage. Three "
            "independent attack surfaces compound here: (1) if the URL loaded is attacker-"
            "controllable, arbitrary JavaScript runs in the app's origin and can steal "
            "cookies and tokens; (2) if `setAllowUniversalAccessFromFileURLs(true)` is set, "
            "a `file://` page can use XHR to read any file the app can access; (3) exposed "
            "JavascriptInterface methods are callable from any page the WebView loads, "
            "including an attacker's page. The Oversecured WebView bug class has been "
            "exploited in major fintech apps to exfiltrate full account tokens."
        ),
        "how_to_verify": [
            "Identify the Activity/Fragment hosting the WebView in `{file}`.",
            "Check whether the URL comes from `getIntent().getStringExtra(...)` or "
            "`getData().getQueryParameter(...)` — these are attacker-controllable.",
            "Test JavaScript execution: "
            "`adb shell am start -n {package}/{fqcn} --es url 'javascript:alert(document.domain)'`",
            "If an alert fires, JavaScript runs in the app's origin.",
            "For file access: serve an HTML page that does "
            "`fetch('file:///data/data/{package}/shared_prefs/prefs.xml')` "
            "and exfiltrates the result.",
            "Enumerate JavascriptInterfaces: search for `addJavascriptInterface(` in the "
            "decompiled source to find all exposed objects and their methods.",
        ],
        "code_analysis": (
            "The scanner matched WebView configuration or URL-loading code. Key indicators: "
            "`setJavaScriptEnabled(true)` alone is not dangerous unless the URL is "
            "controllable; `setAllowUniversalAccessFromFileURLs(true)` combined with any "
            "`file://` URL load is almost always exploitable; `addJavascriptInterface()` "
            "exposes a Java object whose public methods become callable from any page. "
            "Check whether `shouldOverrideUrlLoading()` / `shouldInterceptRequest()` "
            "implement a URL allow-list — their absence is the real risk."
        ),
        "false_positive_check": [
            "The WebView loads only a bundled `file:///android_asset/` URL with no "
            "runtime parameters — the HTML is shipped inside the APK and cannot be "
            "influenced by external input.",
            "All externally-supplied URLs are validated against a strict allow-list "
            "(scheme + exact host check) before `loadUrl()`.",
            "JavascriptInterface methods are side-effect-free read-only getters with no "
            "sensitive data exposed.",
            "File access APIs are disabled explicitly: "
            "`setAllowFileAccess(false); setAllowFileAccessFromFileURLs(false); "
            "setAllowUniversalAccessFromFileURLs(false);`",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
            "https://cwe.mitre.org/data/definitions/749.html",
            "https://blog.oversecured.com/Android-security-checklist-webview/",
            "https://labs.withsecure.com/publications/webview-addjavascriptinterface-remote-code-execution",
            "https://developer.android.com/develop/ui/views/layout/webapps/webview-best-practices",
            "https://www.nowsecure.com/blog/2014/08/07/webview-addjavascriptinterface-security-issue/",
        ],
        "priority": 2,
    },

    # === DEBUGGABLE =====================================================
    "debuggable": {
        "match_keywords": ["debuggable"],
        "why_it_matters": (
            "Shipping a debuggable APK is the single highest-impact configuration mistake "
            "on Android. It grants anyone with physical USB access complete read/write "
            "access to the app's private data directory via `adb shell run-as`, without "
            "root, without unlocking the bootloader, and without bypassing any OS security "
            "control. An attacker can also attach a JDWP debugger and modify runtime "
            "variables — bypassing certificate pinning, root detection, and authentication "
            "checks in real time. This is listed as a release blocker in every major "
            "Android security hardening guide and is specifically checked in MASVS-RESILIENCE-4. "
            "In 2021, a major trading app was found to ship `android:debuggable=true` in its "
            "Play Store release, allowing full account takeover via USB access at trading kiosks."
        ),
        "how_to_verify": [
            "Confirm `android:debuggable=\"true\"` in AndroidManifest.xml "
            "`<application>` tag.",
            "On a non-rooted test device: "
            "`adb shell run-as {package} ls /data/data/{package}/`",
            "If the directory listing succeeds, the app is debuggable on this device.",
            "Extract auth tokens: "
            "`adb shell run-as {package} cat /data/data/{package}/shared_prefs/*.xml`",
            "Attach a debugger: `adb shell am set-debug-app -w {package}`, launch the app, "
            "then connect via Android Studio → Run → Attach Debugger to Android Process.",
            "Set a breakpoint on `login()` to capture credentials at runtime.",
        ],
        "code_analysis": (
            "AndroidManifest.xml `<application android:debuggable=\"true\">` is present. "
            "The Gradle `release` build type clears this flag automatically. Its presence "
            "means either: (1) the APK was built with `./gradlew assembleDebug`, or "
            "(2) the manifest was edited directly, or (3) a custom build script sets "
            "`manifestPlaceholders = [debuggable: true]`. Check the CI/CD pipeline — "
            "a signed release build with this flag is a process failure."
        ),
        "false_positive_check": [
            "The APK was provided as an internal staging build — confirm with the client "
            "that the Play Store release does NOT have this flag.",
            "The flag is in a `debug` source-set manifest overlay that Gradle merges only "
            "in debug builds and is not present in the release manifest.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
            "https://cwe.mitre.org/data/definitions/489.html",
            "https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/",
            "https://developer.android.com/studio/debug/",
            "https://developer.android.com/guide/topics/manifest/application-element#debug",
            "https://www.nowsecure.com/blog/2023/01/10/android-application-security-testing-checklist/",
        ],
        "priority": 1,
    },

    # === NETWORK / TLS ==================================================
    "tls_bypass": {
        "match_keywords": ["trust all", "trustmanager", "hostname verification", "ssl error",
                           "ssl bypass", "certificate pinning", "hostname verifier"],
        "why_it_matters": (
            "Disabling TLS validation removes the entire security guarantee of HTTPS. "
            "Any active MITM attacker — rogue WiFi hotspot, malicious VPN, on-path ISP "
            "equipment, or compromised DNS — can read and modify every HTTPS request "
            "in real time. For financial apps this means intercepting auth tokens, "
            "account numbers, and transaction data. For MFA flows it means capturing "
            "OTPs. The MITRE ATT&CK Mobile framework (T1553) specifically tracks this "
            "technique as 'Subvert Trust Controls'. Several major banks have received "
            "CVEs for shipping empty TrustManagers in production builds — including a "
            "2022 case where all API communication was interceptable without any "
            "certificate installed."
        ),
        "how_to_verify": [
            "Set up mitmproxy: `mitmproxy --listen-port 8080 --ssl-insecure`",
            "Route the test device: "
            "`adb shell settings put global http_proxy <attacker_ip>:8080`",
            "Launch the app and attempt a login or API call.",
            "Observe mitmproxy — if HTTPS requests appear decrypted, TLS is bypassed.",
            "For certificate pinning bypass specifically: install the mitmproxy CA "
            "(`adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /sdcard/` then import via "
            "Settings → Security → Install Certificate), then retry without `--ssl-insecure`.",
            "Clean up: `adb shell settings delete global http_proxy`",
        ],
        "code_analysis": (
            "One of three classic bypass patterns was matched: (1) an empty "
            "`X509TrustManager.checkServerTrusted()` that accepts all certificates; "
            "(2) `SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER` or a "
            "`HostnameVerifier` that unconditionally returns `true`; "
            "(3) `onReceivedSslError()` calling `handler.proceed()` instead of "
            "`handler.cancel()`. Any one of these breaks TLS entirely."
        ),
        "false_positive_check": [
            "The bypass is inside `if (BuildConfig.DEBUG)` — confirm the release build "
            "flag is `false` in production.",
            "The class is in `/test/` or `/androidTest/` — test infrastructure, "
            "not shipped to users.",
            "The custom TrustManager implements strict pinning (not accepting all) "
            "and is the real validator.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication",
            "https://cwe.mitre.org/data/definitions/295.html",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-8028",
            "https://mitmproxy.org/",
            "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/",
            "https://developer.android.com/training/articles/security-ssl",
        ],
        "priority": 1,
    },

    # === LOGGING ========================================================
    "logging_sensitive": {
        "match_keywords": ["sensitive data in log", "http traffic body", "network traffic logged"],
        "why_it_matters": (
            "Android's logcat buffer is accessible to any app holding the `READ_LOGS` "
            "permission (automatically granted to all apps on Android < 4.1, and "
            "grantable by the user on later versions). Device crash dumps and bug reports "
            "submitted to support desks often include several minutes of logcat history. "
            "MDM solutions, crash reporters (Firebase Crashlytics, Sentry), and enterprise "
            "monitoring tools frequently forward logs to external servers. A credential in "
            "a log statement has therefore escaped the device boundary. NIST SP 800-163 "
            "explicitly prohibits logging authentication credentials for this reason."
        ),
        "how_to_verify": [
            "Run: `adb logcat --pid=$(adb shell pidof {package}) | grep -iE "
            "'password|token|bearer|auth|secret|key|ssn|dob'`",
            "Trigger the relevant flow (login, payment, settings sync) while watching "
            "the log.",
            "If any credential or PII appears, the finding is confirmed.",
            "Also check for base64-encoded values: `| base64 -d` can reveal hidden tokens.",
        ],
        "code_analysis": (
            "A `Log.d()` / `Log.i()` / `Log.v()` / `Timber.d()` call passes a variable "
            "whose name contains a credential keyword to the logging framework. This "
            "rule matches the variable name — verify by reviewing the call site to confirm "
            "the variable actually holds sensitive material at runtime."
        ),
        "false_positive_check": [
            "The log call is inside `if (BuildConfig.DEBUG)` — confirmed as false "
            "in the release build.",
            "ProGuard/R8 rules include `-assumenosideeffects class android.util.Log` "
            "to strip all log calls in release.",
            "The variable name contains `token` but holds a non-secret public "
            "identifier (e.g., Firebase notification token — not an auth secret).",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
            "https://cwe.mitre.org/data/definitions/532.html",
            "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-163r1.pdf",
            "https://developer.android.com/reference/android/util/Log",
            "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/",
        ],
        "priority": 3,
    },

    # === STORAGE ========================================================
    "insecure_storage": {
        "match_keywords": ["sharedpreferences", "sqlite", "external storage",
                           "world-readable", "world-writable", "insecure storage"],
        "why_it_matters": (
            "Unencrypted sensitive data at rest is readable by anyone who can access "
            "the device storage — full-disk encryption does not protect data once the "
            "device is unlocked. SharedPreferences XML files and SQLite databases are "
            "trivially extracted via `adb backup` (on older Android), `run-as` (on "
            "debuggable builds), or rooted device file access. Android `MODE_WORLD_READABLE` "
            "(deprecated but still functional on some OEM ROMs) makes files readable by "
            "any app. The Android Keystore and `EncryptedSharedPreferences` (Jetpack "
            "Security) exist specifically to prevent this class of bug — failure to use "
            "them for high-value data is a MASVS-STORAGE-1 violation."
        ),
        "how_to_verify": [
            "If debuggable: "
            "`adb shell run-as {package} cat /data/data/{package}/shared_prefs/*.xml`",
            "If backups enabled: `adb backup -f backup.ab -apk {package}` then "
            "`dd if=backup.ab bs=24 skip=1 | zlib-flate -uncompress | tar xvf -`",
            "Check the extracted files for plaintext tokens, passwords, or PII.",
            "For SQLite: `adb pull /data/data/{package}/databases/ ./db_dump/` "
            "and open with `DB Browser for SQLite`.",
        ],
        "code_analysis": (
            "A `SharedPreferences.Editor.putString()` or SQLite `insert()`/`execSQL()` "
            "call where the key name suggests sensitive data. The pattern matches "
            "the key name — review whether the stored value is plaintext or already "
            "encrypted before storage."
        ),
        "false_positive_check": [
            "The value is encrypted before storage (e.g., `EncryptedSharedPreferences`, "
            "AES-GCM with a Keystore-backed key).",
            "The app uses `androidx.security.crypto` or Tink for at-rest encryption.",
            "The stored value is a non-sensitive preference (theme, locale, feature flag).",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
            "https://cwe.mitre.org/data/definitions/312.html",
            "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/",
            "https://developer.android.com/topic/security/data",
            "https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences",
            "https://github.com/google/tink",
        ],
        "priority": 3,
    },

    # === INTENT REDIRECT ================================================
    "intent_redirect": {
        "match_keywords": ["intent redirect", "parcelableextra", "unvalidated intent"],
        "why_it_matters": (
            "Intent-redirect (also called 'StrandHogg 2.0' in its severe variant) allows "
            "any installed app to invoke internal, non-exported components of the victim "
            "app. The attack works by sending a crafted Intent to an exported component "
            "that blindly forwards an embedded inner Intent — the attacker controls the "
            "inner target. Demonstrated impacts include: bypassing login screens, accessing "
            "admin activities, acquiring content URI grants for private files, and in some "
            "cases RCE via deeplink handlers. CVE-2020-0095 (Android StrandHogg 2.0) was "
            "exploited in the wild by banking trojans before the patch was distributed."
        ),
        "how_to_verify": [
            "Confirm the outer activity is exported (check manifest).",
            "Read its source at `{file}` to find where it calls `startActivity(getIntent()."
            "getParcelableExtra(\"next_intent\"))` or similar.",
            "Build a test APK that sends an Intent to the outer activity with a wrapped "
            "inner Intent targeting a non-exported class of `{package}`.",
            "Confirm the internal activity launches with attacker-controlled extras.",
            "Test URI permission grants: add `FLAG_GRANT_READ_URI_PERMISSION` to the "
            "inner Intent — the victim app may grant the attacker read access to "
            "content URIs it would not normally share.",
        ],
        "code_analysis": (
            "The matched code extracts a Parcelable (likely an Intent) from incoming "
            "`getIntent()` extras and passes it directly to `startActivity()`, "
            "`startService()`, or `sendBroadcast()` without validating the component, "
            "package, or scheme. Proper mitigation requires explicitly checking "
            "`inner.getComponent()` against an allow-list or calling "
            "`inner.setPackage(null); inner.setComponent(null)` to strip targeting."
        ),
        "false_positive_check": [
            "The code validates `inner.getComponent().getPackageName()` equals "
            "`getPackageName()` before forwarding.",
            "The inner Intent is stripped of component info before use: "
            "`inner.setComponent(null)`.",
            "The outer activity is not exported and not reachable via deeplink.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
            "https://cwe.mitre.org/data/definitions/926.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-0095",
            "https://blog.oversecured.com/Android-Access-to-app-protected-components/",
            "https://promon.co/security-news/strandhogg-2/",
            "https://developer.android.com/guide/components/intents-filters#PendingIntents",
        ],
        "priority": 2,
    },

    # === DEEPLINK =======================================================
    "deeplink_no_validation": {
        "match_keywords": ["deeplink", "deep link", "intent filter", "no validation"],
        "why_it_matters": (
            "Unvalidated deeplink parameters are an increasingly targeted attack surface "
            "as apps expand their deeplink usage for OAuth callbacks, promotional links, "
            "and in-app navigation. An attacker can craft a URL hosted on a webpage "
            "(or sent via SMS/email) that triggers privileged actions when clicked — "
            "loading an attacker's URL in a WebView (XSS/token theft), injecting SQL "
            "via a query parameter, or triggering a file download to an attacker-controlled "
            "path. OAuth PKCE flows are particularly sensitive: a deeplink that receives "
            "the `code` parameter without verifying `state` is vulnerable to authorization "
            "code interception (RFC 6819 §4.4.1). Stripe, Twitter, and several payment "
            "processors have issued security advisories for deeplink validation failures "
            "in partner SDKs."
        ),
        "how_to_verify": [
            "Find the `<intent-filter>` with `<data android:scheme=...>` in the manifest.",
            "Identify what parameters the handler reads from `getData()` or "
            "`getIntent().getData().getQueryParameter(...)`.",
            "Craft a target URI: `<scheme>://<host>/<path>?param=<payload>`",
            "Trigger: `adb shell am start -a android.intent.action.VIEW "
            "-d \"<your-uri>\" {package}`",
            "For WebView sinks: use `?url=https://attacker.example` as payload.",
            "For SQL sinks: try `?id=1 UNION SELECT...`",
            "For file sinks: try `?path=../../shared_prefs/auth.xml`",
        ],
        "code_analysis": (
            "The matched code reads `getIntent().getData()` query parameters or path "
            "segments and passes them to a sensitive operation without sanitization. "
            "Common vulnerable patterns: `webView.loadUrl(data.getQueryParameter(\"url\"))`, "
            "`new File(baseDir, data.getLastPathSegment())`, "
            "`db.rawQuery(data.getQueryParameter(\"filter\"), null)`. "
            "Proper mitigation: validate scheme+host+path structure before use; for OAuth "
            "flows verify the `state` parameter matches the one stored before launch."
        ),
        "false_positive_check": [
            "The deeplink handler validates the full URI against a strict allow-list "
            "(scheme, host, and path prefix all checked).",
            "Query parameters are treated as opaque data and never passed to file, "
            "SQL, or WebView sinks.",
            "The handler only processes a fixed set of parameter names and ignores all "
            "others.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
            "https://cwe.mitre.org/data/definitions/939.html",
            "https://tools.ietf.org/html/rfc6819#section-4.4.1",
            "https://blog.oversecured.com/Android-security-checklist-intent-redirection/",
            "https://developer.android.com/training/app-links/deep-linking",
            "https://checkmarx.com/blog/android-deeplink-vulnerabilities/",
        ],
        "priority": 2,
    },

    # === ALLOW BACKUP ===================================================
    "allow_backup": {
        "match_keywords": ["allowbackup", "allow backup", "android backup"],
        "why_it_matters": (
            "When `android:allowBackup=\"true\"` is set, the entire app data directory "
            "— including databases, SharedPreferences, and credential caches — can be "
            "extracted over USB with `adb backup` without root access, even on a locked "
            "device (on some Android versions). The backup archive can also be restored "
            "to a different device under attacker control, enabling account hijacking "
            "by transplanting session tokens. Financial and healthcare apps are "
            "specifically required to disable backups in NIST SP 800-124 and HIPAA "
            "mobile guidance. Starting with API 31 the attribute defaults to `true` "
            "if unset — explicit disabling is required."
        ),
        "how_to_verify": [
            "Confirm `android:allowBackup=\"true\"` (or absence of the flag on API 31+) "
            "in AndroidManifest.xml.",
            "Run: `adb backup -f {package}.ab -apk {package}` while the app is running.",
            "Unpack: `dd if={package}.ab bs=24 skip=1 | python3 -c "
            "'import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))' "
            "| tar xvf -`",
            "Inspect the extracted files for tokens, session cookies, or stored credentials.",
        ],
        "code_analysis": (
            "AndroidManifest.xml `<application android:allowBackup=\"true\">`. "
            "The fix is to set `android:allowBackup=\"false\"` for apps that handle "
            "sensitive data. If selective backup is needed, use "
            "`android:fullBackupContent=\"@xml/backup_rules\"` with `<exclude>` "
            "rules for sensitive files."
        ),
        "false_positive_check": [
            "The app uses `android:fullBackupContent` with explicit exclusion rules "
            "that prevent sensitive data from being backed up.",
            "The app encrypts all stored data before writing — the backup is safe "
            "even if extracted.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
            "https://cwe.mitre.org/data/definitions/312.html",
            "https://developer.android.com/guide/topics/data/autobackup",
            "https://developer.android.com/guide/topics/data/backup",
            "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/",
        ],
        "priority": 2,
    },

    # === CLEARTEXT TRAFFIC ==============================================
    "cleartext_traffic": {
        "match_keywords": ["cleartext", "http url", "http://", "cleartexttrafficpermitted"],
        "why_it_matters": (
            "HTTP (cleartext) traffic can be intercepted and modified by any network "
            "intermediary — WiFi access points, mobile carriers, corporate proxies, and "
            "ISP deep-packet-inspection appliances. Unlike HTTPS, HTTP provides no "
            "confidentiality, authenticity, or integrity guarantees. For financial apps, "
            "a cleartext request carrying session tokens or transaction data is equivalent "
            "to posting them publicly. Android 9+ defaults to blocking cleartext traffic "
            "via Network Security Config, but `android:usesCleartextTraffic=\"true\"` or "
            "explicit `cleartextTrafficPermitted=\"true\"` re-enables it globally or "
            "per-domain. Hardcoded `http://` URLs in code bypass all OS protections."
        ),
        "how_to_verify": [
            "Set up mitmproxy in transparent mode (same network as device).",
            "Run the app and trigger all major flows (login, data sync, analytics).",
            "Check mitmproxy's HTTP flow list — any entries are cleartext intercepts.",
            "Also check for `http://` literals in the decompiled source: "
            "`grep -r 'http://' decompiled/sources/ --include='*.java'`",
        ],
        "code_analysis": (
            "Either a hardcoded `http://` URL was found in app source code, or "
            "the Network Security Config allows cleartext traffic for a specific domain. "
            "Hardcoded URLs in Java source survive ProGuard and are not affected by "
            "Network Security Config — they are direct cleartext channels."
        ),
        "false_positive_check": [
            "The URL is only used in debug builds (`BuildConfig.DEBUG`).",
            "The `http://` URL points to `localhost` or `10.0.2.2` (emulator loopback) "
            "— test infrastructure, not production.",
            "The URL is in a comment, documentation string, or dead code.",
        ],
        "references": [
            "https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication",
            "https://cwe.mitre.org/data/definitions/319.html",
            "https://developer.android.com/training/articles/security-config",
            "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/",
            "https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic",
        ],
        "priority": 2,
    },
}


def _identify_rule(title: str) -> Optional[str]:
    """Map a finding title to one of the enrichment rule keys."""
    t = title.lower()
    for rule_key, rule in ENRICHMENT_RULES.items():
        for kw in rule["match_keywords"]:
            if kw in t:
                return rule_key
    return None


def _component_from_finding(finding: Finding, package: str) -> Tuple[str, str]:
    """Return (component_name, authority) extracted from finding evidence."""
    extra = finding.extra or {}
    component = ""
    authority = ""

    if isinstance(extra, dict):
        component = extra.get("component") or extra.get("activity") or ""
        authority = extra.get("authority") or ""

    if not component and finding.evidence and finding.evidence.file_path:
        stem = os.path.basename(finding.evidence.file_path)
        stem = stem.replace(".java", "").replace(".kt", "")
        if stem and "$" not in stem:
            component = f"{package}.{stem}"

    if not authority:
        authority = f"{package}.provider"

    return component or f"{package}.MainActivity", authority


def _format_strings(items: List[str], **kwargs) -> List[str]:
    """Format every string in a list with safe defaults."""
    out = []
    for item in items:
        try:
            out.append(item.format(**kwargs))
        except (KeyError, IndexError):
            out.append(item)
    return out


def enrich_finding(finding: Finding, package: str) -> Finding:
    """
    Add reviewer-grade context to a single finding.

    Mutates and returns the same Finding (new fields go into `extra`
    and `references`).
    """
    if finding.extra is None:
        finding.extra = {}

    title = finding.title or ""
    rule_key = _identify_rule(title)

    # Always add confidence based on file location
    file_path = finding.evidence.file_path if finding.evidence else ""
    code_class = classify_path(file_path) if file_path else "manifest"
    confidence = confidence_for_path(file_path) if file_path else "high"

    finding.extra["code_class"] = code_class
    finding.extra["confidence"] = confidence

    # If we have a rule template, attach the reviewer fields
    if rule_key:
        rule = ENRICHMENT_RULES[rule_key]
        component, authority = _component_from_finding(finding, package)

        # Build the FQCN from the evidence file path
        fqcn = component
        if file_path and '/sources/' in file_path:
            rel = file_path.split('/sources/', 1)[1]
            for ext in ('.java', '.kt'):
                if rel.endswith(ext):
                    rel = rel[:-len(ext)]
                    break
            fqcn = rel.replace('/', '.')

        fmt = {
            "package":   package,
            "component": component.split(".")[-1] if component else "MainActivity",
            "fqcn":      fqcn or component,
            "authority": authority,
            "file":      _short_file(file_path),
            "line":      finding.evidence.line_number if finding.evidence else 0,
        }

        finding.extra["why_it_matters"]       = rule["why_it_matters"]
        finding.extra["how_to_verify"]        = _format_strings(rule["how_to_verify"], **fmt)
        finding.extra["code_analysis"]        = rule["code_analysis"]
        finding.extra["false_positive_check"] = rule["false_positive_check"]
        finding.extra["reviewer_priority"]    = rule["priority"]
        finding.extra["rule_key"]             = rule_key

        # Merge enrichment references into the finding (don't replace existing)
        enrichment_refs = rule.get("references", [])
        existing_refs = list(finding.references or [])
        # Deduplicate: add only refs not already present
        merged = existing_refs + [r for r in enrichment_refs if r not in existing_refs]
        finding.references = merged

        # Adjust priority based on code location: library code is lower priority
        if code_class in ("library", "obfuscated"):
            finding.extra["reviewer_priority"] = min(5, rule["priority"] + 2)

    else:
        finding.extra["reviewer_priority"] = 4

    return finding


def _short_file(path: str) -> str:
    """Return a shortened file path for display."""
    if not path:
        return ""
    if "/sources/" in path:
        return "sources/" + path.split("/sources/")[-1]
    if "/resources/" in path:
        return "resources/" + path.split("/resources/")[-1]
    return path


def enrich_findings(findings: List[Finding], package: str) -> List[Finding]:
    """Enrich a list of findings in place. Returns the same list."""
    for f in findings:
        enrich_finding(f, package)
    return findings


# ──────────────────────────────────────────────────────────────────────
# Grouping — collapse multiple identical findings in the same class
# ──────────────────────────────────────────────────────────────────────


# Patterns that detect the same underlying vulnerability — collapse them
# into a single canonical bucket so we don't show 2-3 cards for one bug.
_DEDUP_ALIASES = {
    # SQL injection variants
    "component-sql-injection":      "sql_injection_provider",
    "bb-content-provider-sqli":     "sql_injection_provider",
    "os-provider-sql-injection":    "sql_injection_provider",
    "deep-provider-sql_injection":  "sql_injection_provider",
    # Path traversal variants
    "component-path-traversal":     "path_traversal_provider",
    "bb-path-traversal-provider":   "path_traversal_provider",
    "deep-provider-path_traversal": "path_traversal_provider",
    # WebView SSL bypass
    "webview-ssl-error-proceed":    "webview_ssl_bypass",
    "network-webview-ssl-proceed":  "webview_ssl_bypass",
    # WebView file access (universal vs from-file are technically distinct
    # but in practice indicate the same misconfiguration)
    "webview-file-access-universal":"webview_file_access_unsafe",
    "webview-file-access-from-file":"webview_file_access_unsafe",
    "os-webview-file-xhr-access":   "webview_file_access_unsafe",
    # WebView JS interface
    "webview-js-interface":         "webview_js_interface",
    # Path traversal in providers (additional rule id)
    "os-content-provider-path-traversal": "path_traversal_provider",
}


def _canonical_rule(fid: str) -> str:
    """Map a finding's rule id to a canonical bucket for cross-pattern dedup."""
    if not fid:
        return ""
    base = fid.split(":", 1)[0]
    return _DEDUP_ALIASES.get(base, base)


def group_findings_by_class(findings: List[Finding]) -> List[Finding]:
    """
    Collapse findings that share (canonical_rule, file_path) into one card.

    Two layers of grouping:
      1. Cross-pattern: rules that detect the same vuln (e.g. two different
         SQL injection regexes) get merged via the _DEDUP_ALIASES map.
      2. Same-class: multiple matches in the same file collapse, with every
         hit recorded under `extra.occurrences = [...]`.

    The first finding wins as the primary; later ones contribute their line
    numbers and snippets only.
    """
    groups: Dict[Tuple[str, str], Finding] = {}
    order: List[Tuple[str, str]] = []

    for f in findings:
        rule_id = _canonical_rule(f.fid or f.title)
        file_path = f.evidence.file_path if f.evidence else ""
        key = (rule_id, file_path)

        if key not in groups:
            groups[key] = f
            order.append(key)
            if f.extra is None:
                f.extra = {}
            line_no = f.evidence.line_number if f.evidence else 0
            snippet = f.evidence.snippet if f.evidence else ""
            f.extra["occurrences"] = [
                {"line": line_no, "snippet": snippet}
            ]
        else:
            primary = groups[key]
            if primary.extra is None:
                primary.extra = {}
            occ = primary.extra.setdefault("occurrences", [])
            line_no = f.evidence.line_number if f.evidence else 0
            snippet = f.evidence.snippet if f.evidence else ""
            # Avoid duplicate line entries
            if not any(o.get("line") == line_no for o in occ):
                occ.append({"line": line_no, "snippet": snippet})

    return [groups[k] for k in order]
