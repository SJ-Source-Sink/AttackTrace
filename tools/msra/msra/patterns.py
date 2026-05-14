from __future__ import annotations

from dataclasses import dataclass
import re
from typing import List, Pattern


@dataclass(frozen=True)
class PatternRule:
    fid: str
    title: str
    severity: str
    pattern: Pattern[str]
    description: str
    attack_path: str
    adb: str


def get_patterns() -> List[PatternRule]:
    return [
        PatternRule(
            fid="webview-js-interface",
            title="WebView JavaScript interface enabled",
            severity="High",
            pattern=re.compile(r"addJavascriptInterface\(", re.IGNORECASE),
            description=(
                "A JavaScript interface is exposed to WebView content. Modern research highlights this as a "
                "high-risk surface when combined with untrusted content or weak URL validation."
            ),
            attack_path="An attacker can load content that reaches the JavaScript interface and executes sensitive methods.",
            adb="webview",
        ),
        PatternRule(
            fid="webview-js-enabled",
            title="WebView JavaScript enabled",
            severity="Medium",
            pattern=re.compile(r"setJavaScriptEnabled\(\s*true\s*\)", re.IGNORECASE),
            description=(
                "JavaScript is enabled in WebView. When content is attacker-controlled, it can enable XSS-style "
                "attacks and access to exposed bridges."
            ),
            attack_path="A malicious webpage can execute scripts and reach exposed WebView bridges.",
            adb="webview",
        ),
        PatternRule(
            fid="webview-file-access",
            title="WebView file access enabled",
            severity="Medium",
            pattern=re.compile(
                r"setAllowFileAccessFromFileURLs\(|setAllowUniversalAccessFromFileURLs\(",
                re.IGNORECASE,
            ),
            description=(
                "The WebView allows file URL access. Research shows this can enable local file disclosure "
                "or cross-origin access when combined with attacker-controlled content."
            ),
            attack_path="Attacker-controlled HTML can read local files or pivot to privileged origins.",
            adb="webview",
        ),
        PatternRule(
            fid="webview-file-access-true",
            title="WebView file access enabled (local files)",
            severity="Low",
            pattern=re.compile(r"setAllowFileAccess\(\s*true\s*\)", re.IGNORECASE),
            description=(
                "Local file access is allowed in WebView. If combined with untrusted content, it can expose "
                "local files or sensitive caches."
            ),
            attack_path="Attacker-controlled HTML can attempt to load local files via file:// URIs.",
            adb="webview",
        ),
        PatternRule(
            fid="webview-mixed-content",
            title="WebView mixed content allowed",
            severity="Medium",
            pattern=re.compile(r"MIXED_CONTENT_ALWAYS_ALLOW", re.IGNORECASE),
            description=(
                "Mixed content is allowed in WebView. This permits HTTP resources on HTTPS pages and can lead "
                "to MITM injection in embedded browsers."
            ),
            attack_path="A network attacker can inject scripts over HTTP into an HTTPS WebView.",
            adb="webview",
        ),
        PatternRule(
            fid="webview-dom-storage",
            title="WebView DOM storage enabled",
            severity="Low",
            pattern=re.compile(r"setDomStorageEnabled\(\s*true\s*\)", re.IGNORECASE),
            description=(
                "DOM storage is enabled. This can persist attacker-controlled data when WebView loads "
                "untrusted content."
            ),
            attack_path="An attacker can store data in WebView DOM storage for later retrieval.",
            adb="webview",
        ),
        PatternRule(
            fid="webview-save-password",
            title="WebView password saving enabled",
            severity="Low",
            pattern=re.compile(r"setSavePassword\(\s*true\s*\)", re.IGNORECASE),
            description=(
                "Password saving is enabled in WebView. This deprecated API can leak credentials on older "
                "Android versions."
            ),
            attack_path="Sensitive credentials may be stored and extracted from WebView.",
            adb="webview",
        ),
        PatternRule(
            fid="insecure-trust",
            title="Insecure TLS trust configuration",
            severity="High",
            pattern=re.compile(r"X509TrustManager|HostnameVerifier|TrustManager", re.IGNORECASE),
            description=(
                "Custom trust managers or hostname verifiers are commonly used to bypass TLS checks. "
                "Recent analyses show these patterns are a leading cause of MITM exposure in Android apps."
            ),
            attack_path="A network attacker can MITM traffic if TLS verification is bypassed.",
            adb="tls",
        ),
        PatternRule(
            fid="hostname-allow-all",
            title="Hostname verification bypass",
            severity="High",
            pattern=re.compile(r"ALLOW_ALL_HOSTNAME_VERIFIER|verify\(.*true\)", re.IGNORECASE),
            description=(
                "Hostname verification appears to be bypassed or forced to accept all hosts. This allows "
                "MITM attacks with any certificate."
            ),
            attack_path="A network attacker can present any certificate and intercept traffic.",
            adb="tls",
        ),
        PatternRule(
            fid="hardcoded-secret",
            title="Hardcoded secret or token",
            severity="High",
            pattern=re.compile(r"(api[_-]?key|secret|token|password)\s*=\s*\"[^\"]+\"", re.IGNORECASE),
            description=(
                "Hardcoded secrets remain a frequent source of credential leakage in mobile apps. "
                "They are trivially extracted once the APK is decompiled."
            ),
            attack_path="An attacker can recover the secret from the APK and use it to access backend services.",
            adb="general",
        ),
        PatternRule(
            fid="weak-hash",
            title="Weak hashing algorithm",
            severity="Medium",
            pattern=re.compile(r"MessageDigest\.getInstance\(\s*\"(MD5|SHA1)\"\s*\)", re.IGNORECASE),
            description=(
                "Weak hash algorithms (MD5/SHA1) are still present. Modern guidance discourages their use "
                "for integrity or password hashing due to collision attacks."
            ),
            attack_path="An attacker can exploit weak hashes to tamper with or spoof data.",
            adb="general",
        ),
        PatternRule(
            fid="aes-ecb",
            title="AES ECB mode detected",
            severity="High",
            pattern=re.compile(r"Cipher\.getInstance\(\s*\"AES/ECB", re.IGNORECASE),
            description=(
                "AES in ECB mode leaks structure and is considered insecure for most data. "
                "Recent mobile crypto audits continue to flag ECB usage."
            ),
            attack_path="An attacker can analyze repeated blocks to infer plaintext structure.",
            adb="general",
        ),
        PatternRule(
            fid="weak-crypto",
            title="Weak or legacy crypto algorithm",
            severity="High",
            pattern=re.compile(r"Cipher\.getInstance\(\s*\"(DES|RC4|RC2)", re.IGNORECASE),
            description=(
                "Legacy ciphers such as DES/RC4 are present. These are widely considered broken "
                "and can be cracked or downgraded."
            ),
            attack_path="An attacker can break or downgrade encrypted data.",
            adb="general",
        ),
        PatternRule(
            fid="insecure-random",
            title="Insecure random used for security",
            severity="Medium",
            pattern=re.compile(r"new\s+Random\(", re.IGNORECASE),
            description=(
                "java.util.Random is used. If this is for security tokens or keys, it is predictable "
                "and may be guessed."
            ),
            attack_path="An attacker can predict tokens or session identifiers.",
            adb="general",
        ),
        PatternRule(
            fid="world-readable-prefs",
            title="World-readable or world-writable storage",
            severity="High",
            pattern=re.compile(r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE", re.IGNORECASE),
            description=(
                "Legacy world-readable/writeable modes expose app data to other apps on older Android versions. "
                "This is a known data leakage risk."
            ),
            attack_path="A malicious app can read or modify private app data.",
            adb="general",
        ),
        PatternRule(
            fid="file-uri-exposed",
            title="File URI exposure",
            severity="Medium",
            pattern=re.compile(r"Uri\.fromFile\(|file://", re.IGNORECASE),
            description=(
                "File URIs are used. On newer Android versions, this can lead to FileUriExposedException "
                "or unintended file exposure if shared across apps."
            ),
            attack_path="An attacker app can attempt to access exposed file:// URIs.",
            adb="general",
        ),
        PatternRule(
            fid="log-sensitive",
            title="Sensitive data logged",
            severity="Medium",
            pattern=re.compile(r"Log\.(d|i|w|e)\(.*(token|password|secret|auth|bearer)", re.IGNORECASE),
            description=(
                "Sensitive data appears in logs. Research shows that logs are frequently accessible on rooted "
                "devices and during QA, leading to inadvertent data exposure."
            ),
            attack_path="An attacker with log access can read sensitive data from logcat.",
            adb="logcat",
        ),
        PatternRule(
            fid="pending-intent",
            title="Potentially mutable PendingIntent",
            severity="Medium",
            pattern=re.compile(r"PendingIntent\.get(Activity|Service|Broadcast)\(", re.IGNORECASE),
            description=(
                "PendingIntents created without explicit mutability flags can be hijacked or rejected on newer "
                "Android versions. Security research continues to highlight PendingIntent hijacking as a vector."
            ),
            attack_path="A malicious app can replay or mutate a PendingIntent if it is exposed.",
            adb="general",
        ),
    ]
