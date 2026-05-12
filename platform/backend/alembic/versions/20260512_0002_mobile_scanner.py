"""Mobile scanner: patterns, scans, findings tables + built-in pattern seed

Revision ID: mobile_scanner_001
Revises: add_assigned_to_findings
Create Date: 2026-05-12
"""

import uuid
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "mobile_scanner_001"
down_revision = "add_assigned_to_findings"
branch_labels = None
depends_on = None


# ---------------------------------------------------------------------------
# Built-in detection patterns
# ---------------------------------------------------------------------------
def _uid():
    return str(uuid.uuid4())


BUILTIN_PATTERNS = [
    # ── Android ──────────────────────────────────────────────────────────────
    {
        "id": _uid(), "platform": "android", "severity": "Critical", "is_custom": False,
        "title": "Hardcoded API Key or Secret",
        "category": "Secrets",
        "cwe": "CWE-798",
        "regex_pattern": r'(api[_\-]?key|api[_\-]?secret|client[_\-]?secret|auth[_\-]?token)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']',
        "description": "A hardcoded API key, secret, or authentication token was found. Attackers who decompile the APK gain permanent access to the associated service.",
        "remediation": "Move secrets to a remote config service, environment variables, or encrypted secure storage. Never embed secrets in source code or resources.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "Critical", "is_custom": False,
        "title": "Hardcoded Password",
        "category": "Secrets",
        "cwe": "CWE-259",
        "regex_pattern": r'(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
        "description": "A plaintext password is hardcoded in the application code or resources.",
        "remediation": "Never hardcode passwords. Use Android Keystore or server-side authentication.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "Cleartext HTTP Traffic",
        "category": "Network Security",
        "cwe": "CWE-319",
        "regex_pattern": r'http://(?!localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.)[\w.\-]+',
        "description": "The application communicates over unencrypted HTTP with a remote server, exposing data to interception.",
        "remediation": "Use HTTPS for all network communication. Set android:usesCleartextTraffic=false in the AndroidManifest.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "WebView JavaScript Enabled",
        "category": "WebView Security",
        "cwe": "CWE-749",
        "regex_pattern": r'setJavaScriptEnabled\s*\(\s*true\s*\)',
        "description": "WebView has JavaScript enabled. Combined with addJavascriptInterface or a compromised URL, this can lead to XSS or RCE.",
        "remediation": "Disable JavaScript unless strictly necessary. If required, use a strict allowlist for URLs loaded in the WebView and remove addJavascriptInterface in production.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "WebView addJavascriptInterface",
        "category": "WebView Security",
        "cwe": "CWE-749",
        "regex_pattern": r'addJavascriptInterface\s*\(',
        "description": "addJavascriptInterface exposes Java objects to JavaScript. On Android < 4.2, this allows arbitrary code execution.",
        "remediation": "Remove addJavascriptInterface or ensure minSdkVersion >= 17 and the exposed interface is minimal and safe.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "Insecure SSL/TLS — Trust All Certificates",
        "category": "Cryptography",
        "cwe": "CWE-295",
        "regex_pattern": r'(TrustAllCerts|X509TrustManager|checkServerTrusted\s*\([^)]*\)\s*\{?\s*\})',
        "description": "The application disables SSL certificate validation, making it vulnerable to man-in-the-middle attacks.",
        "remediation": "Use the default TrustManager. Implement certificate pinning for sensitive endpoints.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "Weak Cryptography — DES or RC4",
        "category": "Cryptography",
        "cwe": "CWE-327",
        "regex_pattern": r'Cipher\.getInstance\s*\(\s*["\'](?:DES|DESede|RC4|RC2|Blowfish)[/"\']',
        "description": "A deprecated or weak cipher algorithm (DES, RC4) is used for encryption.",
        "remediation": "Replace with AES/GCM/NoPadding or AES/CBC/PKCS7Padding with a 256-bit key.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "MD5 or SHA1 for Sensitive Hashing",
        "category": "Cryptography",
        "cwe": "CWE-328",
        "regex_pattern": r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1|SHA1)["\']',
        "description": "MD5 and SHA-1 are cryptographically broken and should not be used for passwords, signatures, or integrity checks.",
        "remediation": "Use SHA-256 or SHA-3 for general hashing. Use bcrypt/Argon2 for passwords.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "Medium", "is_custom": False,
        "title": "ECB Mode Encryption",
        "category": "Cryptography",
        "cwe": "CWE-327",
        "regex_pattern": r'Cipher\.getInstance\s*\(\s*["\']AES/ECB',
        "description": "AES in ECB mode does not use an IV, making encrypted blocks deterministic and patterns visible in ciphertext.",
        "remediation": "Use AES/GCM/NoPadding or AES/CBC/PKCS7Padding with a random IV.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "Insecure Random — Math.random()",
        "category": "Cryptography",
        "cwe": "CWE-330",
        "regex_pattern": r'Math\.random\s*\(',
        "description": "Math.random() is a pseudo-random generator not suitable for security-sensitive values like session tokens or keys.",
        "remediation": "Use SecureRandom for security-sensitive randomness.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "Insecure SharedPreferences — World Readable",
        "category": "Data Storage",
        "cwe": "CWE-921",
        "regex_pattern": r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',
        "description": "Data stored in world-readable SharedPreferences can be read by any application on the device.",
        "remediation": "Use MODE_PRIVATE for SharedPreferences. Consider EncryptedSharedPreferences for sensitive data.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "External Storage for Sensitive Data",
        "category": "Data Storage",
        "cwe": "CWE-922",
        "regex_pattern": r'getExternalStorage|getExternalFilesDir|openFileOutput.*EXTERNAL',
        "description": "Data written to external storage (SD card) is accessible to other applications with READ_EXTERNAL_STORAGE permission.",
        "remediation": "Store sensitive data in internal app storage or use the Android Keystore system.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "Medium", "is_custom": False,
        "title": "Backup Enabled in Manifest",
        "category": "Data Storage",
        "cwe": "CWE-530",
        "regex_pattern": r'android:allowBackup\s*=\s*"true"',
        "description": "allowBackup=true allows ADB backup to extract all app data without root access.",
        "remediation": "Set android:allowBackup=false or use android:fullBackupContent to exclude sensitive files.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "Debug Mode Enabled in Manifest",
        "category": "Configuration",
        "cwe": "CWE-489",
        "regex_pattern": r'android:debuggable\s*=\s*"true"',
        "description": "Debuggable apps can be attached by ADB, allowing memory inspection and code injection.",
        "remediation": "Never ship a production APK with android:debuggable=true. Remove this attribute — it defaults to false in release builds.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "Exported Activity Without Permission",
        "category": "Access Control",
        "cwe": "CWE-926",
        "regex_pattern": r'android:exported\s*=\s*"true"(?:(?!android:permission).){0,200}(?:<activity)',
        "description": "An exported activity without a permission restriction can be launched by any third-party application.",
        "remediation": "Add android:permission to exported components or set android:exported=false for components not intended for external use.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "SQL Injection — Raw Query with Concatenation",
        "category": "Injection",
        "cwe": "CWE-89",
        "regex_pattern": r'(rawQuery|execSQL)\s*\([^)]*\+[^)]*\)',
        "description": "A raw SQL query is constructed by string concatenation with user-controlled data, enabling SQL injection.",
        "remediation": "Use parameterized queries via SQLiteDatabase.query() with selection args, or Room's @Query with :parameters.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "Dynamic Code Loading",
        "category": "Code Execution",
        "cwe": "CWE-913",
        "regex_pattern": r'DexClassLoader|PathClassLoader|loadClass\s*\(|Class\.forName\s*\(',
        "description": "The app loads and executes code dynamically, which can be abused to load malicious DEX files.",
        "remediation": "Avoid dynamic code loading from untrusted sources. If required, verify signatures of loaded code.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "Critical", "is_custom": False,
        "title": "Runtime Command Execution",
        "category": "Code Execution",
        "cwe": "CWE-78",
        "regex_pattern": r'Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(|ProcessBuilder\s*\(',
        "description": "The application executes OS commands at runtime. If the command includes user-controlled data, this is an OS command injection vulnerability.",
        "remediation": "Avoid Runtime.exec(). If shell commands are necessary, allowlist permitted commands and never include user-controlled data.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "Medium", "is_custom": False,
        "title": "Logging Sensitive Data",
        "category": "Data Exposure",
        "cwe": "CWE-532",
        "regex_pattern": r'Log\.[dvwief]\s*\([^)]*(?:password|token|secret|key|credit|ssn|auth)[^)]*\)',
        "description": "Potentially sensitive values are written to Android logcat, readable by other apps with READ_LOGS permission.",
        "remediation": "Remove or guard all Log statements with BuildConfig.DEBUG checks. Use ProGuard/R8 to strip log calls in release builds.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "Medium", "is_custom": False,
        "title": "Intent Without Explicit Component (Implicit Intent)",
        "category": "Access Control",
        "cwe": "CWE-927",
        "regex_pattern": r'new\s+Intent\s*\(\s*["\'][a-zA-Z.]+ACTION',
        "description": "Implicit intents can be intercepted by malicious apps that register for the same action.",
        "remediation": "Use explicit intents with a specific component class for sensitive operations. Use LocalBroadcastManager for intra-app broadcasts.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "Medium", "is_custom": False,
        "title": "Hardcoded Database Credentials",
        "category": "Secrets",
        "cwe": "CWE-798",
        "regex_pattern": r'(jdbc:[a-zA-Z]+://[^"\']+)',
        "description": "A JDBC connection string with credentials is hardcoded in the application.",
        "remediation": "Store database credentials server-side. The mobile app should never connect directly to a database.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "Medium", "is_custom": False,
        "title": "Pending Intent — Mutable Without FLAG_IMMUTABLE",
        "category": "Access Control",
        "cwe": "CWE-925",
        "regex_pattern": r'PendingIntent\.(getActivity|getBroadcast|getService)\s*\(',
        "description": "Mutable PendingIntents without FLAG_IMMUTABLE can be modified by malicious apps on Android 12+.",
        "remediation": "Add FLAG_IMMUTABLE to all PendingIntent calls unless mutability is required.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "Medium", "is_custom": False,
        "title": "WebView File Access Enabled",
        "category": "WebView Security",
        "cwe": "CWE-200",
        "regex_pattern": r'setAllowFileAccess\s*\(\s*true\s*\)|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
        "description": "WebView file access allows JavaScript to read local files via file:// URIs, potentially leaking app data.",
        "remediation": "Set setAllowFileAccess(false) and setAllowFileAccessFromFileURLs(false) unless explicitly required.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "Low", "is_custom": False,
        "title": "StrictMode Disabled in Production Code",
        "category": "Configuration",
        "cwe": "CWE-489",
        "regex_pattern": r'StrictMode\.(?:setThreadPolicy|setVmPolicy)',
        "description": "StrictMode configuration found outside of debug-only blocks may indicate development settings shipped to production.",
        "remediation": "Wrap all StrictMode calls in if(BuildConfig.DEBUG) blocks.",
    },
    {
        "id": _uid(), "platform": "android", "severity": "High", "is_custom": False,
        "title": "Realm Database Unencrypted or Empty Key",
        "category": "Data Storage",
        "cwe": "CWE-312",
        "regex_pattern": r'RealmConfiguration\.Builder\s*\(\s*\)(?:(?!encryptionKey).){0,500}\.build\s*\(\s*\)',
        "description": "A Realm database is opened without an encryption key, storing data in plaintext on the device.",
        "remediation": "Always use an encryption key from Android Keystore when configuring Realm.",
    },

    # ── iOS ───────────────────────────────────────────────────────────────────
    {
        "id": _uid(), "platform": "ios", "severity": "High", "is_custom": False,
        "title": "NSLog Sensitive Data",
        "category": "Data Exposure",
        "cwe": "CWE-532",
        "regex_pattern": r'NSLog\s*\(@"[^"]*(?:password|token|secret|key|auth|credit)[^"]*"',
        "description": "Sensitive values are written to NSLog, accessible via device console in development and potentially in jailbroken devices.",
        "remediation": "Remove NSLog from production builds. Use os_log with appropriate log levels and never log sensitive data.",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "Critical", "is_custom": False,
        "title": "Hardcoded API Key in Swift/Objective-C",
        "category": "Secrets",
        "cwe": "CWE-798",
        "regex_pattern": r'(apiKey|api_key|APIKey|clientSecret|authToken)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']',
        "description": "A hardcoded API key or secret is embedded in the iOS application source.",
        "remediation": "Use iOS Keychain or a remote secrets service. Never embed credentials in source code or plist files.",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "High", "is_custom": False,
        "title": "App Transport Security Disabled",
        "category": "Network Security",
        "cwe": "CWE-319",
        "regex_pattern": r'NSAllowsArbitraryLoads\s*</?\s*(?:true|key)',
        "description": "NSAllowsArbitraryLoads disables App Transport Security, allowing cleartext HTTP connections to any server.",
        "remediation": "Remove NSAllowsArbitraryLoads. Use NSExceptionDomains with minimum TLS version for specific domains only.",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "High", "is_custom": False,
        "title": "UIWebView Usage (Deprecated)",
        "category": "WebView Security",
        "cwe": "CWE-749",
        "regex_pattern": r'UIWebView|UIWebViewDelegate',
        "description": "UIWebView is deprecated and contains unfixed security vulnerabilities. It lacks many WKWebView security improvements.",
        "remediation": "Migrate to WKWebView which provides process isolation and better JavaScript sandboxing.",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "High", "is_custom": False,
        "title": "Keychain Item Accessible Always (No Device Restriction)",
        "category": "Data Storage",
        "cwe": "CWE-312",
        "regex_pattern": r'kSecAttrAccessibleAlways(?:ThisDeviceOnly)?(?!\w)',
        "description": "Keychain items with kSecAttrAccessibleAlways are accessible even when the device is locked, reducing security.",
        "remediation": "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly for sensitive data that should only be accessible when the device is unlocked.",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "High", "is_custom": False,
        "title": "MD5/SHA1 Weak Hash (CommonCrypto)",
        "category": "Cryptography",
        "cwe": "CWE-328",
        "regex_pattern": r'CC_MD5|CC_SHA1|kCCAlgorithmDES|kCCOptionECBMode',
        "description": "Weak or broken cryptographic primitives (MD5, SHA-1, DES, ECB) are used via CommonCrypto.",
        "remediation": "Use CC_SHA256, AES-GCM, or CryptoKit's modern APIs (AES.GCM, ChaChaPoly).",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "Medium", "is_custom": False,
        "title": "NSUserDefaults Storing Sensitive Data",
        "category": "Data Storage",
        "cwe": "CWE-312",
        "regex_pattern": r'UserDefaults\.standard\.set\s*\([^,]+,\s*forKey:\s*"[^"]*(?:token|password|secret|key|auth)[^"]*"\s*\)',
        "description": "Sensitive data stored in NSUserDefaults is stored as plaintext plist and is not protected by the iOS Keychain.",
        "remediation": "Use iOS Keychain for tokens, passwords, and cryptographic keys.",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "High", "is_custom": False,
        "title": "SQLite Injection — String Interpolation",
        "category": "Injection",
        "cwe": "CWE-89",
        "regex_pattern": r'sqlite3_exec\s*\([^,]+,\s*(?:[^"]*\+|\\()',
        "description": "SQL query to SQLite is constructed by string interpolation, enabling SQL injection.",
        "remediation": "Use sqlite3_prepare_v2 with bound parameters, or use FMDB/GRDB with parameterized queries.",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "Medium", "is_custom": False,
        "title": "UIPasteboard Write — Sensitive Data",
        "category": "Data Exposure",
        "cwe": "CWE-200",
        "regex_pattern": r'UIPasteboard\.general\.string\s*=|UIPasteboard\.general\.setValue',
        "description": "Data written to UIPasteboard is accessible to all apps on the device and persists after app removal.",
        "remediation": "Avoid writing sensitive data to the pasteboard. If required, use UIPasteboard with localOnly:true and expirationDate.",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "Medium", "is_custom": False,
        "title": "Hardcoded URL — Internal Endpoint",
        "category": "Secrets",
        "cwe": "CWE-547",
        "regex_pattern": r'"https?://(?:internal|dev|staging|test|qa|admin|api)\.[a-zA-Z0-9.\-]+"',
        "description": "Internal, development, or staging server URLs are hardcoded and may expose internal infrastructure.",
        "remediation": "Use environment-specific build configurations (xcconfig files) rather than hardcoding URLs.",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "Medium", "is_custom": False,
        "title": "getenv() for Secrets",
        "category": "Secrets",
        "cwe": "CWE-526",
        "regex_pattern": r'getenv\s*\(\s*"[^"]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS)[^"]*"\s*\)',
        "description": "Secrets loaded from environment variables are not available in iOS production apps and indicate a misconfigured security model.",
        "remediation": "Use iOS Keychain or remote configuration for secrets.",
    },
    {
        "id": _uid(), "platform": "ios", "severity": "Low", "is_custom": False,
        "title": "ptrace Anti-Debug Bypass Pattern",
        "category": "Anti-Tamper",
        "cwe": "CWE-693",
        "regex_pattern": r'ptrace\s*\(\s*PT_DENY_ATTACH',
        "description": "ptrace(PT_DENY_ATTACH) is used for anti-debugging. This is easily bypassed and indicates reliance on insecure anti-tampering.",
        "remediation": "Implement server-side integrity checks rather than relying on client-side anti-debugging.",
    },

    # ── JAR / All ─────────────────────────────────────────────────────────────
    {
        "id": _uid(), "platform": "jar", "severity": "Critical", "is_custom": False,
        "title": "Java Deserialization — ObjectInputStream",
        "category": "Injection",
        "cwe": "CWE-502",
        "regex_pattern": r'new\s+ObjectInputStream\s*\(|readObject\s*\(\s*\)',
        "description": "Java native deserialization via ObjectInputStream can trigger remote code execution gadget chains.",
        "remediation": "Replace ObjectInputStream with safe serialization formats (JSON, Protobuf). If required, use a deserialization filter (JEP 290).",
    },
    {
        "id": _uid(), "platform": "jar", "severity": "High", "is_custom": False,
        "title": "SQL String Concatenation (Java)",
        "category": "Injection",
        "cwe": "CWE-89",
        "regex_pattern": r'(?:createQuery|createStatement|executeQuery|executeUpdate)\s*\([^)]*\+',
        "description": "SQL query built by string concatenation is vulnerable to SQL injection.",
        "remediation": "Use PreparedStatement with parameterized queries or JPA/Hibernate named parameters.",
    },
    {
        "id": _uid(), "platform": "jar", "severity": "High", "is_custom": False,
        "title": "Hardcoded SecretKeySpec Bytes",
        "category": "Cryptography",
        "cwe": "CWE-321",
        "regex_pattern": r'new\s+SecretKeySpec\s*\(\s*(?:new\s+byte\s*\[|")',
        "description": "A cryptographic key is hardcoded as a byte array or string literal.",
        "remediation": "Derive keys from a secure source (HSM, KMS). Never hardcode cryptographic keys.",
    },
    {
        "id": _uid(), "platform": "jar", "severity": "High", "is_custom": False,
        "title": "Trust-All SSL Manager (Java)",
        "category": "Cryptography",
        "cwe": "CWE-295",
        "regex_pattern": r'SSLContext\.getInstance\s*\(\s*["\'](?:SSL|TLS)["\'].*\)\s*;[^;]*init\s*\(',
        "description": "SSLContext may be initialized with a trust-all TrustManager, disabling certificate validation.",
        "remediation": "Use the default SSLContext or implement certificate pinning.",
    },
    {
        "id": _uid(), "platform": "all", "severity": "Critical", "is_custom": False,
        "title": "AWS Access Key Exposed",
        "category": "Secrets",
        "cwe": "CWE-798",
        "regex_pattern": r'AKIA[0-9A-Z]{16}',
        "description": "An AWS Access Key ID was found. This grants access to AWS services and could lead to cloud resource compromise.",
        "remediation": "Rotate the key immediately. Use IAM roles or AWS Secrets Manager instead of hardcoded keys.",
    },
    {
        "id": _uid(), "platform": "all", "severity": "High", "is_custom": False,
        "title": "Google API Key Exposed",
        "category": "Secrets",
        "cwe": "CWE-798",
        "regex_pattern": r'AIza[0-9A-Za-z\-_]{35}',
        "description": "A Google API key was found. Depending on the key's scope, this can enable API abuse and billing charges.",
        "remediation": "Restrict the key to specific APIs and referrers in the Google Cloud Console. Use server-side APIs for sensitive operations.",
    },
    {
        "id": _uid(), "platform": "all", "severity": "High", "is_custom": False,
        "title": "GitHub/GitLab Personal Access Token",
        "category": "Secrets",
        "cwe": "CWE-798",
        "regex_pattern": r'(?:ghp|gho|ghu|ghs|ghr|glpat)_[A-Za-z0-9]{36,}',
        "description": "A GitHub or GitLab personal access token was found, providing access to source code and CI/CD pipelines.",
        "remediation": "Revoke the token immediately. Use short-lived tokens or machine accounts with minimal scope.",
    },
    {
        "id": _uid(), "platform": "all", "severity": "High", "is_custom": False,
        "title": "Private Key Material",
        "category": "Cryptography",
        "cwe": "CWE-312",
        "regex_pattern": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "description": "A PEM-encoded private key is embedded in the application.",
        "remediation": "Remove all private keys from the app bundle. Use certificate pinning for server validation, not client certificates.",
    },
    {
        "id": _uid(), "platform": "all", "severity": "Medium", "is_custom": False,
        "title": "Stripe Secret Key",
        "category": "Secrets",
        "cwe": "CWE-798",
        "regex_pattern": r'sk_live_[A-Za-z0-9]{24,}',
        "description": "A Stripe live secret key was found. This allows full access to the Stripe account including charges and refunds.",
        "remediation": "Rotate immediately. Never use secret keys in mobile apps — use Stripe's publishable key and process payments server-side.",
    },
    {
        "id": _uid(), "platform": "all", "severity": "Medium", "is_custom": False,
        "title": "Firebase Database URL Exposed",
        "category": "Secrets",
        "cwe": "CWE-200",
        "regex_pattern": r'https://[a-zA-Z0-9\-]+\.firebaseio\.com',
        "description": "A Firebase Realtime Database URL is exposed. If rules allow unauthenticated access, data can be read or written.",
        "remediation": "Ensure Firebase Security Rules require authentication. Never allow public read/write access.",
    },
    {
        "id": _uid(), "platform": "all", "severity": "Low", "is_custom": False,
        "title": "Internal IP Address Hardcoded",
        "category": "Secrets",
        "cwe": "CWE-547",
        "regex_pattern": r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})',
        "description": "An internal RFC-1918 IP address is hardcoded, exposing internal network topology.",
        "remediation": "Use domain names with DNS-based service discovery. Remove hardcoded internal IPs from production builds.",
    },
    {
        "id": _uid(), "platform": "all", "severity": "Medium", "is_custom": False,
        "title": "Base64-Encoded Secret",
        "category": "Secrets",
        "cwe": "CWE-798",
        "regex_pattern": r'(?:password|secret|key|token)\s*[=:]\s*["\'][A-Za-z0-9+/]{32,}={0,2}["\']',
        "description": "A potential Base64-encoded secret or credential was found. Obfuscation via Base64 does not provide security.",
        "remediation": "Use proper secrets management. Obfuscation is not encryption.",
    },
]


def upgrade() -> None:
    # ── mobile_patterns ──────────────────────────────────────────────────────
    mobile_patterns = op.create_table(
        "mobile_patterns",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("platform", sa.String(20), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(128), nullable=False),
        sa.Column("regex_pattern", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("cwe", sa.String(32), nullable=True),
        sa.Column("is_custom", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_mpattern_org_platform", "mobile_patterns", ["org_id", "platform"])
    op.create_index("idx_mpattern_enabled_platform", "mobile_patterns", ["is_enabled", "platform"])

    # ── mobile_scans ──────────────────────────────────────────────────────────
    op.create_table(
        "mobile_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("app_name", sa.String(255), nullable=False),
        sa.Column("package_id", sa.String(255), nullable=True),
        sa.Column("platform", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("findings_count", postgresql.JSONB(), nullable=False,
                  server_default='{"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}'),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("celery_task_id", sa.String(255), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_mscan_org_status", "mobile_scans", ["org_id", "status"])
    op.create_index("idx_mscan_org_created", "mobile_scans", ["org_id", "created_at"])

    # ── mobile_findings ───────────────────────────────────────────────────────
    op.create_table(
        "mobile_findings",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pattern_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.Column("triage_status", sa.String(32), nullable=False, server_default="New"),
        sa.Column("cwe", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["mobile_scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["pattern_id"], ["mobile_patterns.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_mfinding_scan", "mobile_findings", ["scan_id"])

    # ── Seed built-in patterns ────────────────────────────────────────────────
    rows = [
        {
            "id": p["id"],
            "org_id": None,
            "platform": p["platform"],
            "title": p["title"],
            "severity": p["severity"],
            "category": p["category"],
            "regex_pattern": p["regex_pattern"],
            "description": p.get("description"),
            "remediation": p.get("remediation"),
            "cwe": p.get("cwe"),
            "is_custom": False,
            "is_enabled": True,
        }
        for p in BUILTIN_PATTERNS
    ]
    op.bulk_insert(mobile_patterns, rows)


def downgrade() -> None:
    op.drop_table("mobile_findings")
    op.drop_table("mobile_scans")
    op.drop_table("mobile_patterns")
