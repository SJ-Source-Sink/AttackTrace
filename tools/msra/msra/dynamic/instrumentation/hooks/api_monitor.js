/**
 * Sensitive API Monitoring Script — Full Coverage Build
 *
 * Monitors:
 *  - SharedPreferences (read / write)
 *  - ContentProvider (query / insert / update / delete)
 *  - Cryptographic operations (Cipher, SecretKeySpec, KeyStore, KeyGenerator, Mac)
 *  - Android Log output (sensitive pattern detection)
 *  - File operations (read / write)
 *  - Network (HttpURLConnection, OkHttp3, java.net.URL)
 *  - Intent dispatch and extras
 *  - WebView operations (loadUrl, addJavascriptInterface, evaluateJavascript)
 *  - SQLiteDatabase (rawQuery, execSQL, query, compileStatement) with injection detection
 *  - DexClassLoader / PathClassLoader dynamic loading
 *  - Bundle / Intent extras comprehensive monitoring
 *  - Clipboard (get / set)
 *  - AccountManager (getAuthToken)
 *  - BiometricPrompt authentication callback bypass
 *  - MemoryFile / Binder IPC monitoring
 *
 * Message format:
 *   send({ type: "api_event", class: X, method: Y, args: [...],
 *          extra: { severity: "high|medium|low|critical", category: "...", detail: "..." } })
 *
 * Startup:
 *   send({ type: "hooks_loaded", count: N })
 */

Java.perform(function () {
    console.log("[*] API Monitor loading...");

    var hookCount = 0;

    // =========================================================================
    // Shared utilities
    // =========================================================================

    /** Convert a Java byte array to a hex string (first maxBytes bytes). */
    function bytesToHex(javaBytes, maxBytes) {
        var hex = "";
        try {
            var limit = Math.min(javaBytes.length, maxBytes || 64);
            for (var i = 0; i < limit; i++) {
                var b = javaBytes[i] & 0xff;
                hex += (b < 16 ? "0" : "") + b.toString(16);
            }
            if (javaBytes.length > (maxBytes || 64)) hex += "...";
        } catch (e) { hex = "<err>"; }
        return hex;
    }

    /** Truncate a string to maxLen, appending "..." if trimmed. */
    function trunc(s, maxLen) {
        if (s === null || s === undefined) return null;
        var str = String(s);
        return str.length > (maxLen || 200) ? str.substring(0, maxLen || 200) + "..." : str;
    }

    /** Convert a Java String[] to a JS array of strings. */
    function javaStrArrayToJS(arr) {
        if (arr === null || arr === undefined) return null;
        try {
            var result = [];
            for (var i = 0; i < arr.length; i++) {
                result.push(arr[i] !== null ? String(arr[i]) : null);
            }
            return result;
        } catch (e) { return ["<err>"]; }
    }

    /** SQL injection pattern detection. Returns true if suspicious. */
    var SQL_INJECTION_PATTERNS = [
        /union\s+select/i,
        /'\s+or\s+/i,
        /'\s+and\s+/i,
        /--\s/,
        /\/\*.*\*\//,
        /;\s*drop\s+/i,
        /;\s*delete\s+/i,
        /;\s*insert\s+/i,
        /;\s*update\s+/i,
        /xp_cmdshell/i,
        /exec\s*\(/i,
        /char\s*\(\d/i
    ];

    function detectSqlInjection(sql) {
        if (!sql) return false;
        for (var i = 0; i < SQL_INJECTION_PATTERNS.length; i++) {
            if (SQL_INJECTION_PATTERNS[i].test(sql)) return true;
        }
        return false;
    }

    var SENSITIVE_KEY_PATTERNS = [
        "token", "password", "passwd", "secret", "api_key", "apikey",
        "session", "auth", "credential", "private", "cert", "key",
        "access_token", "refresh_token", "bearer", "oauth"
    ];

    function isSensitiveKey(key) {
        if (!key) return false;
        var lower = key.toLowerCase();
        for (var i = 0; i < SENSITIVE_KEY_PATTERNS.length; i++) {
            if (lower.indexOf(SENSITIVE_KEY_PATTERNS[i]) >= 0) return true;
        }
        return false;
    }

    // =========================================================================
    // 1. SharedPreferences Monitoring
    // =========================================================================
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");

        SharedPreferencesImpl.getString
            .overload("java.lang.String", "java.lang.String")
            .implementation = function (key, defValue) {
                var value = this.getString(key, defValue);
                if (isSensitiveKey(key)) {
                    send({
                        type: "api_event", class: "SharedPreferences", method: "getString",
                        args: [key, value ? trunc(value, 50) : null],
                        extra: {severity: "high", category: "storage",
                                detail: "Sensitive SharedPreferences read: " + key}
                    });
                }
                return value;
            };

        var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

        EditorImpl.putString
            .overload("java.lang.String", "java.lang.String")
            .implementation = function (key, value) {
                if (isSensitiveKey(key)) {
                    send({
                        type: "api_event", class: "SharedPreferences.Editor", method: "putString",
                        args: [key, "[REDACTED]"],
                        extra: {severity: "high", category: "storage",
                                detail: "Sensitive SharedPreferences write: " + key}
                    });
                }
                return this.putString(key, value);
            };

        hookCount += 2;
        console.log("[+] SharedPreferences monitoring installed");
    } catch (e) {
        console.log("[-] SharedPreferences monitoring failed: " + e);
    }

    // =========================================================================
    // 2. ContentProvider / ContentResolver Monitoring
    // =========================================================================
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");

        ContentResolver.query
            .overload("android.net.Uri", "[Ljava.lang.String;",
                      "java.lang.String", "[Ljava.lang.String;", "java.lang.String")
            .implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
                send({
                    type: "api_event", class: "ContentResolver", method: "query",
                    args: [uri.toString(), selection],
                    extra: {severity: "medium", category: "storage", detail: "ContentResolver query"}
                });
                return this.query(uri, projection, selection, selectionArgs, sortOrder);
            };

        ContentResolver.insert
            .overload("android.net.Uri", "android.content.ContentValues")
            .implementation = function (uri, values) {
                send({
                    type: "api_event", class: "ContentResolver", method: "insert",
                    args: [uri.toString()],
                    extra: {severity: "medium", category: "storage", detail: "ContentResolver insert"}
                });
                return this.insert(uri, values);
            };

        ContentResolver.update
            .overload("android.net.Uri", "android.content.ContentValues",
                      "java.lang.String", "[Ljava.lang.String;")
            .implementation = function (uri, values, where, selectionArgs) {
                send({
                    type: "api_event", class: "ContentResolver", method: "update",
                    args: [uri.toString(), where],
                    extra: {severity: "medium", category: "storage", detail: "ContentResolver update"}
                });
                return this.update(uri, values, where, selectionArgs);
            };

        ContentResolver.delete
            .overload("android.net.Uri", "java.lang.String", "[Ljava.lang.String;")
            .implementation = function (uri, where, selectionArgs) {
                send({
                    type: "api_event", class: "ContentResolver", method: "delete",
                    args: [uri.toString(), where],
                    extra: {severity: "medium", category: "storage", detail: "ContentResolver delete"}
                });
                return this.delete(uri, where, selectionArgs);
            };

        hookCount += 4;
        console.log("[+] ContentResolver monitoring installed");
    } catch (e) {
        console.log("[-] ContentResolver monitoring failed: " + e);
    }

    // =========================================================================
    // 3. SQLiteDatabase Monitoring (NEW)
    // =========================================================================
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

        // rawQuery(String sql, String[] selectionArgs)
        SQLiteDatabase.rawQuery
            .overload("java.lang.String", "[Ljava.lang.String;")
            .implementation = function (sql, selectionArgs) {
                var injection = detectSqlInjection(sql);
                send({
                    type: "api_event", class: "SQLiteDatabase", method: "rawQuery",
                    args: [trunc(sql, 300), javaStrArrayToJS(selectionArgs)],
                    extra: {
                        severity: injection ? "high" : "medium",
                        category: "sql",
                        detail: injection ? "POSSIBLE SQL INJECTION in rawQuery" : "SQLite rawQuery"
                    }
                });
                return this.rawQuery(sql, selectionArgs);
            };

        // execSQL(String sql)
        SQLiteDatabase.execSQL
            .overload("java.lang.String")
            .implementation = function (sql) {
                var injection = detectSqlInjection(sql);
                send({
                    type: "api_event", class: "SQLiteDatabase", method: "execSQL",
                    args: [trunc(sql, 300)],
                    extra: {
                        severity: injection ? "high" : "medium",
                        category: "sql",
                        detail: injection ? "POSSIBLE SQL INJECTION in execSQL" : "SQLite execSQL"
                    }
                });
                return this.execSQL(sql);
            };

        // execSQL(String sql, Object[] bindArgs)
        try {
            SQLiteDatabase.execSQL
                .overload("java.lang.String", "[Ljava.lang.Object;")
                .implementation = function (sql, bindArgs) {
                    var injection = detectSqlInjection(sql);
                    send({
                        type: "api_event", class: "SQLiteDatabase", method: "execSQL",
                        args: [trunc(sql, 300)],
                        extra: {
                            severity: injection ? "high" : "medium",
                            category: "sql",
                            detail: injection ? "POSSIBLE SQL INJECTION in execSQL (bound)" : "SQLite execSQL (bound)"
                        }
                    });
                    return this.execSQL(sql, bindArgs);
                };
            hookCount++;
        } catch (e) { /* overload may not exist on all API levels */ }

        // query(table, columns, selection, selectionArgs, groupBy, having, orderBy)
        SQLiteDatabase.query
            .overload("java.lang.String", "[Ljava.lang.String;", "java.lang.String",
                      "[Ljava.lang.String;", "java.lang.String", "java.lang.String",
                      "java.lang.String")
            .implementation = function (table, columns, selection, selectionArgs, groupBy, having, orderBy) {
                var injection = detectSqlInjection(selection);
                send({
                    type: "api_event", class: "SQLiteDatabase", method: "query",
                    args: [table, selection, javaStrArrayToJS(selectionArgs)],
                    extra: {
                        severity: injection ? "high" : "low",
                        category: "sql",
                        detail: injection ? "POSSIBLE SQL INJECTION in query selection" : "SQLite query on table: " + table
                    }
                });
                return this.query(table, columns, selection, selectionArgs, groupBy, having, orderBy);
            };

        // compileStatement(String sql)
        SQLiteDatabase.compileStatement
            .overload("java.lang.String")
            .implementation = function (sql) {
                send({
                    type: "api_event", class: "SQLiteDatabase", method: "compileStatement",
                    args: [trunc(sql, 300)],
                    extra: {severity: "low", category: "sql", detail: "SQLite prepared statement compiled"}
                });
                return this.compileStatement(sql);
            };

        hookCount += 4;
        console.log("[+] SQLiteDatabase monitoring installed");
    } catch (e) {
        console.log("[-] SQLiteDatabase monitoring failed: " + e);
    }

    // =========================================================================
    // 4. Cryptographic Operations Monitoring (expanded)
    // =========================================================================

    // --- Cipher ---
    try {
        var Cipher = Java.use("javax.crypto.Cipher");

        Cipher.getInstance
            .overload("java.lang.String")
            .implementation = function (transformation) {
                send({
                    type: "api_event", class: "Cipher", method: "getInstance",
                    args: [transformation],
                    extra: {severity: "medium", category: "crypto", detail: "Cipher algorithm requested"}
                });
                return this.getInstance(transformation);
            };

        // Cipher.init(int opmode, Key key)
        Cipher.init
            .overload("int", "java.security.Key")
            .implementation = function (opmode, key) {
                var modeStr = opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : String(opmode);
                var alg = "<unknown>";
                try { alg = key.getAlgorithm(); } catch (e) { /* ignore */ }
                send({
                    type: "api_event", class: "Cipher", method: "init",
                    args: [modeStr, alg],
                    extra: {severity: "medium", category: "crypto",
                            detail: "Cipher.init mode=" + modeStr + " alg=" + alg}
                });
                return this.init(opmode, key);
            };

        // Cipher.init(int opmode, Key key, AlgorithmParameterSpec params)
        try {
            Cipher.init
                .overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec")
                .implementation = function (opmode, key, params) {
                    var modeStr = opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : String(opmode);
                    var alg = "<unknown>";
                    try { alg = key.getAlgorithm(); } catch (e) { /* ignore */ }
                    send({
                        type: "api_event", class: "Cipher", method: "init",
                        args: [modeStr, alg, params !== null ? params.getClass().getSimpleName() : null],
                        extra: {severity: "medium", category: "crypto",
                                detail: "Cipher.init (with params) mode=" + modeStr + " alg=" + alg}
                    });
                    return this.init(opmode, key, params);
                };
            hookCount++;
        } catch (e) { /* ignore */ }

        Cipher.doFinal
            .overload("[B")
            .implementation = function (input) {
                var algorithm = "<unknown>";
                try { algorithm = this.getAlgorithm(); } catch (e) { /* ignore */ }
                send({
                    type: "api_event", class: "Cipher", method: "doFinal",
                    args: [input ? input.length + " bytes" : null],
                    extra: {severity: "medium", category: "crypto",
                            detail: "Cipher.doFinal alg=" + algorithm}
                });
                return this.doFinal(input);
            };

        hookCount += 4;
        console.log("[+] Cipher monitoring installed");
    } catch (e) {
        console.log("[-] Cipher monitoring failed: " + e);
    }

    // --- SecretKeySpec ---
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

        SecretKeySpec.$init
            .overload("[B", "java.lang.String")
            .implementation = function (keyBytes, algorithm) {
                send({
                    type: "api_event", class: "SecretKeySpec", method: "$init",
                    args: [bytesToHex(keyBytes, 32), algorithm],
                    extra: {severity: "high", category: "crypto",
                            detail: "SecretKeySpec created: alg=" + algorithm + " key(hex)=" + bytesToHex(keyBytes, 32)}
                });
                return this.$init(keyBytes, algorithm);
            };

        // Overload with offset + length
        try {
            SecretKeySpec.$init
                .overload("[B", "int", "int", "java.lang.String")
                .implementation = function (keyBytes, offset, len, algorithm) {
                    send({
                        type: "api_event", class: "SecretKeySpec", method: "$init",
                        args: [len + " bytes @ " + offset, algorithm],
                        extra: {severity: "high", category: "crypto",
                                detail: "SecretKeySpec created (offset): alg=" + algorithm}
                    });
                    return this.$init(keyBytes, offset, len, algorithm);
                };
            hookCount++;
        } catch (e) { /* ignore */ }

        hookCount++;
        console.log("[+] SecretKeySpec monitoring installed");
    } catch (e) {
        console.log("[-] SecretKeySpec monitoring failed: " + e);
    }

    // --- KeyStore ---
    try {
        var KeyStore = Java.use("java.security.KeyStore");

        KeyStore.getKey
            .overload("java.lang.String", "[C")
            .implementation = function (alias, password) {
                var key = this.getKey(alias, password);
                var keyType = key !== null ? key.getClass().getSimpleName() : "null";
                send({
                    type: "api_event", class: "KeyStore", method: "getKey",
                    args: [alias, keyType],
                    extra: {severity: "high", category: "crypto",
                            detail: "KeyStore.getKey alias=" + alias + " type=" + keyType}
                });
                return key;
            };

        hookCount++;
        console.log("[+] KeyStore monitoring installed");
    } catch (e) {
        console.log("[-] KeyStore monitoring failed: " + e);
    }

    // --- KeyGenerator ---
    try {
        var KeyGenerator = Java.use("javax.crypto.KeyGenerator");

        KeyGenerator.generateKey
            .overload()
            .implementation = function () {
                var key = this.generateKey();
                var alg = "<unknown>";
                var hex = "";
                try { alg = this.getAlgorithm(); } catch (e) { /* ignore */ }
                try {
                    var encoded = key.getEncoded();
                    if (encoded !== null) hex = bytesToHex(encoded, 32);
                } catch (e) { /* ignore */ }
                send({
                    type: "api_event", class: "KeyGenerator", method: "generateKey",
                    args: [alg],
                    extra: {severity: "high", category: "crypto",
                            detail: "KeyGenerator.generateKey alg=" + alg + " key(hex)=" + hex}
                });
                return key;
            };

        hookCount++;
        console.log("[+] KeyGenerator monitoring installed");
    } catch (e) {
        console.log("[-] KeyGenerator monitoring failed: " + e);
    }

    // --- Mac ---
    try {
        var Mac = Java.use("javax.crypto.Mac");

        Mac.init
            .overload("java.security.Key")
            .implementation = function (key) {
                var alg = "<unknown>";
                try { alg = this.getAlgorithm(); } catch (e) { /* ignore */ }
                var keyAlg = "<unknown>";
                try { keyAlg = key.getAlgorithm(); } catch (e) { /* ignore */ }
                send({
                    type: "api_event", class: "Mac", method: "init",
                    args: [alg, keyAlg],
                    extra: {severity: "medium", category: "crypto",
                            detail: "Mac.init mac_alg=" + alg + " key_alg=" + keyAlg}
                });
                return this.init(key);
            };

        hookCount++;
        console.log("[+] Mac monitoring installed");
    } catch (e) {
        console.log("[-] Mac monitoring failed: " + e);
    }

    // =========================================================================
    // 5. Log Output Monitoring
    // =========================================================================
    try {
        var Log = Java.use("android.util.Log");
        var LOG_SENSITIVE_PATTERNS = ["password", "passwd", "token", "secret", "api_key",
                                       "auth", "credit", "ssn", "private_key", "bearer"];

        function logIsSensitive(msg) {
            if (!msg) return false;
            var lower = msg.toLowerCase();
            for (var i = 0; i < LOG_SENSITIVE_PATTERNS.length; i++) {
                if (lower.indexOf(LOG_SENSITIVE_PATTERNS[i]) >= 0) return true;
            }
            return false;
        }

        ["d", "i", "w", "e", "v"].forEach(function (level) {
            try {
                Log[level].overload("java.lang.String", "java.lang.String")
                    .implementation = function (tag, msg) {
                        if (logIsSensitive(msg)) {
                            send({
                                type: "api_event", class: "Log", method: level,
                                args: [tag, trunc(msg, 200)],
                                extra: {severity: "high", category: "storage",
                                        detail: "Sensitive data in logcat: tag=" + tag}
                            });
                        }
                        return this[level](tag, msg);
                    };
                hookCount++;
            } catch (e) { /* ignore per-level failures */ }
        });

        console.log("[+] Log monitoring installed");
    } catch (e) {
        console.log("[-] Log monitoring failed: " + e);
    }

    // =========================================================================
    // 6. File Operations Monitoring
    // =========================================================================
    try {
        var FileInputStream  = Java.use("java.io.FileInputStream");
        var FileOutputStream = Java.use("java.io.FileOutputStream");

        FileInputStream.$init
            .overload("java.io.File")
            .implementation = function (file) {
                var path = file.getAbsolutePath();
                if (path.indexOf("shared_prefs") >= 0 || path.indexOf("databases") >= 0 ||
                    path.indexOf("sdcard") >= 0 || path.indexOf("/data/data") >= 0) {
                    send({
                        type: "api_event", class: "FileInputStream", method: "$init",
                        args: [path],
                        extra: {severity: "medium", category: "storage", detail: "Sensitive file read"}
                    });
                }
                return this.$init(file);
            };

        FileOutputStream.$init
            .overload("java.io.File")
            .implementation = function (file) {
                var path = file.getAbsolutePath();
                send({
                    type: "api_event", class: "FileOutputStream", method: "$init",
                    args: [path],
                    extra: {severity: "low", category: "storage", detail: "File write opened"}
                });
                return this.$init(file);
            };

        hookCount += 2;
        console.log("[+] File operation monitoring installed");
    } catch (e) {
        console.log("[-] File operation monitoring failed: " + e);
    }

    // =========================================================================
    // 7. Network Monitoring — HttpURLConnection
    // =========================================================================
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");

        HttpURLConnection.connect.overload().implementation = function () {
            var urlStr = "<unknown>";
            try { urlStr = this.getURL().toString(); } catch (e) { /* ignore */ }
            send({
                type: "api_event", class: "HttpURLConnection", method: "connect",
                args: [urlStr],
                extra: {severity: "medium", category: "network", detail: "HTTP connect: " + urlStr}
            });
            return this.connect();
        };

        HttpURLConnection.setRequestProperty
            .overload("java.lang.String", "java.lang.String")
            .implementation = function (key, value) {
                if (isSensitiveKey(key)) {
                    send({
                        type: "api_event", class: "HttpURLConnection", method: "setRequestProperty",
                        args: [key, "[REDACTED]"],
                        extra: {severity: "high", category: "network",
                                detail: "Sensitive request header set: " + key}
                    });
                }
                return this.setRequestProperty(key, value);
            };

        hookCount += 2;
        console.log("[+] HttpURLConnection monitoring installed");
    } catch (e) {
        console.log("[-] HttpURLConnection monitoring failed: " + e);
    }

    // --- java.net.URL constructor (fallback for all URL usage) ---
    try {
        var JavaURL = Java.use("java.net.URL");

        JavaURL.$init
            .overload("java.lang.String")
            .implementation = function (spec) {
                send({
                    type: "api_event", class: "URL", method: "$init",
                    args: [trunc(spec, 300)],
                    extra: {severity: "low", category: "network", detail: "URL constructed: " + trunc(spec, 100)}
                });
                return this.$init(spec);
            };

        hookCount++;
        console.log("[+] java.net.URL monitoring installed");
    } catch (e) {
        console.log("[-] java.net.URL monitoring failed: " + e);
    }

    // --- OkHttp3 ---
    try {
        var OkHttpRealCall = Java.use("okhttp3.internal.connection.RealCall");

        OkHttpRealCall.execute.overload().implementation = function () {
            var method = "<unknown>";
            var url    = "<unknown>";
            try {
                var req = this.request();
                method  = req.method();
                url     = req.url().toString();
            } catch (e) { /* ignore */ }
            send({
                type: "api_event", class: "OkHttp3.RealCall", method: "execute",
                args: [method, url],
                extra: {severity: "medium", category: "network",
                        detail: "OkHttp3 execute: " + method + " " + trunc(url, 150)}
            });
            return this.execute();
        };

        hookCount++;
        console.log("[+] OkHttp3 RealCall monitoring installed");
    } catch (e) {
        // Try older okhttp3 class location
        try {
            var OkHttpCallFallback = Java.use("okhttp3.RealCall");
            OkHttpCallFallback.execute.overload().implementation = function () {
                var method = "<unknown>"; var url = "<unknown>";
                try { var req = this.request(); method = req.method(); url = req.url().toString(); } catch (e2) { /* ignore */ }
                send({
                    type: "api_event", class: "OkHttp3.RealCall", method: "execute",
                    args: [method, url],
                    extra: {severity: "medium", category: "network",
                            detail: "OkHttp3 execute (fallback): " + method + " " + trunc(url, 150)}
                });
                return this.execute();
            };
            hookCount++;
            console.log("[+] OkHttp3 RealCall (fallback path) monitoring installed");
        } catch (e2) {
            console.log("[-] OkHttp3 monitoring failed: " + e2);
        }
    }

    // OkHttp3 Request.Builder.url(String)
    try {
        var OkHttpRequestBuilder = Java.use("okhttp3.Request$Builder");

        OkHttpRequestBuilder.url
            .overload("java.lang.String")
            .implementation = function (url) {
                send({
                    type: "api_event", class: "OkHttp3.Request.Builder", method: "url",
                    args: [trunc(url, 300)],
                    extra: {severity: "low", category: "network",
                            detail: "OkHttp3 request URL set: " + trunc(url, 150)}
                });
                return this.url(url);
            };

        hookCount++;
        console.log("[+] OkHttp3 Request.Builder monitoring installed");
    } catch (e) {
        console.log("[-] OkHttp3 Request.Builder monitoring failed: " + e);
    }

    // =========================================================================
    // 8. WebView Monitoring
    // =========================================================================
    try {
        var WebView = Java.use("android.webkit.WebView");

        WebView.loadUrl
            .overload("java.lang.String")
            .implementation = function (url) {
                send({
                    type: "api_event", class: "WebView", method: "loadUrl",
                    args: [url],
                    extra: {severity: "medium", category: "network", detail: "WebView loadUrl"}
                });
                return this.loadUrl(url);
            };

        WebView.loadUrl
            .overload("java.lang.String", "java.util.Map")
            .implementation = function (url, headers) {
                send({
                    type: "api_event", class: "WebView", method: "loadUrl",
                    args: [url],
                    extra: {severity: "medium", category: "network",
                            detail: "WebView loadUrl (with headers)"}
                });
                return this.loadUrl(url, headers);
            };

        WebView.loadData
            .overload("java.lang.String", "java.lang.String", "java.lang.String")
            .implementation = function (data, mimeType, encoding) {
                send({
                    type: "api_event", class: "WebView", method: "loadData",
                    args: [trunc(data, 100), mimeType, encoding],
                    extra: {severity: "low", category: "network", detail: "WebView loadData"}
                });
                return this.loadData(data, mimeType, encoding);
            };

        WebView.addJavascriptInterface
            .overload("java.lang.Object", "java.lang.String")
            .implementation = function (obj, name) {
                send({
                    type: "api_event", class: "WebView", method: "addJavascriptInterface",
                    args: [obj.getClass().getName(), name],
                    extra: {severity: "critical", category: "network",
                            detail: "addJavascriptInterface: name=" + name + " class=" + obj.getClass().getName()}
                });
                return this.addJavascriptInterface(obj, name);
            };

        WebView.evaluateJavascript
            .overload("java.lang.String", "android.webkit.ValueCallback")
            .implementation = function (script, callback) {
                send({
                    type: "api_event", class: "WebView", method: "evaluateJavascript",
                    args: [trunc(script, 200)],
                    extra: {severity: "high", category: "network",
                            detail: "WebView JavaScript evaluated"}
                });
                return this.evaluateJavascript(script, callback);
            };

        hookCount += 5;
        console.log("[+] WebView monitoring installed");
    } catch (e) {
        console.log("[-] WebView monitoring failed: " + e);
    }

    // =========================================================================
    // 9. Intent Monitoring (dispatch)
    // =========================================================================
    try {
        var Activity = Java.use("android.app.Activity");

        Activity.startActivity
            .overload("android.content.Intent")
            .implementation = function (intent) {
                var action    = null; var data   = null; var component = null;
                try { action    = intent.getAction(); }                              catch (e) { /* ignore */ }
                try { data      = intent.getDataString(); }                          catch (e) { /* ignore */ }
                try { component = intent.getComponent() ?
                          intent.getComponent().flattenToString() : null; }          catch (e) { /* ignore */ }
                send({
                    type: "api_event", class: "Activity", method: "startActivity",
                    args: [action, data, component],
                    extra: {severity: "medium", category: "intent", detail: "Activity startActivity"}
                });
                return this.startActivity(intent);
            };

        Activity.startActivityForResult
            .overload("android.content.Intent", "int")
            .implementation = function (intent, requestCode) {
                var action = null; var data = null;
                try { action = intent.getAction(); }   catch (e) { /* ignore */ }
                try { data   = intent.getDataString(); } catch (e) { /* ignore */ }
                send({
                    type: "api_event", class: "Activity", method: "startActivityForResult",
                    args: [action, data, requestCode],
                    extra: {severity: "medium", category: "intent",
                            detail: "startActivityForResult requestCode=" + requestCode}
                });
                return this.startActivityForResult(intent, requestCode);
            };

        hookCount += 2;
        console.log("[+] Activity Intent monitoring installed");
    } catch (e) {
        console.log("[-] Activity Intent monitoring failed: " + e);
    }

    // =========================================================================
    // 10. Bundle / Intent Extras — Comprehensive Monitoring (NEW)
    // =========================================================================
    try {
        var Bundle = Java.use("android.os.Bundle");

        var BUNDLE_STRING_METHODS = ["getString", "getCharSequence"];
        var BUNDLE_SCALAR_METHODS = ["getInt", "getLong", "getFloat", "getDouble", "getBoolean"];

        BUNDLE_STRING_METHODS.forEach(function (method) {
            try {
                Bundle[method]
                    .overload("java.lang.String")
                    .implementation = function (key) {
                        var value = this[method](key);
                        if (isSensitiveKey(key)) {
                            send({
                                type: "api_event", class: "Bundle", method: method,
                                args: [key, value !== null ? trunc(String(value), 100) : null],
                                extra: {severity: "medium", category: "intent",
                                        detail: "Bundle." + method + " sensitive key=" + key}
                            });
                        }
                        return value;
                    };
                hookCount++;
            } catch (e) { /* overload may differ */ }
        });

        BUNDLE_SCALAR_METHODS.forEach(function (method) {
            try {
                // Most have a (String key, T defaultValue) overload
                Bundle[method].overloads.forEach(function (overload) {
                    var orig = overload.implementation;
                    overload.implementation = function () {
                        var key = arguments[0];
                        var result = overload.apply(this, arguments);
                        if (isSensitiveKey(key)) {
                            send({
                                type: "api_event", class: "Bundle", method: method,
                                args: [key, result],
                                extra: {severity: "low", category: "intent",
                                        detail: "Bundle." + method + " sensitive key=" + key}
                            });
                        }
                        return result;
                    };
                    hookCount++;
                });
            } catch (e) { /* ignore per-method */ }
        });

        // getByteArray
        try {
            Bundle.getByteArray
                .overload("java.lang.String")
                .implementation = function (key) {
                    var value = this.getByteArray(key);
                    if (isSensitiveKey(key) && value !== null) {
                        send({
                            type: "api_event", class: "Bundle", method: "getByteArray",
                            args: [key, value.length + " bytes"],
                            extra: {severity: "high", category: "intent",
                                    detail: "Bundle.getByteArray sensitive key=" + key}
                        });
                    }
                    return value;
                };
            hookCount++;
        } catch (e) { /* ignore */ }

        // getSerializable
        try {
            Bundle.getSerializable
                .overload("java.lang.String")
                .implementation = function (key) {
                    var value = this.getSerializable(key);
                    send({
                        type: "api_event", class: "Bundle", method: "getSerializable",
                        args: [key, value !== null ? value.getClass().getName() : null],
                        extra: {severity: "medium", category: "intent",
                                detail: "Bundle.getSerializable key=" + key}
                    });
                    return value;
                };
            hookCount++;
        } catch (e) { /* ignore */ }

        // getParcelable
        try {
            Bundle.getParcelable
                .overload("java.lang.String")
                .implementation = function (key) {
                    var value = this.getParcelable(key);
                    send({
                        type: "api_event", class: "Bundle", method: "getParcelable",
                        args: [key, value !== null ? value.getClass().getName() : null],
                        extra: {severity: "low", category: "intent",
                                detail: "Bundle.getParcelable key=" + key}
                    });
                    return value;
                };
            hookCount++;
        } catch (e) { /* ignore */ }

        console.log("[+] Bundle monitoring installed");
    } catch (e) {
        console.log("[-] Bundle monitoring failed: " + e);
    }

    // Intent extras
    try {
        var Intent = Java.use("android.content.Intent");

        Intent.getStringExtra
            .overload("java.lang.String")
            .implementation = function (name) {
                var value = this.getStringExtra(name);
                send({
                    type: "api_event", class: "Intent", method: "getStringExtra",
                    args: [name, isSensitiveKey(name) ? "[REDACTED]" : trunc(value, 100)],
                    extra: {
                        severity: isSensitiveKey(name) ? "high" : "low",
                        category: "intent",
                        detail: "Intent.getStringExtra key=" + name
                    }
                });
                return value;
            };

        Intent.getIntExtra
            .overload("java.lang.String", "int")
            .implementation = function (name, defaultValue) {
                var value = this.getIntExtra(name, defaultValue);
                if (isSensitiveKey(name)) {
                    send({
                        type: "api_event", class: "Intent", method: "getIntExtra",
                        args: [name, value],
                        extra: {severity: "medium", category: "intent",
                                detail: "Intent.getIntExtra sensitive key=" + name}
                    });
                }
                return value;
            };

        Intent.getData.overload().implementation = function () {
            var uri = this.getData();
            if (uri !== null) {
                send({
                    type: "api_event", class: "Intent", method: "getData",
                    args: [uri.toString()],
                    extra: {severity: "medium", category: "intent",
                            detail: "Intent.getData: " + uri.toString()}
                });
            }
            return uri;
        };

        Intent.getDataString.overload().implementation = function () {
            var str = this.getDataString();
            if (str !== null) {
                send({
                    type: "api_event", class: "Intent", method: "getDataString",
                    args: [str],
                    extra: {severity: "medium", category: "intent",
                            detail: "Intent.getDataString: " + trunc(str, 100)}
                });
            }
            return str;
        };

        hookCount += 4;
        console.log("[+] Intent extras monitoring installed");
    } catch (e) {
        console.log("[-] Intent extras monitoring failed: " + e);
    }

    // =========================================================================
    // 11. DexClassLoader / PathClassLoader — Dynamic Code Loading (NEW)
    // =========================================================================
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");

        DexClassLoader.$init
            .overload("java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader")
            .implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
                send({
                    type: "dynamic_load", class: "DexClassLoader", method: "$init",
                    args: [dexPath, optimizedDirectory],
                    extra: {severity: "high", category: "dynamic_load",
                            detail: "DexClassLoader loading: " + dexPath}
                });
                return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
            };

        hookCount++;
        console.log("[+] DexClassLoader monitoring installed");
    } catch (e) {
        console.log("[-] DexClassLoader monitoring failed: " + e);
    }

    try {
        var PathClassLoader = Java.use("dalvik.system.PathClassLoader");

        PathClassLoader.$init
            .overload("java.lang.String", "java.lang.ClassLoader")
            .implementation = function (dexPath, parent) {
                send({
                    type: "dynamic_load", class: "PathClassLoader", method: "$init",
                    args: [dexPath],
                    extra: {severity: "medium", category: "dynamic_load",
                            detail: "PathClassLoader loading: " + dexPath}
                });
                return this.$init(dexPath, parent);
            };

        // Also hook the 3-arg variant (dexPath, librarySearchPath, parent)
        try {
            PathClassLoader.$init
                .overload("java.lang.String", "java.lang.String", "java.lang.ClassLoader")
                .implementation = function (dexPath, librarySearchPath, parent) {
                    send({
                        type: "dynamic_load", class: "PathClassLoader", method: "$init",
                        args: [dexPath, librarySearchPath],
                        extra: {severity: "medium", category: "dynamic_load",
                                detail: "PathClassLoader (libPath) loading: " + dexPath}
                    });
                    return this.$init(dexPath, librarySearchPath, parent);
                };
            hookCount++;
        } catch (e) { /* ignore */ }

        hookCount++;
        console.log("[+] PathClassLoader monitoring installed");
    } catch (e) {
        console.log("[-] PathClassLoader monitoring failed: " + e);
    }

    // =========================================================================
    // 12. Clipboard Monitoring (NEW)
    // =========================================================================
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");

        ClipboardManager.getPrimaryClip.overload().implementation = function () {
            var clip = this.getPrimaryClip();
            if (clip !== null) {
                var text = "<non-text>";
                try {
                    var item = clip.getItemAt(0);
                    if (item !== null && item.getText() !== null) {
                        text = trunc(item.getText().toString(), 200);
                    }
                } catch (e) { /* ignore */ }
                send({
                    type: "api_event", class: "ClipboardManager", method: "getPrimaryClip",
                    args: [text],
                    extra: {severity: "medium", category: "storage",
                            detail: "Clipboard read: " + trunc(text, 50)}
                });
            }
            return clip;
        };

        ClipboardManager.setPrimaryClip
            .overload("android.content.ClipData")
            .implementation = function (clip) {
                var text = "<non-text>";
                try {
                    var item = clip.getItemAt(0);
                    if (item !== null && item.getText() !== null) {
                        text = trunc(item.getText().toString(), 200);
                    }
                } catch (e) { /* ignore */ }
                send({
                    type: "api_event", class: "ClipboardManager", method: "setPrimaryClip",
                    args: [text],
                    extra: {severity: "medium", category: "storage",
                            detail: "Clipboard write: " + trunc(text, 50)}
                });
                return this.setPrimaryClip(clip);
            };

        hookCount += 2;
        console.log("[+] ClipboardManager monitoring installed");
    } catch (e) {
        console.log("[-] ClipboardManager monitoring failed: " + e);
    }

    // =========================================================================
    // 13. AccountManager — getAuthToken (NEW)
    // =========================================================================
    try {
        var AccountManager = Java.use("android.accounts.AccountManager");

        // getAuthToken(Account, String authTokenType, Bundle options,
        //              Activity activity, AccountManagerCallback cb, Handler handler)
        AccountManager.getAuthToken
            .overload("android.accounts.Account", "java.lang.String",
                      "android.os.Bundle", "android.app.Activity",
                      "android.accounts.AccountManagerCallback", "android.os.Handler")
            .implementation = function (account, authTokenType, options, activity, callback, handler) {
                var accountName = "<unknown>";
                try { accountName = account.name; } catch (e) { /* ignore */ }
                send({
                    type: "api_event", class: "AccountManager", method: "getAuthToken",
                    args: [accountName, authTokenType],
                    extra: {severity: "high", category: "auth",
                            detail: "AccountManager.getAuthToken account=" + accountName +
                                    " tokenType=" + authTokenType}
                });
                return this.getAuthToken(account, authTokenType, options, activity, callback, handler);
            };

        // Also hook boolean-variant (notifyAuthFailure instead of Activity)
        try {
            AccountManager.getAuthToken
                .overload("android.accounts.Account", "java.lang.String",
                          "android.os.Bundle", "boolean",
                          "android.accounts.AccountManagerCallback", "android.os.Handler")
                .implementation = function (account, authTokenType, options, notifyAuthFailure, callback, handler) {
                    var accountName = "<unknown>";
                    try { accountName = account.name; } catch (e) { /* ignore */ }
                    send({
                        type: "api_event", class: "AccountManager", method: "getAuthToken",
                        args: [accountName, authTokenType],
                        extra: {severity: "high", category: "auth",
                                detail: "AccountManager.getAuthToken (background) account=" + accountName}
                    });
                    return this.getAuthToken(account, authTokenType, options, notifyAuthFailure, callback, handler);
                };
            hookCount++;
        } catch (e) { /* ignore variant */ }

        hookCount++;
        console.log("[+] AccountManager monitoring installed");
    } catch (e) {
        console.log("[-] AccountManager monitoring failed: " + e);
    }

    // =========================================================================
    // 14. BiometricPrompt — Authentication Bypass (NEW)
    // =========================================================================

    // Framework BiometricPrompt (API 28+)
    try {
        var BiometricCallback = Java.use(
            "android.hardware.biometrics.BiometricPrompt$AuthenticationCallback");

        BiometricCallback.onAuthenticationSucceeded
            .overload("android.hardware.biometrics.BiometricPrompt$AuthenticationResult")
            .implementation = function (result) {
                send({
                    type: "api_event",
                    class: "BiometricPrompt.AuthenticationCallback",
                    method: "onAuthenticationSucceeded",
                    args: [],
                    extra: {severity: "high", category: "auth",
                            detail: "Framework BiometricPrompt authentication succeeded"}
                });
                return this.onAuthenticationSucceeded(result);
            };

        hookCount++;
        console.log("[+] Framework BiometricPrompt monitoring installed");
    } catch (e) {
        console.log("[-] Framework BiometricPrompt not available: " + e);
    }

    // AndroidX BiometricPrompt
    try {
        var AndroidXBiometricCallback = Java.use(
            "androidx.biometric.BiometricPrompt$AuthenticationCallback");

        AndroidXBiometricCallback.onAuthenticationSucceeded
            .overload("androidx.biometric.BiometricPrompt$AuthenticationResult")
            .implementation = function (result) {
                send({
                    type: "api_event",
                    class: "androidx.BiometricPrompt.AuthenticationCallback",
                    method: "onAuthenticationSucceeded",
                    args: [],
                    extra: {severity: "high", category: "auth",
                            detail: "AndroidX BiometricPrompt authentication succeeded"}
                });
                return this.onAuthenticationSucceeded(result);
            };

        hookCount++;
        console.log("[+] AndroidX BiometricPrompt monitoring installed");
    } catch (e) {
        console.log("[-] AndroidX BiometricPrompt not available: " + e);
    }

    // =========================================================================
    // 15. MemoryFile / Binder IPC (NEW)
    // =========================================================================
    try {
        var MemoryFile = Java.use("android.os.MemoryFile");

        MemoryFile.$init
            .overload("java.lang.String", "int")
            .implementation = function (name, length) {
                send({
                    type: "api_event", class: "MemoryFile", method: "$init",
                    args: [name, length],
                    extra: {severity: "medium", category: "ipc",
                            detail: "MemoryFile created: name=" + name + " size=" + length}
                });
                return this.$init(name, length);
            };

        hookCount++;
        console.log("[+] MemoryFile monitoring installed");
    } catch (e) {
        console.log("[-] MemoryFile monitoring failed: " + e);
    }

    try {
        var Binder = Java.use("android.os.Binder");

        // High-value transaction codes often cluster in the 1–20 range or
        // match well-known IBinder codes (e.g., INTERFACE_TRANSACTION = 1)
        var HIGH_VALUE_CODES = {1: true, 2: true, 3: true, 4: true, 5: true,
                                 6: true, 7: true, 8: true, 9: true, 10: true,
                                 16: true, 32: true, 1598968902: true /* 'dump' */};

        Binder.transact
            .overload("int", "android.os.Parcel", "android.os.Parcel", "int")
            .implementation = function (code, data, reply, flags) {
                var descriptor = "<unknown>";
                try { descriptor = this.getInterfaceDescriptor(); } catch (e) { /* ignore */ }
                if (HIGH_VALUE_CODES[code]) {
                    send({
                        type: "api_event", class: "Binder", method: "transact",
                        args: [descriptor, code, flags],
                        extra: {severity: "low", category: "ipc",
                                detail: "Binder.transact descriptor=" + descriptor + " code=" + code}
                    });
                }
                return this.transact(code, data, reply, flags);
            };

        hookCount++;
        console.log("[+] Binder.transact monitoring installed");
    } catch (e) {
        console.log("[-] Binder monitoring failed: " + e);
    }

    // =========================================================================
    // Finalise — report total hook count
    // =========================================================================
    send({type: "hooks_loaded", count: hookCount});
    console.log("[*] API Monitor complete — " + hookCount + " hooks installed");
});
