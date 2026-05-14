/**
 * SSL/TLS Certificate Pinning Bypass Script
 *
 * Bypasses common SSL pinning implementations:
 * - TrustManager
 * - OkHttp CertificatePinner
 * - Apache HttpClient
 * - Conscrypt
 * - Network Security Config
 */

Java.perform(function() {
    console.log("[*] SSL Pinning Bypass loaded");

    // ===== TrustManager Bypass =====
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        // Create a custom TrustManager that trusts all certificates
        var TrustManagerImpl = Java.registerClass({
            name: "com.bypass.TrustManagerImpl",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {
                    // Trust all client certificates
                },
                checkServerTrusted: function(chain, authType) {
                    // Trust all server certificates
                    send({
                        class: "X509TrustManager",
                        method: "checkServerTrusted",
                        extra: {bypassed: true, authType: authType}
                    });
                },
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });

        console.log("[+] TrustManager bypass installed");
    } catch(e) {
        console.log("[-] TrustManager bypass failed: " + e);
    }

    // ===== OkHttp3 CertificatePinner Bypass =====
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");

        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            send({
                class: "okhttp3.CertificatePinner",
                method: "check",
                args: [hostname],
                extra: {bypassed: true}
            });
            // Don't throw exception, just return
        };

        CertificatePinner.check$okhttp.overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function(hostname, peerCertificates) {
            send({
                class: "okhttp3.CertificatePinner",
                method: "check$okhttp",
                args: [hostname],
                extra: {bypassed: true}
            });
        };

        console.log("[+] OkHttp3 CertificatePinner bypass installed");
    } catch(e) {
        console.log("[-] OkHttp3 bypass failed: " + e);
    }

    // ===== OkHttp3 internal bypass =====
    try {
        var CertificatePinnerBuilder = Java.use("okhttp3.CertificatePinner$Builder");
        CertificatePinnerBuilder.add.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(hostname, pins) {
            // Return builder without adding pins
            return this;
        };
        console.log("[+] OkHttp3 Builder bypass installed");
    } catch(e) {}

    // ===== Apache HttpClient Bypass =====
    try {
        var AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
        AbstractVerifier.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean").implementation = function(host, cns, subjectAlts, strictWithSubDomains) {
            send({
                class: "AbstractVerifier",
                method: "verify",
                args: [host],
                extra: {bypassed: true}
            });
        };
        console.log("[+] Apache HttpClient bypass installed");
    } catch(e) {}

    // ===== Conscrypt Bypass =====
    try {
        var OpenSSLSocketImpl = Java.use("com.android.org.conscrypt.OpenSSLSocketImpl");
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, authMethod) {
            send({
                class: "OpenSSLSocketImpl",
                method: "verifyCertificateChain",
                extra: {bypassed: true}
            });
        };
        console.log("[+] Conscrypt bypass installed");
    } catch(e) {}

    // ===== Android TrustManagerImpl Bypass =====
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            send({
                class: "TrustManagerImpl",
                method: "verifyChain",
                args: [host],
                extra: {bypassed: true}
            });
            return untrustedChain;
        };
        console.log("[+] Android TrustManagerImpl bypass installed");
    } catch(e) {}

    // ===== Network Security Config Bypass (Android 7+) =====
    try {
        var NetworkSecurityConfig = Java.use("android.security.net.config.NetworkSecurityConfig");
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
            return true;
        };
        console.log("[+] NetworkSecurityConfig cleartext bypass installed");
    } catch(e) {}

    // ===== WebView SSL Error Handler Bypass =====
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            send({
                class: "WebViewClient",
                method: "onReceivedSslError",
                extra: {bypassed: true, error: error.toString()}
            });
            handler.proceed();
        };
        console.log("[+] WebView SSL error bypass installed");
    } catch(e) {}

    // ===== HostnameVerifier Bypass =====
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var SSLSession = Java.use("javax.net.ssl.SSLSession");

        var HostnameVerifierImpl = Java.registerClass({
            name: "com.bypass.HostnameVerifierImpl",
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    return true;
                }
            }
        });
        console.log("[+] HostnameVerifier bypass installed");
    } catch(e) {}

    send({
        class: "SSLBypass",
        method: "init",
        extra: {status: "active", message: "SSL pinning bypass activated"}
    });

    console.log("[*] SSL Pinning Bypass complete");
});
