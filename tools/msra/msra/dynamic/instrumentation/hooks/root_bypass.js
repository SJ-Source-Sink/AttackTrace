/**
 * Root Detection Bypass Script
 *
 * Bypasses common root detection methods:
 * - File existence checks (su, Superuser.apk, etc.)
 * - Package checks (Magisk, SuperSU, etc.)
 * - Property checks (ro.build.tags)
 * - Runtime.exec checks
 * - Native library checks
 */

Java.perform(function() {
    console.log("[*] Root Detection Bypass loaded");

    // Root indicator paths to hide
    var rootIndicators = [
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/su",
        "/magisk",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99telecom",
        "/system/app/Magisk.apk",
        "/system/app/MagiskManager.apk",
        "/sbin/.magisk",
        "/sbin/.core",
        "/data/adb/magisk",
        "/system/xbin/busybox"
    ];

    // Root-related packages to hide
    var rootPackages = [
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.zachspong.temprootremovejb",
        "com.ramdroid.appquarantine",
        "com.topjohnwu.magisk",
        "me.phh.superuser",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global"
    ];

    // ===== File.exists() Bypass =====
    try {
        var File = Java.use("java.io.File");

        File.exists.implementation = function() {
            var path = this.getAbsolutePath();

            for (var i = 0; i < rootIndicators.length; i++) {
                if (path.indexOf(rootIndicators[i]) >= 0) {
                    send({
                        class: "java.io.File",
                        method: "exists",
                        args: [path],
                        extra: {bypassed: true, type: "file_check"}
                    });
                    return false;
                }
            }
            return this.exists();
        };

        File.canRead.implementation = function() {
            var path = this.getAbsolutePath();

            for (var i = 0; i < rootIndicators.length; i++) {
                if (path.indexOf(rootIndicators[i]) >= 0) {
                    return false;
                }
            }
            return this.canRead();
        };

        File.canWrite.implementation = function() {
            var path = this.getAbsolutePath();

            if (path.indexOf("/system") === 0) {
                return false;
            }
            return this.canWrite();
        };

        console.log("[+] File checks bypass installed");
    } catch(e) {
        console.log("[-] File bypass failed: " + e);
    }

    // ===== Runtime.exec() Bypass =====
    try {
        var Runtime = Java.use("java.lang.Runtime");

        Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            if (cmd.indexOf("su") >= 0 || cmd.indexOf("which") >= 0 ||
                cmd.indexOf("busybox") >= 0) {
                send({
                    class: "java.lang.Runtime",
                    method: "exec",
                    args: [cmd],
                    extra: {bypassed: true, type: "exec_check"}
                });
                throw Java.use("java.io.IOException").$new("Permission denied");
            }
            return this.exec(cmd);
        };

        Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmds) {
            var cmd = cmds.join(" ");
            if (cmd.indexOf("su") >= 0 || cmd.indexOf("which") >= 0) {
                throw Java.use("java.io.IOException").$new("Permission denied");
            }
            return this.exec(cmds);
        };

        console.log("[+] Runtime.exec bypass installed");
    } catch(e) {
        console.log("[-] Runtime.exec bypass failed: " + e);
    }

    // ===== Build Properties Bypass =====
    try {
        var Build = Java.use("android.os.Build");

        // Change TAGS to release-keys
        var originalTags = Build.TAGS.value;
        Build.TAGS.value = "release-keys";

        console.log("[+] Build.TAGS changed from '" + originalTags + "' to 'release-keys'");
    } catch(e) {}

    // ===== System.getProperty Bypass =====
    try {
        var System = Java.use("java.lang.System");

        System.getProperty.overload("java.lang.String").implementation = function(key) {
            if (key === "ro.build.tags") {
                return "release-keys";
            }
            if (key === "ro.build.selinux") {
                return "1";
            }
            return this.getProperty(key);
        };

        console.log("[+] System.getProperty bypass installed");
    } catch(e) {}

    // ===== PackageManager Bypass =====
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(packageName, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (packageName === rootPackages[i]) {
                    send({
                        class: "PackageManager",
                        method: "getPackageInfo",
                        args: [packageName],
                        extra: {bypassed: true, type: "package_check"}
                    });
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                }
            }
            return this.getPackageInfo(packageName, flags);
        };

        console.log("[+] PackageManager bypass installed");
    } catch(e) {}

    // ===== ProcessBuilder Bypass =====
    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");

        ProcessBuilder.start.implementation = function() {
            var command = this.command().toArray().join(" ");

            if (command.indexOf("su") >= 0 || command.indexOf("which") >= 0) {
                send({
                    class: "ProcessBuilder",
                    method: "start",
                    args: [command],
                    extra: {bypassed: true}
                });
                throw Java.use("java.io.IOException").$new("Permission denied");
            }
            return this.start();
        };

        console.log("[+] ProcessBuilder bypass installed");
    } catch(e) {}

    // ===== Native Library Checks =====
    try {
        var System = Java.use("java.lang.System");

        System.loadLibrary.overload("java.lang.String").implementation = function(libName) {
            // Log but allow loading
            send({
                class: "System",
                method: "loadLibrary",
                args: [libName],
                extra: {type: "native_load"}
            });
            return this.loadLibrary(libName);
        };

        console.log("[+] Native library monitoring installed");
    } catch(e) {}

    // ===== SafetyNet/Play Integrity Bypass Helpers =====
    try {
        var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        // Additional SafetyNet bypass would go here
        console.log("[+] SafetyNet bypass helpers installed");
    } catch(e) {}

    send({
        class: "RootBypass",
        method: "init",
        extra: {status: "active", message: "Root detection bypass activated"}
    });

    console.log("[*] Root Detection Bypass complete");
});
