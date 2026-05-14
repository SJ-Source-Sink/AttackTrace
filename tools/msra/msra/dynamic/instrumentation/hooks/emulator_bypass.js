/**
 * Emulator Detection Bypass Script
 *
 * Spoofs:
 *  - SystemProperties (ro.product.*, ro.hardware, ro.build.fingerprint, ro.kernel.version)
 *  - TelephonyManager (device ID, network operator, SIM info, line number)
 *  - android.os.Build static fields
 *  - Sensor availability (accelerometer / gyroscope)
 *  - Runtime.exec() commands that reveal emulator environment
 *  - File existence checks for QEMU / emulator artefacts
 *  - PackageManager.hasSystemFeature() for emulator-only features
 *
 * Realistic device profile: Google Pixel 7 (panther)
 */

Java.perform(function () {

    // -------------------------------------------------------------------------
    // Shared device profile — change here to repurpose the whole script
    // -------------------------------------------------------------------------
    var DEVICE = {
        model:        "Pixel 7",
        manufacturer: "Google",
        brand:        "google",
        device:       "panther",
        product:      "panther",
        hardware:     "gs101",
        fingerprint:  "google/panther/panther:13/TQ3A.230901.001/10750268:user/release-keys",
        kernelVersion: "5.10.149-android13-4-00010-g89f2f5a0d5f9",
        imei:         "356938035643809",
        networkOp:    "310260",
        networkOpName: "T-Mobile",
        simOp:        "310260",
        simCountry:   "us",
        lineNumber:   "+12025550179"
    };

    // -------------------------------------------------------------------------
    // Helper: bytes → hex string
    // -------------------------------------------------------------------------
    function bytesToHex(bytes) {
        var hex = "";
        try {
            for (var i = 0; i < bytes.length; i++) {
                var b = bytes[i] & 0xff;
                hex += (b < 16 ? "0" : "") + b.toString(16);
            }
        } catch (e) { /* ignore */ }
        return hex;
    }

    var hookCount = 0;

    // =========================================================================
    // 1. SystemProperties.get()
    // =========================================================================
    var PROP_MAP = {
        "ro.product.model":        DEVICE.model,
        "ro.product.manufacturer": DEVICE.manufacturer,
        "ro.product.device":       DEVICE.device,
        "ro.hardware":             DEVICE.hardware,
        "ro.product.name":         DEVICE.product,
        "ro.build.fingerprint":    DEVICE.fingerprint,
        "ro.kernel.version":       DEVICE.kernelVersion,
        "ro.product.brand":        DEVICE.brand,
        // Extra properties checked by common detection libraries
        "ro.kernel.qemu":          "0",
        "ro.kernel.qemu.gles":     "0",
        "ro.product.cpu.abi":      "arm64-v8a",
        "ro.build.tags":           "release-keys",
        "ro.build.type":           "user",
        "ro.build.version.sdk":    "33",
        "ro.debuggable":           "0"
    };

    try {
        var SystemProperties = Java.use("android.os.SystemProperties");

        SystemProperties.get.overload("java.lang.String").implementation = function (key) {
            if (PROP_MAP.hasOwnProperty(key)) {
                send({
                    type: "api_event", class: "SystemProperties", method: "get",
                    args: [key], extra: {
                        severity: "low", category: "emulator_bypass",
                        detail: "Spoofed prop " + key + " -> " + PROP_MAP[key]
                    }
                });
                return PROP_MAP[key];
            }
            return this.get(key);
        };

        SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function (key, def) {
            if (PROP_MAP.hasOwnProperty(key)) {
                send({
                    type: "api_event", class: "SystemProperties", method: "get",
                    args: [key, def], extra: {
                        severity: "low", category: "emulator_bypass",
                        detail: "Spoofed prop (w/default) " + key + " -> " + PROP_MAP[key]
                    }
                });
                return PROP_MAP[key];
            }
            return this.get(key, def);
        };

        hookCount += 2;
        console.log("[+] SystemProperties bypass installed");
    } catch (e) {
        console.log("[-] SystemProperties bypass failed: " + e);
    }

    // =========================================================================
    // 2. TelephonyManager
    // =========================================================================
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getDeviceId.overload().implementation = function () {
            send({
                type: "api_event", class: "TelephonyManager", method: "getDeviceId",
                args: [], extra: {severity: "low", category: "emulator_bypass", detail: "Spoofed IMEI"}
            });
            return DEVICE.imei;
        };

        // API 26+: getImei()
        try {
            TelephonyManager.getImei.overload().implementation = function () {
                return DEVICE.imei;
            };
            TelephonyManager.getImei.overload("int").implementation = function (slotIndex) {
                return DEVICE.imei;
            };
            hookCount += 2;
        } catch (e) { /* older API */ }

        TelephonyManager.getNetworkOperator.overload().implementation = function () {
            return DEVICE.networkOp;
        };

        TelephonyManager.getNetworkOperatorName.overload().implementation = function () {
            return DEVICE.networkOpName;
        };

        TelephonyManager.getSimOperator.overload().implementation = function () {
            return DEVICE.simOp;
        };

        TelephonyManager.getSimCountryIso.overload().implementation = function () {
            return DEVICE.simCountry;
        };

        TelephonyManager.getLine1Number.overload().implementation = function () {
            return DEVICE.lineNumber;
        };

        // Phone type: PHONE_TYPE_GSM = 1
        try {
            TelephonyManager.getPhoneType.overload().implementation = function () {
                return 1;
            };
            hookCount++;
        } catch (e) { /* ignore */ }

        // Network type: LTE = 13
        try {
            TelephonyManager.getNetworkType.overload().implementation = function () {
                return 13;
            };
            hookCount++;
        } catch (e) { /* ignore */ }

        hookCount += 6;
        console.log("[+] TelephonyManager bypass installed");
    } catch (e) {
        console.log("[-] TelephonyManager bypass failed: " + e);
    }

    // =========================================================================
    // 3. android.os.Build static fields
    // =========================================================================
    try {
        var Build = Java.use("android.os.Build");

        Build.MODEL.value        = DEVICE.model;
        Build.MANUFACTURER.value = DEVICE.manufacturer;
        Build.BRAND.value        = DEVICE.brand;
        Build.DEVICE.value       = DEVICE.device;
        Build.PRODUCT.value      = DEVICE.product;
        Build.HARDWARE.value     = DEVICE.hardware;
        Build.FINGERPRINT.value  = DEVICE.fingerprint;

        // Tags and type prevent "test-keys" / "eng" fingerprint checks
        try { Build.TAGS.value = "release-keys"; } catch (e) { /* field may be final */ }
        try { Build.TYPE.value = "user"; }          catch (e) { /* field may be final */ }
        try { Build.HOST.value = "abfarm-release-rbe-00087"; } catch (e) { /* ignore */ }
        try { Build.USER.value = "android-build"; }             catch (e) { /* ignore */ }

        hookCount += 7;
        console.log("[+] Build fields spoofed");
    } catch (e) {
        console.log("[-] Build field spoofing failed: " + e);
    }

    // =========================================================================
    // 4. Sensor availability — SensorManager.getSensorList() / getDefaultSensor()
    //    Many emulator detectors call getDefaultSensor(TYPE_ACCELEROMETER) and
    //    check for null.  We return the real value unchanged — emulators running
    //    on AVD already report virtual sensors — but we suppress the detection
    //    by ensuring getVendorString-based checks see a realistic vendor.
    // =========================================================================
    try {
        var Sensor = Java.use("android.hardware.Sensor");

        // Hook getVendor() to return a plausible vendor string instead of
        // "Google" (which is the giveaway on QEMU-based emulators)
        Sensor.getVendor.overload().implementation = function () {
            var vendor = this.getVendor();
            if (vendor !== null && (vendor.toLowerCase().indexOf("google") >= 0 ||
                                    vendor.toLowerCase().indexOf("qemu")   >= 0)) {
                send({
                    type: "api_event", class: "Sensor", method: "getVendor",
                    args: [vendor], extra: {severity: "low", category: "emulator_bypass",
                    detail: "Spoofed sensor vendor"}
                });
                return "STMicroelectronics";
            }
            return vendor;
        };

        // Hook getName() similarly
        Sensor.getName.overload().implementation = function () {
            var name = this.getName();
            if (name !== null && (name.toLowerCase().indexOf("goldfish") >= 0 ||
                                   name.toLowerCase().indexOf("qemu")     >= 0)) {
                send({
                    type: "api_event", class: "Sensor", method: "getName",
                    args: [name], extra: {severity: "low", category: "emulator_bypass",
                    detail: "Spoofed sensor name: " + name}
                });
                // Return realistic accelerometer name
                return "LSM6DSO Accelerometer";
            }
            return name;
        };

        hookCount += 2;
        console.log("[+] Sensor bypass installed");
    } catch (e) {
        console.log("[-] Sensor bypass failed: " + e);
    }

    // =========================================================================
    // 5. Runtime.exec() — intercept commands that expose emulator environment
    // =========================================================================
    var BLOCKED_EXEC_PATTERNS = [
        "getprop",
        "qemu",
        "qemu-props",
        "which qemu",
        "/system/bin/qemu",
        "goldfish",
        "ranchu"
    ];

    function execContainsEmulatorHint(cmd) {
        var lower = cmd.toLowerCase();
        for (var i = 0; i < BLOCKED_EXEC_PATTERNS.length; i++) {
            if (lower.indexOf(BLOCKED_EXEC_PATTERNS[i]) >= 0) {
                return true;
            }
        }
        return false;
    }

    try {
        var Runtime = Java.use("java.lang.Runtime");

        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            if (execContainsEmulatorHint(cmd)) {
                send({
                    type: "api_event", class: "Runtime", method: "exec",
                    args: [cmd], extra: {severity: "medium", category: "emulator_bypass",
                    detail: "Intercepted emulator-probing exec: " + cmd}
                });
                // Return exec of a benign command that produces empty output
                return this.exec("echo");
            }
            return this.exec(cmd);
        };

        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
            var combined = cmds.join(" ");
            if (execContainsEmulatorHint(combined)) {
                send({
                    type: "api_event", class: "Runtime", method: "exec",
                    args: [combined], extra: {severity: "medium", category: "emulator_bypass",
                    detail: "Intercepted emulator-probing exec (array): " + combined}
                });
                return this.exec("echo");
            }
            return this.exec(cmds);
        };

        Runtime.exec.overload("[Ljava.lang.String;", "[Ljava.lang.String;", "java.io.File").implementation = function (cmds, env, dir) {
            var combined = cmds.join(" ");
            if (execContainsEmulatorHint(combined)) {
                send({
                    type: "api_event", class: "Runtime", method: "exec",
                    args: [combined], extra: {severity: "medium", category: "emulator_bypass",
                    detail: "Intercepted emulator-probing exec (env/dir): " + combined}
                });
                return this.exec("echo");
            }
            return this.exec(cmds, env, dir);
        };

        hookCount += 3;
        console.log("[+] Runtime.exec() bypass installed");
    } catch (e) {
        console.log("[-] Runtime.exec() bypass failed: " + e);
    }

    // =========================================================================
    // 6. File.exists() — hide emulator-specific paths
    // =========================================================================
    var EMULATOR_PATHS = [
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/system/bin/qemud",
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
        "/proc/tty/drivers",          // checked for "goldfish"
        "/sys/class/rfkill/rfkill0/type",
        "/sys/devices/virtual/misc/qemu_pipe",
        "/dev/socket/qemud",
        "/dev/goldfish_pipe",
        "/sys/bus/platform/drivers/goldfish_fb",
        "/sys/bus/platform/drivers/goldfish_audio",
        "/sys/bus/platform/drivers/goldfish_battery",
        "/sys/bus/platform/drivers/goldfish_events",
        "/proc/irq/8",               // goldfish timer
        "/proc/irq/9",
        "/proc/irq/10"
    ];

    function pathIsEmulatorArtifact(path) {
        for (var i = 0; i < EMULATOR_PATHS.length; i++) {
            if (path === EMULATOR_PATHS[i]) return true;
        }
        // Catch-all: path contains goldfish, qemu, ranchu, genymotion
        var lower = path.toLowerCase();
        return lower.indexOf("goldfish") >= 0 ||
               lower.indexOf("qemu")     >= 0 ||
               lower.indexOf("ranchu")   >= 0 ||
               lower.indexOf("genyd")    >= 0 ||
               lower.indexOf("genymotion") >= 0;
    }

    try {
        var File = Java.use("java.io.File");

        File.exists.overload().implementation = function () {
            var path = this.getAbsolutePath();
            if (pathIsEmulatorArtifact(path)) {
                send({
                    type: "api_event", class: "File", method: "exists",
                    args: [path], extra: {severity: "low", category: "emulator_bypass",
                    detail: "Spoofed File.exists() -> false for: " + path}
                });
                return false;
            }
            return this.exists();
        };

        hookCount++;
        console.log("[+] File.exists() bypass installed");
    } catch (e) {
        console.log("[-] File.exists() bypass failed: " + e);
    }

    // =========================================================================
    // 7. PackageManager.hasSystemFeature() — hide emulator-only features
    // =========================================================================
    var EMULATOR_FEATURES = [
        "android.software.cts",
        "android.hardware.telephony.carrierlock",
        "com.google.android.feature.EXCHANGE_6_2"  // sometimes emulator-only
    ];

    // Features a real Pixel 7 WOULD have — return true for these if queried
    var REAL_DEVICE_FEATURES = {
        "android.hardware.camera.flash":           true,
        "android.hardware.fingerprint":            true,
        "android.hardware.nfc":                    true,
        "android.hardware.sensor.accelerometer":   true,
        "android.hardware.sensor.gyroscope":       true,
        "android.hardware.sensor.barometer":       true,
        "android.hardware.telephony":              true,
        "android.hardware.bluetooth":              true,
        "android.hardware.wifi":                   true,
        "android.hardware.location.gps":           true
    };

    try {
        var PackageManager = Java.use("android.content.pm.PackageManager");

        PackageManager.hasSystemFeature.overload("java.lang.String").implementation = function (feature) {
            // Block emulator-only features
            for (var i = 0; i < EMULATOR_FEATURES.length; i++) {
                if (feature === EMULATOR_FEATURES[i]) {
                    send({
                        type: "api_event", class: "PackageManager", method: "hasSystemFeature",
                        args: [feature], extra: {severity: "low", category: "emulator_bypass",
                        detail: "Blocked emulator-only feature: " + feature}
                    });
                    return false;
                }
            }
            // Guarantee real-device features return true
            if (REAL_DEVICE_FEATURES.hasOwnProperty(feature)) {
                return true;
            }
            return this.hasSystemFeature(feature);
        };

        PackageManager.hasSystemFeature.overload("java.lang.String", "int").implementation = function (feature, version) {
            for (var i = 0; i < EMULATOR_FEATURES.length; i++) {
                if (feature === EMULATOR_FEATURES[i]) {
                    return false;
                }
            }
            if (REAL_DEVICE_FEATURES.hasOwnProperty(feature)) {
                return true;
            }
            return this.hasSystemFeature(feature, version);
        };

        hookCount += 2;
        console.log("[+] PackageManager.hasSystemFeature() bypass installed");
    } catch (e) {
        console.log("[-] PackageManager.hasSystemFeature() bypass failed: " + e);
    }

    // =========================================================================
    // Finalise — report hook count
    // =========================================================================
    send({type: "hooks_loaded", count: hookCount, module: "emulator_bypass"});
    console.log("[*] Emulator bypass complete — " + hookCount + " hooks installed");
});
