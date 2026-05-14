"""Frida session management for runtime hooking."""

import os
import time
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path

from ..device.base import DeviceInterface
from ..exceptions import (
    FridaError, FridaNotAvailableError, FridaServerError,
    FridaAttachError, FridaScriptError
)

logger = logging.getLogger(__name__)


# Check for Frida availability
_FRIDA_AVAILABLE = False
try:
    import frida
    _FRIDA_AVAILABLE = True
except ImportError:
    frida = None


def is_frida_available() -> bool:
    """Check if Frida is available."""
    return _FRIDA_AVAILABLE


@dataclass
class HookResult:
    """Result from a Frida hook."""
    timestamp: float
    hook_name: str
    class_name: str
    method_name: str
    arguments: List[Any] = field(default_factory=list)
    return_value: Optional[Any] = None
    stack_trace: Optional[str] = None
    thread_id: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)


class FridaManager:
    """Manage Frida sessions and hooks."""

    # Default Frida server path on device
    DEFAULT_SERVER_PATH = "/data/local/tmp/frida-server"

    def __init__(self, device: DeviceInterface,
                 server_path: Optional[str] = None):
        if not _FRIDA_AVAILABLE:
            raise FridaNotAvailableError(
                "Frida is not installed. Install with: pip install frida-tools"
            )

        self._device = device
        self._server_path = server_path or self.DEFAULT_SERVER_PATH
        self._frida_device = None
        self._session = None
        self._scripts: Dict[str, Any] = {}
        self._hook_results: List[HookResult] = []
        self._message_handlers: List[Callable] = []
        self._lock = threading.Lock()
        self._running = False

    def is_server_running(self) -> bool:
        """Check if Frida server is running on device."""
        success, output = self._device.execute_shell("ps | grep frida-server")
        return success and "frida-server" in output

    def start_server(self, timeout: int = 10) -> bool:
        """Start Frida server on device.

        Args:
            timeout: Maximum time to wait for server to start.

        Returns:
            True if server is running.
        """
        if self.is_server_running():
            logger.info("Frida server already running")
            return True

        # Check if server binary exists
        success, _ = self._device.execute_shell(f"ls {self._server_path}")
        if not success:
            logger.error(f"Frida server not found at {self._server_path}")
            raise FridaServerError(f"Frida server not found at {self._server_path}")

        # Start server in background
        self._device.execute_shell(f"chmod 755 {self._server_path}")
        self._device.execute_shell(f"{self._server_path} &")

        # Wait for server to start
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.is_server_running():
                logger.info("Frida server started")
                time.sleep(0.5)  # Give it a moment
                return True
            time.sleep(0.5)

        raise FridaServerError("Failed to start Frida server")

    def stop_server(self) -> bool:
        """Stop Frida server on device."""
        success, _ = self._device.execute_shell("pkill -f frida-server")
        return success

    def connect(self) -> bool:
        """Connect to Frida on device.

        Returns:
            True if connected successfully.
        """
        try:
            # Get device serial
            info = self._device.get_device_info()
            serial = info.serial

            # Connect to device
            device_manager = frida.get_device_manager()

            # Try USB connection first
            try:
                self._frida_device = device_manager.get_device(serial)
            except Exception:
                # Try as remote
                try:
                    self._frida_device = frida.get_usb_device()
                except Exception:
                    self._frida_device = frida.get_remote_device()

            logger.info(f"Connected to Frida device: {self._frida_device.name}")
            self._running = True
            return True

        except Exception as e:
            logger.error(f"Failed to connect to Frida: {e}")
            raise FridaError(f"Failed to connect: {e}")

    def attach(self, package: str) -> bool:
        """Attach to running process.

        Args:
            package: Package name to attach to.

        Returns:
            True if attached successfully.
        """
        if not self._frida_device:
            self.connect()

        try:
            self._session = self._frida_device.attach(package)
            self._session.on('detached', self._on_detached)
            logger.info(f"Attached to {package}")
            return True

        except frida.ProcessNotFoundError:
            raise FridaAttachError(package, "Process not running")
        except Exception as e:
            raise FridaAttachError(package, str(e))

    def spawn_and_attach(self, package: str, activity: Optional[str] = None) -> bool:
        """Spawn app and attach.

        Args:
            package: Package name.
            activity: Optional activity to launch.

        Returns:
            True if spawned and attached.
        """
        if not self._frida_device:
            self.connect()

        try:
            # Spawn the process
            pid = self._frida_device.spawn([package])
            logger.info(f"Spawned {package} with PID {pid}")

            # Attach to spawned process
            self._session = self._frida_device.attach(pid)
            self._session.on('detached', self._on_detached)

            # Resume execution
            self._frida_device.resume(pid)
            logger.info(f"Attached and resumed {package}")

            return True

        except Exception as e:
            raise FridaAttachError(package, f"Failed to spawn: {e}")

    def _on_detached(self, reason, crash):
        """Handle session detachment."""
        logger.warning(f"Frida session detached: {reason}")
        if crash:
            logger.error(f"Crash info: {crash}")
        self._session = None

    def load_script(self, name: str, code: str,
                    on_message: Optional[Callable] = None) -> bool:
        """Load a Frida script.

        Args:
            name: Script identifier.
            code: JavaScript code.
            on_message: Optional message handler.

        Returns:
            True if script loaded successfully.
        """
        if not self._session:
            raise FridaError("Not attached to any process")

        try:
            script = self._session.create_script(code)

            def message_handler(message, data):
                self._handle_message(name, message, data)
                if on_message:
                    on_message(message, data)

            script.on('message', message_handler)
            script.load()

            self._scripts[name] = script
            logger.info(f"Loaded script: {name}")
            return True

        except Exception as e:
            raise FridaScriptError(name, str(e))

    def unload_script(self, name: str) -> bool:
        """Unload a script.

        Args:
            name: Script identifier.

        Returns:
            True if unloaded successfully.
        """
        if name in self._scripts:
            try:
                self._scripts[name].unload()
                del self._scripts[name]
                return True
            except Exception:
                pass
        return False

    def _handle_message(self, script_name: str, message: Dict, data: Any):
        """Handle message from Frida script."""
        with self._lock:
            if message.get('type') == 'send':
                payload = message.get('payload', {})

                if isinstance(payload, dict):
                    hook_result = HookResult(
                        timestamp=time.time(),
                        hook_name=script_name,
                        class_name=payload.get('class', ''),
                        method_name=payload.get('method', ''),
                        arguments=payload.get('args', []),
                        return_value=payload.get('retval'),
                        stack_trace=payload.get('stack'),
                        thread_id=payload.get('tid'),
                        extra=payload.get('extra', {})
                    )
                    self._hook_results.append(hook_result)

            elif message.get('type') == 'error':
                logger.error(f"Script error ({script_name}): {message.get('description')}")

    def call_script_function(self, script_name: str, function_name: str,
                             *args) -> Any:
        """Call an exported function in a script.

        Args:
            script_name: Script identifier.
            function_name: Function to call.
            *args: Arguments to pass.

        Returns:
            Function return value.
        """
        if script_name not in self._scripts:
            raise FridaError(f"Script not loaded: {script_name}")

        try:
            script = self._scripts[script_name]
            exports = script.exports
            if hasattr(exports, function_name):
                return getattr(exports, function_name)(*args)
            else:
                raise FridaError(f"Function not found: {function_name}")
        except Exception as e:
            raise FridaScriptError(script_name, f"Call failed: {e}")

    def get_hook_results(self, hook_name: Optional[str] = None,
                         since: Optional[float] = None) -> List[HookResult]:
        """Get captured hook results.

        Args:
            hook_name: Filter by hook name (optional).
            since: Only results after this timestamp (optional).

        Returns:
            List of HookResult.
        """
        with self._lock:
            results = self._hook_results.copy()

        if hook_name:
            results = [r for r in results if r.hook_name == hook_name]

        if since:
            results = [r for r in results if r.timestamp > since]

        return results

    def clear_results(self):
        """Clear all captured hook results."""
        with self._lock:
            self._hook_results.clear()

    def bypass_ssl_pinning(self) -> bool:
        """Enable SSL pinning bypass.

        Loads a script that hooks common SSL pinning implementations.
        """
        script_path = Path(__file__).parent / "hooks" / "ssl_bypass.js"
        if script_path.exists():
            with open(script_path, 'r') as f:
                code = f.read()
        else:
            # Embedded fallback script
            code = self._get_ssl_bypass_script()

        return self.load_script("ssl_bypass", code)

    def bypass_root_detection(self) -> bool:
        """Enable root detection bypass."""
        script_path = Path(__file__).parent / "hooks" / "root_bypass.js"
        if script_path.exists():
            with open(script_path, 'r') as f:
                code = f.read()
        else:
            code = self._get_root_bypass_script()
        return self.load_script("root_bypass", code)

    def bypass_emulator_detection(self) -> bool:
        """Enable emulator/environment detection bypass."""
        script_path = Path(__file__).parent / "hooks" / "emulator_bypass.js"
        if script_path.exists():
            with open(script_path, 'r') as f:
                code = f.read()
            return self.load_script("emulator_bypass", code)
        return False

    def enable_api_monitoring(self) -> bool:
        """Enable sensitive API monitoring.

        Hooks sensitive APIs to detect data access.
        """
        script_path = Path(__file__).parent / "hooks" / "api_monitor.js"
        if script_path.exists():
            with open(script_path, 'r') as f:
                code = f.read()
        else:
            code = self._get_api_monitor_script()

        return self.load_script("api_monitor", code)

    def hook_method(self, class_name: str, method_name: str,
                    log_args: bool = True, log_return: bool = True,
                    log_stack: bool = False) -> bool:
        """Hook a specific Java method.

        Args:
            class_name: Full class name.
            method_name: Method name.
            log_args: Log method arguments.
            log_return: Log return value.
            log_stack: Log stack trace.

        Returns:
            True if hook was set.
        """
        hook_id = f"hook_{class_name}_{method_name}".replace(".", "_")

        code = f"""
        Java.perform(function() {{
            var clazz = Java.use("{class_name}");
            var overloads = clazz.{method_name}.overloads;

            for (var i = 0; i < overloads.length; i++) {{
                overloads[i].implementation = function() {{
                    var args = [];
                    {"for (var j = 0; j < arguments.length; j++) { args.push(String(arguments[j])); }" if log_args else ""}

                    var result = this.{method_name}.apply(this, arguments);

                    send({{
                        "class": "{class_name}",
                        "method": "{method_name}",
                        "args": args,
                        {"retval: String(result)," if log_return else ""}
                        {"stack: Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new())," if log_stack else ""}
                        "tid": Process.getCurrentThreadId()
                    }});

                    return result;
                }};
            }}
        }});
        """

        return self.load_script(hook_id, code)

    def hook_webview_load(self) -> bool:
        """Hook WebView.loadUrl for XSS detection."""
        code = """
        Java.perform(function() {
            var WebView = Java.use("android.webkit.WebView");

            WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
                send({
                    "class": "android.webkit.WebView",
                    "method": "loadUrl",
                    "args": [url],
                    "extra": {"type": "webview_load"}
                });
                return this.loadUrl(url);
            };

            WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function(url, headers) {
                send({
                    "class": "android.webkit.WebView",
                    "method": "loadUrl",
                    "args": [url, headers ? headers.toString() : null],
                    "extra": {"type": "webview_load_headers"}
                });
                return this.loadUrl(url, headers);
            };

            WebView.loadData.overload("java.lang.String", "java.lang.String", "java.lang.String").implementation = function(data, mimeType, encoding) {
                send({
                    "class": "android.webkit.WebView",
                    "method": "loadData",
                    "args": [data.substring(0, 200), mimeType, encoding],
                    "extra": {"type": "webview_data"}
                });
                return this.loadData(data, mimeType, encoding);
            };
        });
        """
        return self.load_script("webview_hooks", code)

    def detach(self):
        """Detach from process."""
        for name in list(self._scripts.keys()):
            self.unload_script(name)

        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None

        self._running = False

    def is_attached(self) -> bool:
        """Check if currently attached."""
        return self._session is not None

    def is_available(self) -> bool:
        """Check if Frida is available and ready to use."""
        return is_frida_available() and (self.is_server_running() or self._session is not None)

    def _get_ssl_bypass_script(self) -> str:
        """Get embedded SSL bypass script."""
        return """
        Java.perform(function() {
            // TrustManager bypass
            var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");

            var TrustManagerImpl = Java.registerClass({
                name: "com.bypass.TrustManager",
                implements: [TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });

            // OkHttp bypass
            try {
                var CertificatePinner = Java.use("okhttp3.CertificatePinner");
                CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
                    send({class: "okhttp3.CertificatePinner", method: "check", args: [hostname], extra: {bypassed: true}});
                };
            } catch(e) {}

            // Apache bypass
            try {
                var AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
                AbstractVerifier.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean").implementation = function() {
                    send({class: "AbstractVerifier", method: "verify", extra: {bypassed: true}});
                };
            } catch(e) {}

            send({class: "SSLBypass", method: "init", extra: {status: "active"}});
        });
        """

    def _get_root_bypass_script(self) -> str:
        """Get embedded root bypass script."""
        return """
        Java.perform(function() {
            // File.exists bypass for common root indicators
            var File = Java.use("java.io.File");
            var rootIndicators = ["/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
                                  "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
                                  "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
                                  "/su/bin/su", "/magisk"];

            File.exists.implementation = function() {
                var path = this.getAbsolutePath();
                for (var i = 0; i < rootIndicators.length; i++) {
                    if (path.indexOf(rootIndicators[i]) >= 0) {
                        send({class: "java.io.File", method: "exists", args: [path], extra: {bypassed: true}});
                        return false;
                    }
                }
                return this.exists();
            };

            // Runtime.exec bypass
            var Runtime = Java.use("java.lang.Runtime");
            Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
                if (cmd.indexOf("su") >= 0 || cmd.indexOf("which") >= 0) {
                    send({class: "java.lang.Runtime", method: "exec", args: [cmd], extra: {bypassed: true}});
                    throw Java.use("java.io.IOException").$new("Permission denied");
                }
                return this.exec(cmd);
            };

            // Build.TAGS bypass
            var Build = Java.use("android.os.Build");
            Build.TAGS.value = "release-keys";

            send({class: "RootBypass", method: "init", extra: {status: "active"}});
        });
        """

    def _get_api_monitor_script(self) -> str:
        """Get embedded API monitoring script."""
        return """
        Java.perform(function() {
            // SharedPreferences monitoring
            var SharedPreferences = Java.use("android.content.SharedPreferences");
            var Editor = Java.use("android.content.SharedPreferences$Editor");

            // Content Resolver
            var ContentResolver = Java.use("android.content.ContentResolver");
            ContentResolver.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String").implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
                send({
                    class: "android.content.ContentResolver",
                    method: "query",
                    args: [uri.toString(), selection],
                    extra: {type: "content_query"}
                });
                return this.query(uri, projection, selection, selectionArgs, sortOrder);
            };

            // Crypto operations
            try {
                var Cipher = Java.use("javax.crypto.Cipher");
                Cipher.doFinal.overload("[B").implementation = function(input) {
                    send({
                        class: "javax.crypto.Cipher",
                        method: "doFinal",
                        args: [input.length + " bytes"],
                        extra: {type: "crypto"}
                    });
                    return this.doFinal(input);
                };
            } catch(e) {}

            // Log monitoring for sensitive data
            var Log = Java.use("android.util.Log");
            ["d", "i", "w", "e", "v"].forEach(function(level) {
                Log[level].overload("java.lang.String", "java.lang.String").implementation = function(tag, msg) {
                    var lowerMsg = msg.toLowerCase();
                    if (lowerMsg.indexOf("password") >= 0 || lowerMsg.indexOf("token") >= 0 ||
                        lowerMsg.indexOf("secret") >= 0 || lowerMsg.indexOf("api_key") >= 0) {
                        send({
                            class: "android.util.Log",
                            method: level,
                            args: [tag, msg],
                            extra: {type: "sensitive_log"}
                        });
                    }
                    return this[level](tag, msg);
                };
            });

            send({class: "APIMonitor", method: "init", extra: {status: "active"}});
        });
        """
