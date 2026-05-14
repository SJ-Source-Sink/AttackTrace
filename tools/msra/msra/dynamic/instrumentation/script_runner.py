"""Frida script runner for executing hook scripts."""

import os
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path
from enum import Enum

from .frida_manager import FridaManager, HookResult, is_frida_available
from ..device.base import DeviceInterface
from ..exceptions import FridaError, FridaScriptError

logger = logging.getLogger(__name__)


class ScriptCategory(Enum):
    """Category of Frida script."""
    BYPASS = "bypass"           # Security bypass (SSL, root, etc.)
    MONITOR = "monitor"         # API monitoring
    EXPLOIT = "exploit"         # Exploit verification
    HELPER = "helper"           # Utility scripts


@dataclass
class ScriptResult:
    """Result of script execution."""
    script_name: str
    category: ScriptCategory
    success: bool
    duration: float = 0.0
    hook_results: List[HookResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)


class ScriptRunner:
    """Execute Frida scripts for dynamic analysis."""

    # Built-in script templates
    SCRIPTS = {
        "ssl_bypass": {
            "category": ScriptCategory.BYPASS,
            "description": "Bypass SSL certificate pinning",
            "file": "ssl_bypass.js",
        },
        "root_bypass": {
            "category": ScriptCategory.BYPASS,
            "description": "Bypass root detection",
            "file": "root_bypass.js",
        },
        "api_monitor": {
            "category": ScriptCategory.MONITOR,
            "description": "Monitor sensitive API calls",
            "file": "api_monitor.js",
        },
        "webview_monitor": {
            "category": ScriptCategory.MONITOR,
            "description": "Monitor WebView operations",
            "file": "webview_monitor.js",
        },
        "intent_monitor": {
            "category": ScriptCategory.MONITOR,
            "description": "Monitor Intent operations",
            "file": "intent_monitor.js",
        },
        "crypto_monitor": {
            "category": ScriptCategory.MONITOR,
            "description": "Monitor cryptographic operations",
            "file": "crypto_monitor.js",
        },
        "file_monitor": {
            "category": ScriptCategory.MONITOR,
            "description": "Monitor file system access",
            "file": "file_monitor.js",
        },
        "network_monitor": {
            "category": ScriptCategory.MONITOR,
            "description": "Monitor network operations",
            "file": "network_monitor.js",
        },
    }

    def __init__(self, device: DeviceInterface, frida_manager: FridaManager):
        self._device = device
        self._frida = frida_manager
        self._hooks_dir = Path(__file__).parent / "hooks"
        self._loaded_scripts: Dict[str, ScriptCategory] = {}
        self._results: Dict[str, ScriptResult] = {}

    def list_available_scripts(self) -> Dict[str, Dict[str, Any]]:
        """List all available scripts."""
        scripts = {}

        # Built-in scripts
        for name, info in self.SCRIPTS.items():
            script_path = self._hooks_dir / info["file"]
            scripts[name] = {
                "category": info["category"].value,
                "description": info["description"],
                "available": script_path.exists(),
            }

        # Custom scripts in hooks directory
        if self._hooks_dir.exists():
            for js_file in self._hooks_dir.glob("*.js"):
                name = js_file.stem
                if name not in scripts:
                    scripts[name] = {
                        "category": "custom",
                        "description": f"Custom script: {name}",
                        "available": True,
                    }

        return scripts

    def load_script(self, name: str,
                    on_message: Optional[Callable] = None) -> bool:
        """Load a script by name.

        Args:
            name: Script name.
            on_message: Optional message callback.

        Returns:
            True if loaded successfully.
        """
        if not self._frida.is_attached():
            raise FridaError("Not attached to any process")

        # Find script
        if name in self.SCRIPTS:
            script_path = self._hooks_dir / self.SCRIPTS[name]["file"]
            category = self.SCRIPTS[name]["category"]
        else:
            script_path = self._hooks_dir / f"{name}.js"
            category = ScriptCategory.HELPER

        if not script_path.exists():
            # Try to use embedded script
            if name == "ssl_bypass":
                return self._frida.bypass_ssl_pinning()
            elif name == "root_bypass":
                return self._frida.bypass_root_detection()
            elif name == "api_monitor":
                return self._frida.enable_api_monitoring()
            else:
                raise FridaScriptError(name, f"Script not found: {script_path}")

        # Load from file
        with open(script_path, 'r') as f:
            code = f.read()

        success = self._frida.load_script(name, code, on_message)
        if success:
            self._loaded_scripts[name] = category

        return success

    def unload_script(self, name: str) -> bool:
        """Unload a script."""
        if name in self._loaded_scripts:
            success = self._frida.unload_script(name)
            if success:
                del self._loaded_scripts[name]
            return success
        return False

    def run_bypass_scripts(self) -> Dict[str, bool]:
        """Run all bypass scripts.

        Returns:
            Dict of script_name -> success.
        """
        results = {}

        bypass_scripts = [name for name, info in self.SCRIPTS.items()
                         if info["category"] == ScriptCategory.BYPASS]

        for name in bypass_scripts:
            try:
                results[name] = self.load_script(name)
            except Exception as e:
                logger.warning(f"Failed to load {name}: {e}")
                results[name] = False

        return results

    def run_monitor_scripts(self) -> Dict[str, bool]:
        """Run all monitoring scripts.

        Returns:
            Dict of script_name -> success.
        """
        results = {}

        monitor_scripts = [name for name, info in self.SCRIPTS.items()
                          if info["category"] == ScriptCategory.MONITOR]

        for name in monitor_scripts:
            try:
                results[name] = self.load_script(name)
            except Exception as e:
                logger.warning(f"Failed to load {name}: {e}")
                results[name] = False

        return results

    def run_script_with_timeout(self, name: str, timeout: float = 10.0,
                                 wait_for_results: bool = True) -> ScriptResult:
        """Run script and wait for results.

        Args:
            name: Script name.
            timeout: Maximum wait time.
            wait_for_results: Wait for hook results.

        Returns:
            ScriptResult with hook data.
        """
        start_time = time.time()
        result = ScriptResult(
            script_name=name,
            category=self.SCRIPTS.get(name, {}).get("category", ScriptCategory.HELPER),
            success=False,
        )

        try:
            # Record current results count
            initial_results = len(self._frida.get_hook_results())

            # Load script
            success = self.load_script(name)
            result.success = success

            if success and wait_for_results:
                # Wait for results
                end_time = start_time + timeout
                while time.time() < end_time:
                    current_results = self._frida.get_hook_results()
                    if len(current_results) > initial_results:
                        # Got new results
                        result.hook_results = current_results[initial_results:]
                        break
                    time.sleep(0.2)

            result.duration = time.time() - start_time

        except Exception as e:
            result.errors.append(str(e))
            result.duration = time.time() - start_time

        self._results[name] = result
        return result

    def inject_xss_detector(self) -> bool:
        """Inject XSS detection hooks."""
        code = """
        Java.perform(function() {
            // Hook WebView methods that could execute JS
            var WebView = Java.use("android.webkit.WebView");

            WebView.evaluateJavascript.overload("java.lang.String", "android.webkit.ValueCallback").implementation = function(script, callback) {
                send({
                    class: "android.webkit.WebView",
                    method: "evaluateJavascript",
                    args: [script.substring(0, 500)],
                    extra: {type: "js_execution", severity: "high"}
                });
                return this.evaluateJavascript(script, callback);
            };

            // Hook addJavascriptInterface
            WebView.addJavascriptInterface.overload("java.lang.Object", "java.lang.String").implementation = function(obj, name) {
                send({
                    class: "android.webkit.WebView",
                    method: "addJavascriptInterface",
                    args: [obj.getClass().getName(), name],
                    extra: {type: "js_interface", severity: "critical"}
                });
                return this.addJavascriptInterface(obj, name);
            };

            // Hook loadUrl with javascript:
            var originalLoadUrl = WebView.loadUrl.overload("java.lang.String");
            originalLoadUrl.implementation = function(url) {
                if (url.toLowerCase().indexOf("javascript:") === 0) {
                    send({
                        class: "android.webkit.WebView",
                        method: "loadUrl",
                        args: [url.substring(0, 500)],
                        extra: {type: "js_url", severity: "high"}
                    });
                }
                return originalLoadUrl.call(this, url);
            };
        });
        """
        return self._frida.load_script("xss_detector", code)

    def inject_sqli_detector(self) -> bool:
        """Inject SQL injection detection hooks."""
        code = """
        Java.perform(function() {
            // Hook SQLite database operations
            var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

            SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(sql, args) {
                var lowerSql = sql.toLowerCase();
                var suspicious = lowerSql.indexOf("'") >= 0 ||
                                 lowerSql.indexOf("--") >= 0 ||
                                 lowerSql.indexOf("union") >= 0 ||
                                 lowerSql.indexOf("or 1=1") >= 0;
                send({
                    class: "android.database.sqlite.SQLiteDatabase",
                    method: "rawQuery",
                    args: [sql, args ? args.toString() : null],
                    extra: {type: "sql_query", suspicious: suspicious}
                });
                return this.rawQuery(sql, args);
            };

            SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
                send({
                    class: "android.database.sqlite.SQLiteDatabase",
                    method: "execSQL",
                    args: [sql],
                    extra: {type: "sql_exec"}
                });
                return this.execSQL(sql);
            };

            // Hook ContentProvider query
            var ContentProvider = Java.use("android.content.ContentProvider");
            ContentProvider.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String").implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
                var suspicious = selection && (
                    selection.indexOf("'") >= 0 ||
                    selection.indexOf("--") >= 0 ||
                    selection.toLowerCase().indexOf("or 1=1") >= 0
                );
                send({
                    class: "android.content.ContentProvider",
                    method: "query",
                    args: [uri.toString(), selection],
                    extra: {type: "provider_query", suspicious: suspicious}
                });
                return this.query(uri, projection, selection, selectionArgs, sortOrder);
            };
        });
        """
        return self._frida.load_script("sqli_detector", code)

    def inject_intent_monitor(self) -> bool:
        """Inject Intent monitoring hooks."""
        code = """
        Java.perform(function() {
            var Activity = Java.use("android.app.Activity");
            var Intent = Java.use("android.content.Intent");

            // Monitor getIntent
            Activity.getIntent.implementation = function() {
                var intent = this.getIntent();
                if (intent !== null) {
                    send({
                        class: "android.app.Activity",
                        method: "getIntent",
                        args: [],
                        extra: {
                            action: intent.getAction(),
                            data: intent.getDataString(),
                            type: intent.getType(),
                            component: intent.getComponent() ? intent.getComponent().flattenToString() : null
                        }
                    });
                }
                return intent;
            };

            // Monitor startActivity
            Activity.startActivity.overload("android.content.Intent").implementation = function(intent) {
                send({
                    class: "android.app.Activity",
                    method: "startActivity",
                    args: [],
                    extra: {
                        action: intent.getAction(),
                        data: intent.getDataString(),
                        component: intent.getComponent() ? intent.getComponent().flattenToString() : null
                    }
                });
                return this.startActivity(intent);
            };

            // Monitor setResult
            Activity.setResult.overload("int", "android.content.Intent").implementation = function(resultCode, data) {
                send({
                    class: "android.app.Activity",
                    method: "setResult",
                    args: [resultCode],
                    extra: {
                        data: data ? data.getDataString() : null,
                        action: data ? data.getAction() : null
                    }
                });
                return this.setResult(resultCode, data);
            };
        });
        """
        return self._frida.load_script("intent_monitor", code)

    def get_results(self, script_name: Optional[str] = None) -> Dict[str, ScriptResult]:
        """Get script execution results.

        Args:
            script_name: Optional filter by script name.

        Returns:
            Dict of script_name -> ScriptResult.
        """
        if script_name:
            if script_name in self._results:
                return {script_name: self._results[script_name]}
            return {}
        return self._results.copy()

    def get_all_hook_results(self) -> List[HookResult]:
        """Get all hook results from all scripts."""
        return self._frida.get_hook_results()

    def stop_all(self):
        """Stop all scripts and cleanup."""
        for name in list(self._loaded_scripts.keys()):
            self.unload_script(name)
        self._loaded_scripts.clear()
