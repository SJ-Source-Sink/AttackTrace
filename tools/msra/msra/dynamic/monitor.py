"""
Application Monitor

Monitors the application during dynamic testing for:
- Crashes and exceptions
- Sensitive data in logs
- Network traffic indicators
- Security-relevant events
- Runtime API calls (via Frida when available)
"""

import re
import subprocess
import threading
import time
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Callable, Any, TYPE_CHECKING
from queue import Queue
from datetime import datetime

if TYPE_CHECKING:
    from .instrumentation import FridaManager

logger = logging.getLogger(__name__)


@dataclass
class SecurityEvent:
    """A security-relevant event detected during monitoring."""
    timestamp: datetime
    event_type: str  # 'crash', 'sensitive_log', 'network', 'permission', 'exception'
    severity: str    # 'critical', 'high', 'medium', 'low', 'info'
    description: str
    raw_data: str = ""
    context: Dict = field(default_factory=dict)


class AppMonitor:
    """
    Monitors an Android application for security-relevant events during testing.
    """

    # Patterns for sensitive data in logs
    SENSITIVE_PATTERNS = [
        (r'password["\s:=]+[^\s]{4,}', 'password'),
        (r'token["\s:=]+[^\s]{10,}', 'token'),
        (r'api[_-]?key["\s:=]+[^\s]{10,}', 'api_key'),
        (r'secret["\s:=]+[^\s]{4,}', 'secret'),
        (r'bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', 'bearer_token'),
        (r'session[_-]?id["\s:=]+[^\s]{10,}', 'session'),
        (r'auth["\s:=]+[^\s]{10,}', 'auth'),
        (r'credit[_-]?card["\s:=]+\d{13,19}', 'credit_card'),
        (r'ssn["\s:=]+\d{3}-?\d{2}-?\d{4}', 'ssn'),
        (r'private[_-]?key', 'private_key'),
    ]

    # Patterns for crashes/exceptions
    CRASH_PATTERNS = [
        r'FATAL EXCEPTION',
        r'AndroidRuntime.*Error',
        r'java\.lang\.\w+Exception',
        r'Process.*has died',
        r'ANR in',
        r'Native crash',
        r'SIGSEGV',
        r'SIGABRT',
    ]

    def __init__(self, controller, package_name: str):
        self.controller = controller
        self.package_name = package_name
        self.events: List[SecurityEvent] = []
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._log_queue: Queue = Queue()
        self._callbacks: List[Callable[[SecurityEvent], None]] = []

    def start(self) -> bool:
        """Start monitoring the application."""
        if self._monitoring:
            return True

        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

        print(f"[+] Started monitoring {self.package_name}")
        return True

    def stop(self) -> List[SecurityEvent]:
        """Stop monitoring and return collected events."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
        return self.events

    def add_callback(self, callback: Callable[[SecurityEvent], None]):
        """Add callback to be called when security event is detected."""
        self._callbacks.append(callback)

    def _monitor_loop(self):
        """Main monitoring loop."""
        # Start logcat process
        cmd = [
            self.controller.adb_path, "-s", self.controller.current_device.serial,
            "logcat", "-v", "time"
        ]

        try:
            # Get PID for filtering
            pid_result = subprocess.run(
                [self.controller.adb_path, "-s", self.controller.current_device.serial,
                 "shell", "pidof", self.package_name],
                capture_output=True, text=True, timeout=5
            )
            pid = pid_result.stdout.strip()
            if pid:
                cmd.extend(["--pid", pid])
        except Exception:
            pass  # PID not available — fall back to unfiltered logcat

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        try:
            while self._monitoring and process.poll() is None:
                line = process.stdout.readline()
                if line:
                    self._process_log_line(line.strip())
        finally:
            process.terminate()

    def _process_log_line(self, line: str):
        """Process a single log line for security events."""
        if not line:
            return

        # Check for crashes
        for pattern in self.CRASH_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type='crash',
                    severity='critical',
                    description=f"Application crash detected",
                    raw_data=line,
                )
                self._add_event(event)
                return

        # Check for sensitive data
        for pattern, data_type in self.SENSITIVE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type='sensitive_log',
                    severity='high',
                    description=f"Sensitive data ({data_type}) found in logs",
                    raw_data=line[:200],  # Truncate to avoid storing actual secrets
                    context={'data_type': data_type},
                )
                self._add_event(event)
                return

        # Check for security-relevant system events
        if self.package_name in line:
            # Permission denied
            if 'Permission Denial' in line or 'permission denied' in line.lower():
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type='permission',
                    severity='info',
                    description="Permission denial logged",
                    raw_data=line,
                )
                self._add_event(event)

            # Security exceptions
            elif 'SecurityException' in line:
                event = SecurityEvent(
                    timestamp=datetime.now(),
                    event_type='exception',
                    severity='medium',
                    description="Security exception thrown",
                    raw_data=line,
                )
                self._add_event(event)

    def _add_event(self, event: SecurityEvent):
        """Add event to list and notify callbacks."""
        self.events.append(event)

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(event)
            except:
                pass

    def get_events_by_type(self, event_type: str) -> List[SecurityEvent]:
        """Get all events of a specific type."""
        return [e for e in self.events if e.event_type == event_type]

    def get_events_by_severity(self, severity: str) -> List[SecurityEvent]:
        """Get all events of a specific severity."""
        return [e for e in self.events if e.severity == severity]

    def has_crashes(self) -> bool:
        """Check if any crashes were detected."""
        return any(e.event_type == 'crash' for e in self.events)

    def has_sensitive_leaks(self) -> bool:
        """Check if sensitive data was logged."""
        return any(e.event_type == 'sensitive_log' for e in self.events)

    def get_summary(self) -> Dict:
        """Get summary of monitored events."""
        summary = {
            'total_events': len(self.events),
            'crashes': len(self.get_events_by_type('crash')),
            'sensitive_leaks': len(self.get_events_by_type('sensitive_log')),
            'permission_issues': len(self.get_events_by_type('permission')),
            'exceptions': len(self.get_events_by_type('exception')),
            'by_severity': {
                'critical': len(self.get_events_by_severity('critical')),
                'high': len(self.get_events_by_severity('high')),
                'medium': len(self.get_events_by_severity('medium')),
                'low': len(self.get_events_by_severity('low')),
                'info': len(self.get_events_by_severity('info')),
            }
        }
        return summary


class NetworkMonitor:
    """
    Monitor network traffic during testing.
    Requires root or tcpdump on device.
    """

    def __init__(self, controller, output_path: str):
        self.controller = controller
        self.output_path = output_path
        self._process: Optional[subprocess.Popen] = None

    def start_capture(self) -> bool:
        """Start capturing network traffic."""
        # Check if tcpdump is available
        success, output = self.controller.execute_command("which tcpdump")
        if not success or not output.strip():
            print("[!] tcpdump not available on device (requires root)")
            return False

        # Start tcpdump
        device_pcap = "/sdcard/capture.pcap"
        cmd = [
            self.controller.adb_path, "-s", self.controller.current_device.serial,
            "shell", "tcpdump", "-w", device_pcap, "-s", "0"
        ]

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return True
        except Exception as e:
            print(f"[!] Failed to start network capture: {e}")
            return False

    def stop_capture(self) -> Optional[str]:
        """Stop capture and pull pcap file."""
        if self._process:
            self._process.terminate()
            time.sleep(1)

            # Pull pcap file
            device_pcap = "/sdcard/capture.pcap"
            try:
                subprocess.run(
                    [self.controller.adb_path, "-s", self.controller.current_device.serial,
                     "pull", device_pcap, self.output_path],
                    capture_output=True, timeout=30
                )

                # Clean up
                subprocess.run(
                    [self.controller.adb_path, "-s", self.controller.current_device.serial,
                     "shell", "rm", device_pcap],
                    capture_output=True, timeout=5
                )

                return self.output_path
            except:
                pass

        return None


@dataclass
class RuntimeEvent:
    """Event captured from runtime instrumentation (Frida)."""
    timestamp: datetime
    event_type: str  # 'api_call', 'hook_trigger', 'data_access', 'crypto', 'network'
    class_name: str
    method_name: str
    arguments: List[Any] = field(default_factory=list)
    return_value: Any = None
    stack_trace: Optional[str] = None
    severity: str = "info"
    context: Dict = field(default_factory=dict)


class EnhancedAppMonitor:
    """
    Enhanced application monitor with Frida integration.

    Combines logcat monitoring with runtime instrumentation to provide
    comprehensive visibility into application behavior during testing.
    """

    # Sensitive API patterns to monitor
    SENSITIVE_APIS = {
        'crypto': [
            ('javax.crypto.Cipher', 'getInstance'),
            ('javax.crypto.Cipher', 'doFinal'),
            ('java.security.MessageDigest', 'digest'),
            ('javax.crypto.Mac', 'doFinal'),
        ],
        'network': [
            ('java.net.URL', 'openConnection'),
            ('okhttp3.OkHttpClient', 'newCall'),
            ('android.webkit.WebView', 'loadUrl'),
        ],
        'storage': [
            ('android.content.SharedPreferences$Editor', 'putString'),
            ('android.database.sqlite.SQLiteDatabase', 'execSQL'),
            ('android.database.sqlite.SQLiteDatabase', 'rawQuery'),
        ],
        'sensitive': [
            ('android.telephony.TelephonyManager', 'getDeviceId'),
            ('android.telephony.TelephonyManager', 'getSubscriberId'),
            ('android.location.LocationManager', 'getLastKnownLocation'),
            ('android.accounts.AccountManager', 'getAccounts'),
        ],
    }

    def __init__(
        self,
        controller,
        package_name: str,
        frida_manager: Optional['FridaManager'] = None
    ):
        self.controller = controller
        self.package_name = package_name
        self._frida = frida_manager

        # Events from different sources
        self.logcat_events: List[SecurityEvent] = []
        self.runtime_events: List[RuntimeEvent] = []

        # Monitoring state
        self._monitoring = False
        self._logcat_thread: Optional[threading.Thread] = None
        self._log_queue: Queue = Queue()
        self._callbacks: List[Callable[[SecurityEvent], None]] = []
        self._runtime_callbacks: List[Callable[[RuntimeEvent], None]] = []

        # Base app monitor for logcat
        self._base_monitor = AppMonitor(controller, package_name)

    def start(self, enable_frida_hooks: bool = True) -> bool:
        """Start comprehensive monitoring.

        Args:
            enable_frida_hooks: Enable Frida API monitoring if available

        Returns:
            True if monitoring started
        """
        if self._monitoring:
            return True

        self._monitoring = True

        # Start logcat monitoring
        self._base_monitor.start()

        # Start Frida hooks if available
        if enable_frida_hooks and self._frida and self._frida.is_attached():
            self._setup_frida_monitoring()

        logger.info(f"Started enhanced monitoring for {self.package_name}")
        return True

    def _setup_frida_monitoring(self):
        """Setup Frida hooks for runtime monitoring."""
        if not self._frida:
            return

        # Create comprehensive monitoring script
        monitor_script = """
        Java.perform(function() {
            // Monitor SharedPreferences writes
            try {
                var SharedPrefsEditor = Java.use('android.content.SharedPreferences$Editor');
                SharedPrefsEditor.putString.implementation = function(key, value) {
                    send({
                        type: 'api_call',
                        class: 'SharedPreferences$Editor',
                        method: 'putString',
                        args: [key, value ? value.substring(0, 100) : null],
                        category: 'storage'
                    });
                    return this.putString(key, value);
                };
            } catch(e) {}

            // Monitor SQLite queries
            try {
                var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
                SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
                    send({
                        type: 'api_call',
                        class: 'SQLiteDatabase',
                        method: 'rawQuery',
                        args: [sql],
                        category: 'storage'
                    });
                    return this.rawQuery(sql, args);
                };
            } catch(e) {}

            // Monitor WebView loads
            try {
                var WebView = Java.use('android.webkit.WebView');
                WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                    send({
                        type: 'api_call',
                        class: 'WebView',
                        method: 'loadUrl',
                        args: [url],
                        category: 'network'
                    });
                    return this.loadUrl(url);
                };
            } catch(e) {}

            // Monitor HTTP connections
            try {
                var URL = Java.use('java.net.URL');
                URL.openConnection.overload().implementation = function() {
                    send({
                        type: 'api_call',
                        class: 'URL',
                        method: 'openConnection',
                        args: [this.toString()],
                        category: 'network'
                    });
                    return this.openConnection();
                };
            } catch(e) {}

            // Monitor crypto operations
            try {
                var Cipher = Java.use('javax.crypto.Cipher');
                Cipher.doFinal.overload('[B').implementation = function(data) {
                    send({
                        type: 'api_call',
                        class: 'Cipher',
                        method: 'doFinal',
                        args: ['<' + data.length + ' bytes>'],
                        category: 'crypto',
                        extra: {algorithm: this.getAlgorithm()}
                    });
                    return this.doFinal(data);
                };
            } catch(e) {}

            // Monitor sensitive device info access
            try {
                var TelephonyManager = Java.use('android.telephony.TelephonyManager');
                TelephonyManager.getDeviceId.overload().implementation = function() {
                    var result = this.getDeviceId();
                    send({
                        type: 'api_call',
                        class: 'TelephonyManager',
                        method: 'getDeviceId',
                        args: [],
                        category: 'sensitive',
                        severity: 'high'
                    });
                    return result;
                };
            } catch(e) {}

            // Monitor location access
            try {
                var LocationManager = Java.use('android.location.LocationManager');
                LocationManager.getLastKnownLocation.implementation = function(provider) {
                    var result = this.getLastKnownLocation(provider);
                    send({
                        type: 'api_call',
                        class: 'LocationManager',
                        method: 'getLastKnownLocation',
                        args: [provider],
                        category: 'sensitive',
                        severity: 'medium'
                    });
                    return result;
                };
            } catch(e) {}
        });
        """

        try:
            self._frida.load_script(
                "enhanced_monitor",
                monitor_script,
                on_message=self._handle_frida_message
            )
            logger.info("Frida monitoring hooks installed")
        except Exception as e:
            logger.warning(f"Failed to setup Frida monitoring: {e}")

    def _handle_frida_message(self, message: Dict):
        """Handle message from Frida script."""
        if message.get('type') == 'send':
            payload = message.get('payload', {})

            event = RuntimeEvent(
                timestamp=datetime.now(),
                event_type=payload.get('type', 'unknown'),
                class_name=payload.get('class', ''),
                method_name=payload.get('method', ''),
                arguments=payload.get('args', []),
                severity=payload.get('severity', 'info'),
                context={
                    'category': payload.get('category', 'unknown'),
                    'extra': payload.get('extra', {}),
                }
            )

            self.runtime_events.append(event)

            # Notify callbacks
            for callback in self._runtime_callbacks:
                try:
                    callback(event)
                except Exception:
                    pass

    def stop(self) -> Dict:
        """Stop monitoring and return all collected data.

        Returns:
            Dictionary with all events and summary
        """
        self._monitoring = False

        # Stop logcat monitoring
        self._base_monitor.stop()

        # Collect logcat events
        self.logcat_events = self._base_monitor.events

        return {
            'logcat_events': self.logcat_events,
            'runtime_events': self.runtime_events,
            'summary': self.get_summary(),
        }

    def add_callback(self, callback: Callable[[SecurityEvent], None]):
        """Add callback for logcat security events."""
        self._base_monitor.add_callback(callback)

    def add_runtime_callback(self, callback: Callable[[RuntimeEvent], None]):
        """Add callback for runtime events."""
        self._runtime_callbacks.append(callback)

    def get_events_by_category(self, category: str) -> List[RuntimeEvent]:
        """Get runtime events by category."""
        return [e for e in self.runtime_events
                if e.context.get('category') == category]

    def get_summary(self) -> Dict:
        """Get comprehensive monitoring summary."""
        logcat_summary = self._base_monitor.get_summary()

        runtime_by_category = {}
        for event in self.runtime_events:
            cat = event.context.get('category', 'unknown')
            runtime_by_category[cat] = runtime_by_category.get(cat, 0) + 1

        return {
            'logcat': logcat_summary,
            'runtime': {
                'total_events': len(self.runtime_events),
                'by_category': runtime_by_category,
                'sensitive_calls': len([e for e in self.runtime_events
                                       if e.context.get('category') == 'sensitive']),
                'crypto_operations': len([e for e in self.runtime_events
                                         if e.context.get('category') == 'crypto']),
                'network_calls': len([e for e in self.runtime_events
                                     if e.context.get('category') == 'network']),
                'storage_operations': len([e for e in self.runtime_events
                                          if e.context.get('category') == 'storage']),
            },
            'has_sensitive_data': (
                logcat_summary.get('sensitive_leaks', 0) > 0 or
                len([e for e in self.runtime_events if e.severity in ['high', 'critical']]) > 0
            ),
        }

    def has_sensitive_api_calls(self) -> bool:
        """Check if sensitive APIs were called."""
        return any(e.context.get('category') == 'sensitive'
                  for e in self.runtime_events)

    def get_crypto_operations(self) -> List[RuntimeEvent]:
        """Get all cryptographic operations."""
        return self.get_events_by_category('crypto')

    def get_network_activity(self) -> List[RuntimeEvent]:
        """Get all network-related events."""
        return self.get_events_by_category('network')

    def export_events(self, output_path: str):
        """Export all events to JSON file."""
        import json

        data = {
            'package': self.package_name,
            'timestamp': datetime.now().isoformat(),
            'logcat_events': [
                {
                    'timestamp': e.timestamp.isoformat(),
                    'type': e.event_type,
                    'severity': e.severity,
                    'description': e.description,
                    'data': e.raw_data[:500],
                }
                for e in self.logcat_events
            ],
            'runtime_events': [
                {
                    'timestamp': e.timestamp.isoformat(),
                    'type': e.event_type,
                    'class': e.class_name,
                    'method': e.method_name,
                    'args': [str(a)[:100] for a in e.arguments],
                    'severity': e.severity,
                    'category': e.context.get('category'),
                }
                for e in self.runtime_events
            ],
            'summary': self.get_summary(),
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        return output_path
