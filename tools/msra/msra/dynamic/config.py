"""Configuration management for dynamic analysis."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
from pathlib import Path


class AnalysisMode(Enum):
    """Dynamic analysis mode."""
    PASSIVE = "passive"    # Observe only, no modification
    ACTIVE = "active"      # Inject payloads, test exploits
    AGGRESSIVE = "aggressive"  # All techniques including fuzzing


class DeviceType(Enum):
    """Device connection type."""
    ADB_ONLY = "adb_only"
    UIAUTOMATOR = "uiautomator"
    AUTO = "auto"


@dataclass
class FridaConfig:
    """Frida-specific configuration."""
    enabled: bool = True
    server_path: str = "/data/local/tmp/frida-server"
    spawn_timeout: int = 30
    attach_timeout: int = 10
    ssl_bypass: bool = True
    root_bypass: bool = True
    api_monitoring: bool = True
    custom_scripts: List[str] = field(default_factory=list)


@dataclass
class ProxyConfig:
    """mitmproxy configuration."""
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8080
    install_ca: bool = True
    ca_cert_path: Optional[str] = None
    capture_flows: bool = True
    detect_leaks: bool = True
    leak_patterns: List[str] = field(default_factory=lambda: [
        r"password[\"']?\s*[:=]\s*[\"']?[^\"'\s]+",
        r"api[_-]?key[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]{16,}",
        r"bearer\s+[a-zA-Z0-9_.-]+",
        r"authorization[\"']?\s*[:=]\s*[\"']?[^\"'\s]+",
        r"token[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_.-]{16,}",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
        r"\b\d{16}\b",  # Credit card
    ])


@dataclass
class UIAutomationConfig:
    """UI automation configuration."""
    enabled: bool = True
    explore_depth: int = 5
    explore_timeout: int = 60
    click_delay: float = 0.5
    scroll_delay: float = 0.3
    text_input_delay: float = 0.1
    screenshot_on_action: bool = False
    max_elements_per_screen: int = 50
    implicit_wait: float = 2.0


@dataclass
class VerificationConfig:
    """Exploit verification configuration."""
    enabled: bool = True
    timeout_per_test: int = 10
    max_payloads_per_vuln: int = 5
    capture_evidence: bool = True
    screenshot_on_success: bool = True
    logcat_buffer_size: int = 1000

    # XSS payloads for WebView testing
    xss_payloads: List[str] = field(default_factory=lambda: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.domain)",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ])

    # SQLi payloads for ContentProvider testing
    sqli_payloads: List[str] = field(default_factory=lambda: [
        "' OR '1'='1",
        "1; DROP TABLE--",
        "' UNION SELECT *--",
        "1' AND '1'='1",
        "' OR 1=1--",
    ])

    # Path traversal payloads
    path_traversal_payloads: List[str] = field(default_factory=lambda: [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "/data/data/",
        "../shared_prefs/",
    ])


@dataclass
class DynamicConfig:
    """Main dynamic analysis configuration."""
    # Core settings
    mode: AnalysisMode = AnalysisMode.ACTIVE
    device_type: DeviceType = DeviceType.AUTO
    output_dir: str = "dynamic_results"
    adb_path: str = "adb"

    # Timeouts
    global_timeout: int = 600  # 10 minutes max
    test_timeout: int = 30
    command_timeout: int = 10

    # Feature flags
    use_frida: bool = True
    use_proxy: bool = True
    use_ui_automation: bool = True
    use_verification: bool = True

    # Sub-configurations
    frida: FridaConfig = field(default_factory=FridaConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    ui_automation: UIAutomationConfig = field(default_factory=UIAutomationConfig)
    verification: VerificationConfig = field(default_factory=VerificationConfig)

    # Fallback behavior
    fallback_on_error: bool = True
    continue_on_test_failure: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DynamicConfig':
        """Create config from dictionary."""
        config = cls()

        if 'mode' in data:
            config.mode = AnalysisMode(data['mode'])
        if 'device_type' in data:
            config.device_type = DeviceType(data['device_type'])

        for key in ['output_dir', 'adb_path', 'global_timeout', 'test_timeout',
                    'command_timeout', 'use_frida', 'use_proxy',
                    'use_ui_automation', 'use_verification', 'fallback_on_error',
                    'continue_on_test_failure']:
            if key in data:
                setattr(config, key, data[key])

        if 'frida' in data:
            for key, value in data['frida'].items():
                if hasattr(config.frida, key):
                    setattr(config.frida, key, value)

        if 'proxy' in data:
            for key, value in data['proxy'].items():
                if hasattr(config.proxy, key):
                    setattr(config.proxy, key, value)

        if 'ui_automation' in data:
            for key, value in data['ui_automation'].items():
                if hasattr(config.ui_automation, key):
                    setattr(config.ui_automation, key, value)

        if 'verification' in data:
            for key, value in data['verification'].items():
                if hasattr(config.verification, key):
                    setattr(config.verification, key, value)

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'mode': self.mode.value,
            'device_type': self.device_type.value,
            'output_dir': self.output_dir,
            'adb_path': self.adb_path,
            'global_timeout': self.global_timeout,
            'test_timeout': self.test_timeout,
            'command_timeout': self.command_timeout,
            'use_frida': self.use_frida,
            'use_proxy': self.use_proxy,
            'use_ui_automation': self.use_ui_automation,
            'use_verification': self.use_verification,
            'fallback_on_error': self.fallback_on_error,
            'continue_on_test_failure': self.continue_on_test_failure,
            'frida': {
                'enabled': self.frida.enabled,
                'ssl_bypass': self.frida.ssl_bypass,
                'root_bypass': self.frida.root_bypass,
                'api_monitoring': self.frida.api_monitoring,
            },
            'proxy': {
                'enabled': self.proxy.enabled,
                'port': self.proxy.port,
                'detect_leaks': self.proxy.detect_leaks,
            },
            'ui_automation': {
                'enabled': self.ui_automation.enabled,
                'explore_depth': self.ui_automation.explore_depth,
            },
            'verification': {
                'enabled': self.verification.enabled,
                'timeout_per_test': self.verification.timeout_per_test,
            },
        }


def get_default_config() -> DynamicConfig:
    """Get default dynamic analysis configuration."""
    return DynamicConfig()


def load_config_from_file(path: str) -> DynamicConfig:
    """Load configuration from JSON file."""
    import json
    with open(path, 'r') as f:
        data = json.load(f)
    return DynamicConfig.from_dict(data)


def save_config_to_file(config: DynamicConfig, path: str) -> None:
    """Save configuration to JSON file."""
    import json
    with open(path, 'w') as f:
        json.dump(config.to_dict(), f, indent=2)
