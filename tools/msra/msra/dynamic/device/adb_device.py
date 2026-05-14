"""Basic ADB-based device implementation (fallback)."""

import subprocess
import time
import re
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path

from .base import (
    DeviceInterface, Element, ScreenState, DeviceInfo,
    Bounds, ElementType
)
from ..exceptions import (
    DeviceConnectionError, DeviceNotFoundError, ADBError,
    AppNotFoundError
)


class ADBDevice(DeviceInterface):
    """ADB-based device implementation.

    This is the fallback implementation that uses only ADB commands.
    It provides basic functionality without UI automation libraries.
    """

    def __init__(self, adb_path: str = "adb"):
        self._adb_path = adb_path
        self._serial: Optional[str] = None
        self._connected = False
        self._logcat_process: Optional[subprocess.Popen] = None
        self._logcat_output_path: Optional[str] = None
        self._device_info: Optional[DeviceInfo] = None

    def _adb(self, *args, timeout: int = 30) -> Tuple[bool, str]:
        """Execute ADB command.

        Args:
            *args: ADB command arguments.
            timeout: Command timeout in seconds.

        Returns:
            Tuple of (success, output).
        """
        cmd = [self._adb_path]
        if self._serial:
            cmd.extend(["-s", self._serial])
        cmd.extend(args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            success = result.returncode == 0
            output = result.stdout if success else result.stderr
            return success, output
        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {timeout}s"
        except Exception as e:
            return False, str(e)

    def _shell(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Execute shell command via ADB."""
        return self._adb("shell", command, timeout=timeout)

    def connect(self, serial: Optional[str] = None) -> bool:
        """Connect to device."""
        # List available devices
        success, output = self._adb("devices", "-l")
        if not success:
            raise DeviceConnectionError(f"Failed to list devices: {output}")

        devices = []
        for line in output.strip().split("\n")[1:]:
            if not line.strip() or "offline" in line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                dev_serial = parts[0]
                model = "unknown"
                for part in parts[2:]:
                    if part.startswith("model:"):
                        model = part.split(":")[1]
                        break
                devices.append((dev_serial, model))

        if not devices:
            raise DeviceNotFoundError("No connected devices found")

        # Select device
        if serial:
            matching = [d for d in devices if d[0] == serial]
            if not matching:
                raise DeviceNotFoundError(f"Device {serial} not found")
            self._serial = serial
        else:
            # Auto-select first device
            self._serial = devices[0][0]

        # Verify connection
        success, _ = self._shell("echo connected")
        if not success:
            raise DeviceConnectionError(f"Failed to connect to {self._serial}")

        self._connected = True
        self._device_info = self._fetch_device_info()
        return True

    def disconnect(self) -> None:
        """Disconnect from device."""
        if self._logcat_process:
            self.stop_logcat()
        self._connected = False
        self._serial = None

    def is_connected(self) -> bool:
        """Check if device is connected."""
        if not self._connected:
            return False
        success, _ = self._shell("echo test", timeout=5)
        return success

    def _fetch_device_info(self) -> DeviceInfo:
        """Fetch device information."""
        def get_prop(name: str) -> str:
            success, output = self._shell(f"getprop {name}")
            return output.strip() if success else ""

        # Get screen size
        width, height = 0, 0
        success, output = self._shell("wm size")
        if success:
            match = re.search(r"(\d+)x(\d+)", output)
            if match:
                width, height = int(match.group(1)), int(match.group(2))

        api_level = 0
        try:
            api_level = int(get_prop("ro.build.version.sdk"))
        except ValueError:
            pass

        is_emulator = (
            "emulator" in self._serial.lower() or
            "vbox" in get_prop("ro.hardware").lower() or
            get_prop("ro.kernel.qemu") == "1"
        )

        is_rooted = False
        success, _ = self._shell("su -c 'echo rooted'")
        if success:
            is_rooted = True

        return DeviceInfo(
            serial=self._serial,
            model=get_prop("ro.product.model"),
            manufacturer=get_prop("ro.product.manufacturer"),
            android_version=get_prop("ro.build.version.release"),
            api_level=api_level,
            screen_width=width,
            screen_height=height,
            is_emulator=is_emulator,
            is_rooted=is_rooted,
            abi=get_prop("ro.product.cpu.abi"),
        )

    def get_device_info(self) -> DeviceInfo:
        """Get device information."""
        if not self._device_info:
            self._device_info = self._fetch_device_info()
        return self._device_info

    # App management
    def install_apk(self, apk_path: str, reinstall: bool = True) -> bool:
        """Install APK on device."""
        args = ["install"]
        if reinstall:
            args.append("-r")
        args.append(apk_path)
        success, output = self._adb(*args, timeout=120)
        return success and "Success" in output

    def uninstall_app(self, package: str) -> bool:
        """Uninstall application."""
        success, _ = self._adb("uninstall", package, timeout=60)
        return success

    def launch_app(self, package: str, activity: Optional[str] = None) -> bool:
        """Launch application."""
        if activity:
            cmd = f"am start -n {package}/{activity}"
        else:
            cmd = f"monkey -p {package} -c android.intent.category.LAUNCHER 1"
        success, _ = self._shell(cmd)
        return success

    def stop_app(self, package: str) -> bool:
        """Force stop application."""
        success, _ = self._shell(f"am force-stop {package}")
        return success

    def clear_app_data(self, package: str) -> bool:
        """Clear application data."""
        success, _ = self._shell(f"pm clear {package}")
        return success

    def is_app_running(self, package: str) -> bool:
        """Check if app is running."""
        success, output = self._shell(f"pidof {package}")
        return success and output.strip() != ""

    def get_current_activity(self) -> Tuple[str, str]:
        """Get current foreground activity."""
        success, output = self._shell("dumpsys activity activities | grep mResumedActivity")
        if success and output.strip():
            match = re.search(r"(\S+)/(\S+)", output)
            if match:
                return match.group(1), match.group(2)
        return "", ""

    # UI operations
    def _parse_ui_hierarchy(self, xml_content: str) -> List[Element]:
        """Parse UI hierarchy XML into Element list."""
        elements = []
        try:
            root = ET.fromstring(xml_content)
            elements = self._parse_node(root, 0)
        except ET.ParseError:
            pass
        return elements

    def _parse_node(self, node: ET.Element, index: int) -> List[Element]:
        """Recursively parse XML node into Elements."""
        elements = []

        # Get node attributes
        bounds_str = node.get("bounds", "")
        bounds = None
        if bounds_str:
            try:
                bounds = Bounds.from_string(bounds_str)
            except ValueError:
                pass

        # Determine element type
        class_name = node.get("class", "")
        element_type = ElementType.OTHER
        if "Button" in class_name:
            element_type = ElementType.BUTTON
        elif "EditText" in class_name:
            element_type = ElementType.EDIT_TEXT
        elif "TextView" in class_name:
            element_type = ElementType.TEXT
        elif "ImageView" in class_name:
            element_type = ElementType.IMAGE
        elif "CheckBox" in class_name:
            element_type = ElementType.CHECKBOX
        elif "Switch" in class_name:
            element_type = ElementType.SWITCH
        elif "WebView" in class_name:
            element_type = ElementType.WEB_VIEW
        elif "ScrollView" in class_name or "RecyclerView" in class_name:
            element_type = ElementType.SCROLL_VIEW

        element = Element(
            resource_id=node.get("resource-id"),
            text=node.get("text"),
            content_desc=node.get("content-desc"),
            class_name=class_name,
            package=node.get("package"),
            bounds=bounds,
            clickable=node.get("clickable", "false").lower() == "true",
            scrollable=node.get("scrollable", "false").lower() == "true",
            checkable=node.get("checkable", "false").lower() == "true",
            checked=node.get("checked", "false").lower() == "true",
            enabled=node.get("enabled", "true").lower() == "true",
            focused=node.get("focused", "false").lower() == "true",
            selected=node.get("selected", "false").lower() == "true",
            index=index,
            element_type=element_type,
        )
        elements.append(element)

        # Parse children
        for i, child in enumerate(node):
            child_elements = self._parse_node(child, i)
            elements.extend(child_elements)

        return elements

    def find_element(self, **selectors) -> Optional[Element]:
        """Find element by selectors."""
        state = self.get_screen_state()
        return state.find_element(**selectors)

    def find_elements(self, **selectors) -> List[Element]:
        """Find all elements matching selectors."""
        state = self.get_screen_state()
        return state.find_elements(**selectors)

    def click(self, element: Optional[Element] = None,
              x: Optional[int] = None, y: Optional[int] = None) -> bool:
        """Click on element or coordinates."""
        if element and element.bounds:
            cx, cy = element.bounds.center
        elif x is not None and y is not None:
            cx, cy = x, y
        else:
            return False

        success, _ = self._shell(f"input tap {cx} {cy}")
        return success

    def long_click(self, element: Optional[Element] = None,
                   x: Optional[int] = None, y: Optional[int] = None,
                   duration: float = 1.0) -> bool:
        """Long click on element or coordinates."""
        if element and element.bounds:
            cx, cy = element.bounds.center
        elif x is not None and y is not None:
            cx, cy = x, y
        else:
            return False

        duration_ms = int(duration * 1000)
        success, _ = self._shell(f"input swipe {cx} {cy} {cx} {cy} {duration_ms}")
        return success

    def input_text(self, text: str, element: Optional[Element] = None) -> bool:
        """Input text into element or focused field."""
        if element:
            self.click(element)
            time.sleep(0.3)

        # Escape special characters
        escaped = text.replace("'", "'\\''").replace(" ", "%s")
        success, _ = self._shell(f"input text '{escaped}'")
        return success

    def clear_text(self, element: Optional[Element] = None) -> bool:
        """Clear text from element."""
        if element:
            self.click(element)
            time.sleep(0.2)

        # Select all and delete
        self._shell("input keyevent KEYCODE_CTRL_LEFT KEYCODE_A")
        success, _ = self._shell("input keyevent KEYCODE_DEL")
        return success

    def scroll(self, direction: str = "down", distance: float = 0.5) -> bool:
        """Scroll screen."""
        info = self.get_device_info()
        w, h = info.screen_width, info.screen_height
        center_x = w // 2
        center_y = h // 2
        scroll_dist = int(h * distance * 0.4)

        if direction == "down":
            start_y = center_y + scroll_dist
            end_y = center_y - scroll_dist
        elif direction == "up":
            start_y = center_y - scroll_dist
            end_y = center_y + scroll_dist
        elif direction == "left":
            return self.swipe(w - 100, center_y, 100, center_y)
        elif direction == "right":
            return self.swipe(100, center_y, w - 100, center_y)
        else:
            return False

        return self.swipe(center_x, start_y, center_x, end_y)

    def swipe(self, start_x: int, start_y: int,
              end_x: int, end_y: int, duration: float = 0.5) -> bool:
        """Swipe from start to end coordinates."""
        duration_ms = int(duration * 1000)
        success, _ = self._shell(
            f"input swipe {start_x} {start_y} {end_x} {end_y} {duration_ms}"
        )
        return success

    def press_key(self, keycode: int) -> bool:
        """Press key by keycode."""
        success, _ = self._shell(f"input keyevent {keycode}")
        return success

    # Screen state
    def get_screen_state(self) -> ScreenState:
        """Get current screen state."""
        # Get UI hierarchy
        success, xml_output = self._shell("uiautomator dump /dev/tty")
        hierarchy_xml = ""
        if success:
            # Extract XML content
            start = xml_output.find("<?xml")
            end = xml_output.rfind(">") + 1
            if start != -1 and end > start:
                hierarchy_xml = xml_output[start:end]

        elements = self._parse_ui_hierarchy(hierarchy_xml) if hierarchy_xml else []
        package, activity = self.get_current_activity()

        return ScreenState(
            activity=activity,
            package=package,
            elements=elements,
            hierarchy_xml=hierarchy_xml,
            timestamp=time.time()
        )

    def get_screen_hierarchy(self) -> Dict[str, Any]:
        """Get screen hierarchy as dictionary."""
        state = self.get_screen_state()
        return {
            "activity": state.activity,
            "package": state.package,
            "elements": len(state.elements),
            "clickables": len(state.clickables),
            "inputs": len(state.input_fields),
        }

    def take_screenshot(self, path: str) -> bool:
        """Take screenshot and save to path."""
        remote_path = "/data/local/tmp/screenshot.png"
        success, _ = self._shell(f"screencap -p {remote_path}")
        if success:
            success, _ = self._adb("pull", remote_path, path)
            self._shell(f"rm {remote_path}")
        return success

    def wait_for_element(self, timeout: float = 10.0, **selectors) -> Optional[Element]:
        """Wait for element to appear."""
        start = time.time()
        while time.time() - start < timeout:
            element = self.find_element(**selectors)
            if element:
                return element
            time.sleep(0.5)
        return None

    def wait_for_idle(self, timeout: float = 10.0) -> bool:
        """Wait for UI to become idle."""
        # ADB doesn't have a good way to detect idle
        # Just wait a short time
        time.sleep(min(timeout, 2.0))
        return True

    # Shell/ADB
    def execute_shell(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Execute shell command on device."""
        return self._shell(command, timeout=timeout)

    def push_file(self, local_path: str, remote_path: str) -> bool:
        """Push file to device."""
        success, _ = self._adb("push", local_path, remote_path)
        return success

    def pull_file(self, remote_path: str, local_path: str) -> bool:
        """Pull file from device."""
        success, _ = self._adb("pull", remote_path, local_path)
        return success

    # Intent operations
    def start_activity(self, package: str, activity: str,
                       extras: Optional[Dict[str, Any]] = None,
                       flags: Optional[List[str]] = None,
                       data_uri: Optional[str] = None) -> bool:
        """Start activity with intent."""
        cmd = f"am start -n {package}/{activity}"

        if data_uri:
            cmd += f" -d '{data_uri}'"

        if flags:
            for flag in flags:
                cmd += f" -f {flag}"

        if extras:
            for key, value in extras.items():
                if isinstance(value, bool):
                    cmd += f" --ez {key} {str(value).lower()}"
                elif isinstance(value, int):
                    cmd += f" --ei {key} {value}"
                elif isinstance(value, float):
                    cmd += f" --ef {key} {value}"
                else:
                    cmd += f" --es {key} '{value}'"

        success, _ = self._shell(cmd)
        return success

    def send_broadcast(self, action: str, package: Optional[str] = None,
                       extras: Optional[Dict[str, Any]] = None) -> bool:
        """Send broadcast intent."""
        cmd = f"am broadcast -a {action}"

        if package:
            cmd += f" -p {package}"

        if extras:
            for key, value in extras.items():
                if isinstance(value, bool):
                    cmd += f" --ez {key} {str(value).lower()}"
                elif isinstance(value, int):
                    cmd += f" --ei {key} {value}"
                else:
                    cmd += f" --es {key} '{value}'"

        success, _ = self._shell(cmd)
        return success

    def start_service(self, package: str, service: str,
                      extras: Optional[Dict[str, Any]] = None) -> bool:
        """Start service."""
        cmd = f"am startservice -n {package}/{service}"

        if extras:
            for key, value in extras.items():
                if isinstance(value, str):
                    cmd += f" --es {key} '{value}'"
                elif isinstance(value, int):
                    cmd += f" --ei {key} {value}"

        success, _ = self._shell(cmd)
        return success

    def query_content_provider(self, uri: str,
                               projection: Optional[List[str]] = None,
                               selection: Optional[str] = None) -> Tuple[bool, str]:
        """Query content provider."""
        cmd = f"content query --uri {uri}"

        if projection:
            cmd += f" --projection {':'.join(projection)}"

        if selection:
            cmd += f" --where \"{selection}\""

        return self._shell(cmd)

    # Logcat
    def start_logcat(self, output_path: str,
                     package_filter: Optional[str] = None) -> bool:
        """Start capturing logcat."""
        if self._logcat_process:
            self.stop_logcat()

        cmd = [self._adb_path]
        if self._serial:
            cmd.extend(["-s", self._serial])
        cmd.extend(["logcat", "-v", "time"])

        if package_filter:
            # Get PID for filtering
            success, output = self._shell(f"pidof {package_filter}")
            if success and output.strip():
                pid = output.strip()
                cmd.extend(["--pid", pid])

        try:
            self._logcat_output_path = output_path
            with open(output_path, 'w') as f:
                self._logcat_process = subprocess.Popen(
                    cmd,
                    stdout=f,
                    stderr=subprocess.STDOUT
                )
            return True
        except Exception:
            return False

    def stop_logcat(self) -> str:
        """Stop logcat capture and return captured content."""
        content = ""
        if self._logcat_process:
            self._logcat_process.terminate()
            try:
                self._logcat_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._logcat_process.kill()
            self._logcat_process = None

        if self._logcat_output_path and Path(self._logcat_output_path).exists():
            with open(self._logcat_output_path, 'r') as f:
                content = f.read()

        return content

    # Network
    def set_proxy(self, host: str, port: int) -> bool:
        """Set HTTP proxy on device."""
        success, _ = self._shell(
            f"settings put global http_proxy {host}:{port}"
        )
        return success

    def clear_proxy(self) -> bool:
        """Clear proxy settings."""
        success, _ = self._shell("settings put global http_proxy :0")
        return success
