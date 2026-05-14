"""uiautomator2-based device implementation for advanced UI automation."""

import time
import logging
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path

from .base import (
    DeviceInterface, Element, ScreenState, DeviceInfo,
    Bounds, ElementType
)
from ..exceptions import (
    DeviceConnectionError, DeviceNotFoundError, UIAutomationError,
    ElementNotFoundError
)

logger = logging.getLogger(__name__)


# Check for uiautomator2 availability
_U2_AVAILABLE = False
try:
    import uiautomator2 as u2
    _U2_AVAILABLE = True
except ImportError:
    u2 = None


def is_uiautomator2_available() -> bool:
    """Check if uiautomator2 is available."""
    return _U2_AVAILABLE


class UIAutomatorDevice(DeviceInterface):
    """uiautomator2-based device implementation.

    This implementation provides advanced UI automation capabilities
    using the uiautomator2 library. It offers faster and more reliable
    element finding and interaction compared to raw ADB commands.
    """

    def __init__(self, adb_path: str = "adb"):
        if not _U2_AVAILABLE:
            raise ImportError(
                "uiautomator2 is not installed. Install with: pip install uiautomator2"
            )

        self._adb_path = adb_path
        self._device = None
        self._serial: Optional[str] = None
        self._connected = False
        self._device_info: Optional[DeviceInfo] = None
        self._logcat_output_path: Optional[str] = None
        self._logcat_content: List[str] = []

    def connect(self, serial: Optional[str] = None) -> bool:
        """Connect to device using uiautomator2."""
        try:
            if serial:
                self._device = u2.connect(serial)
                self._serial = serial
            else:
                # Connect to first available device
                self._device = u2.connect()
                self._serial = self._device.serial

            # Verify connection
            self._device.info
            self._connected = True
            self._device_info = self._fetch_device_info()

            logger.info(f"Connected to device: {self._serial}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            raise DeviceConnectionError(f"Failed to connect to device: {e}")

    def disconnect(self) -> None:
        """Disconnect from device."""
        self._device = None
        self._connected = False
        self._serial = None

    def is_connected(self) -> bool:
        """Check if device is connected."""
        if not self._connected or not self._device:
            return False
        try:
            self._device.info
            return True
        except Exception:
            self._connected = False
            return False

    def _fetch_device_info(self) -> DeviceInfo:
        """Fetch device information."""
        info = self._device.info

        # Get additional info via shell
        def get_prop(name: str) -> str:
            try:
                return self._device.shell(f"getprop {name}").output.strip()
            except Exception:
                return ""

        # Check if rooted
        is_rooted = False
        try:
            result = self._device.shell("su -c 'echo rooted'")
            is_rooted = "rooted" in result.output.lower()
        except Exception:
            pass

        return DeviceInfo(
            serial=self._serial,
            model=get_prop("ro.product.model"),
            manufacturer=get_prop("ro.product.manufacturer"),
            android_version=get_prop("ro.build.version.release"),
            api_level=int(get_prop("ro.build.version.sdk") or "0"),
            screen_width=info.get("displayWidth", 0),
            screen_height=info.get("displayHeight", 0),
            is_emulator="emulator" in self._serial.lower() if self._serial else False,
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
        try:
            self._device.app_install(apk_path)
            return True
        except Exception as e:
            logger.error(f"Failed to install APK: {e}")
            return False

    def uninstall_app(self, package: str) -> bool:
        """Uninstall application."""
        try:
            self._device.app_uninstall(package)
            return True
        except Exception:
            return False

    def launch_app(self, package: str, activity: Optional[str] = None) -> bool:
        """Launch application."""
        try:
            if activity:
                self._device.app_start(package, activity)
            else:
                self._device.app_start(package)
            return True
        except Exception as e:
            logger.error(f"Failed to launch app: {e}")
            return False

    def stop_app(self, package: str) -> bool:
        """Force stop application."""
        try:
            self._device.app_stop(package)
            return True
        except Exception:
            return False

    def clear_app_data(self, package: str) -> bool:
        """Clear application data."""
        try:
            self._device.app_clear(package)
            return True
        except Exception:
            return False

    def is_app_running(self, package: str) -> bool:
        """Check if app is running."""
        try:
            return package in self._device.app_current().get("package", "")
        except Exception:
            return False

    def get_current_activity(self) -> Tuple[str, str]:
        """Get current foreground activity."""
        try:
            current = self._device.app_current()
            return current.get("package", ""), current.get("activity", "")
        except Exception:
            return "", ""

    # UI operations
    def _u2_element_to_element(self, u2_elem, index: int = 0) -> Element:
        """Convert uiautomator2 element to our Element type."""
        info = u2_elem.info

        bounds = None
        bounds_dict = info.get("bounds", {})
        if bounds_dict:
            bounds = Bounds(
                left=bounds_dict.get("left", 0),
                top=bounds_dict.get("top", 0),
                right=bounds_dict.get("right", 0),
                bottom=bounds_dict.get("bottom", 0)
            )

        class_name = info.get("className", "")
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

        return Element(
            resource_id=info.get("resourceName"),
            text=info.get("text"),
            content_desc=info.get("contentDescription"),
            class_name=class_name,
            package=info.get("packageName"),
            bounds=bounds,
            clickable=info.get("clickable", False),
            scrollable=info.get("scrollable", False),
            checkable=info.get("checkable", False),
            checked=info.get("checked", False),
            enabled=info.get("enabled", True),
            focused=info.get("focused", False),
            selected=info.get("selected", False),
            index=index,
            element_type=element_type,
        )

    def _build_selector(self, **selectors) -> Dict[str, Any]:
        """Build uiautomator2 selector from our selectors."""
        u2_selectors = {}

        mapping = {
            'resourceId': 'resourceId',
            'resource_id': 'resourceId',
            'text': 'text',
            'textContains': 'textContains',
            'textStartsWith': 'textStartsWith',
            'textMatches': 'textMatches',
            'contentDescription': 'description',
            'content_desc': 'description',
            'descriptionContains': 'descriptionContains',
            'className': 'className',
            'class_name': 'className',
            'clickable': 'clickable',
            'scrollable': 'scrollable',
            'enabled': 'enabled',
            'focused': 'focused',
            'selected': 'selected',
            'checkable': 'checkable',
            'checked': 'checked',
            'package': 'packageName',
            'index': 'index',
        }

        for key, value in selectors.items():
            if key in mapping:
                u2_selectors[mapping[key]] = value

        return u2_selectors

    def find_element(self, **selectors) -> Optional[Element]:
        """Find element by selectors."""
        try:
            u2_selectors = self._build_selector(**selectors)
            elem = self._device(**u2_selectors)
            if elem.exists:
                return self._u2_element_to_element(elem)
            return None
        except Exception as e:
            logger.debug(f"Element not found: {e}")
            return None

    def find_elements(self, **selectors) -> List[Element]:
        """Find all elements matching selectors."""
        try:
            u2_selectors = self._build_selector(**selectors)
            elems = self._device(**u2_selectors)
            count = elems.count
            return [self._u2_element_to_element(elems[i], i) for i in range(count)]
        except Exception:
            return []

    def click(self, element: Optional[Element] = None,
              x: Optional[int] = None, y: Optional[int] = None) -> bool:
        """Click on element or coordinates."""
        try:
            if element and element.bounds:
                cx, cy = element.bounds.center
                self._device.click(cx, cy)
            elif x is not None and y is not None:
                self._device.click(x, y)
            else:
                return False
            return True
        except Exception as e:
            logger.error(f"Click failed: {e}")
            return False

    def long_click(self, element: Optional[Element] = None,
                   x: Optional[int] = None, y: Optional[int] = None,
                   duration: float = 1.0) -> bool:
        """Long click on element or coordinates."""
        try:
            if element and element.bounds:
                cx, cy = element.bounds.center
                self._device.long_click(cx, cy, duration)
            elif x is not None and y is not None:
                self._device.long_click(x, y, duration)
            else:
                return False
            return True
        except Exception as e:
            logger.error(f"Long click failed: {e}")
            return False

    def input_text(self, text: str, element: Optional[Element] = None) -> bool:
        """Input text into element or focused field."""
        try:
            if element and element.resource_id:
                self._device(resourceId=element.resource_id).set_text(text)
            elif element and element.bounds:
                self.click(element)
                time.sleep(0.3)
                self._device.send_keys(text)
            else:
                self._device.send_keys(text)
            return True
        except Exception as e:
            logger.error(f"Input text failed: {e}")
            return False

    def clear_text(self, element: Optional[Element] = None) -> bool:
        """Clear text from element."""
        try:
            if element and element.resource_id:
                self._device(resourceId=element.resource_id).clear_text()
            else:
                # Clear by selecting all and deleting
                self._device.press("keycode_ctrl_a")
                self._device.press("keycode_del")
            return True
        except Exception:
            return False

    def scroll(self, direction: str = "down", distance: float = 0.5) -> bool:
        """Scroll screen."""
        try:
            if direction == "down":
                self._device.swipe_ext("up", scale=distance)
            elif direction == "up":
                self._device.swipe_ext("down", scale=distance)
            elif direction == "left":
                self._device.swipe_ext("right", scale=distance)
            elif direction == "right":
                self._device.swipe_ext("left", scale=distance)
            else:
                return False
            return True
        except Exception as e:
            logger.error(f"Scroll failed: {e}")
            return False

    def swipe(self, start_x: int, start_y: int,
              end_x: int, end_y: int, duration: float = 0.5) -> bool:
        """Swipe from start to end coordinates."""
        try:
            self._device.swipe(start_x, start_y, end_x, end_y, duration)
            return True
        except Exception:
            return False

    def press_key(self, keycode: int) -> bool:
        """Press key by keycode."""
        try:
            self._device.press(keycode)
            return True
        except Exception:
            return False

    def press_back(self) -> bool:
        """Press back button."""
        try:
            self._device.press("back")
            return True
        except Exception:
            return False

    def press_home(self) -> bool:
        """Press home button."""
        try:
            self._device.press("home")
            return True
        except Exception:
            return False

    def press_enter(self) -> bool:
        """Press enter key."""
        try:
            self._device.press("enter")
            return True
        except Exception:
            return False

    # Screen state
    def get_screen_state(self) -> ScreenState:
        """Get current screen state."""
        try:
            # Get hierarchy
            hierarchy = self._device.dump_hierarchy()

            # Parse elements from hierarchy
            import xml.etree.ElementTree as ET
            elements = []
            try:
                root = ET.fromstring(hierarchy)
                elements = self._parse_hierarchy_node(root, 0)
            except ET.ParseError:
                pass

            package, activity = self.get_current_activity()

            return ScreenState(
                activity=activity,
                package=package,
                elements=elements,
                hierarchy_xml=hierarchy,
                timestamp=time.time()
            )
        except Exception as e:
            logger.error(f"Failed to get screen state: {e}")
            return ScreenState(
                activity="",
                package="",
                elements=[],
                timestamp=time.time()
            )

    def _parse_hierarchy_node(self, node, index: int) -> List[Element]:
        """Parse XML hierarchy node into Elements."""
        elements = []

        bounds_str = node.get("bounds", "")
        bounds = None
        if bounds_str:
            try:
                bounds = Bounds.from_string(bounds_str)
            except ValueError:
                pass

        class_name = node.get("class", "")
        element_type = ElementType.OTHER
        if "Button" in class_name:
            element_type = ElementType.BUTTON
        elif "EditText" in class_name:
            element_type = ElementType.EDIT_TEXT
        elif "TextView" in class_name:
            element_type = ElementType.TEXT
        elif "WebView" in class_name:
            element_type = ElementType.WEB_VIEW

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

        for i, child in enumerate(node):
            child_elements = self._parse_hierarchy_node(child, i)
            elements.extend(child_elements)

        return elements

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
        try:
            self._device.screenshot(path)
            return True
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return False

    def wait_for_element(self, timeout: float = 10.0, **selectors) -> Optional[Element]:
        """Wait for element to appear."""
        try:
            u2_selectors = self._build_selector(**selectors)
            elem = self._device(**u2_selectors)
            if elem.wait(timeout=timeout):
                return self._u2_element_to_element(elem)
            return None
        except Exception:
            return None

    def wait_for_idle(self, timeout: float = 10.0) -> bool:
        """Wait for UI to become idle."""
        try:
            self._device.wait_activity(timeout=timeout)
            return True
        except Exception:
            return False

    # Shell/ADB
    def execute_shell(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Execute shell command on device."""
        try:
            result = self._device.shell(command, timeout=timeout)
            return True, result.output
        except Exception as e:
            return False, str(e)

    def push_file(self, local_path: str, remote_path: str) -> bool:
        """Push file to device."""
        try:
            self._device.push(local_path, remote_path)
            return True
        except Exception:
            return False

    def pull_file(self, remote_path: str, local_path: str) -> bool:
        """Pull file from device."""
        try:
            self._device.pull(remote_path, local_path)
            return True
        except Exception:
            return False

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

        success, _ = self.execute_shell(cmd)
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

        success, _ = self.execute_shell(cmd)
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

        success, _ = self.execute_shell(cmd)
        return success

    def query_content_provider(self, uri: str,
                               projection: Optional[List[str]] = None,
                               selection: Optional[str] = None) -> Tuple[bool, str]:
        """Query content provider."""
        cmd = f"content query --uri {uri}"

        if projection:
            cmd += f" --projection {':'.join(projection)}"

        if selection:
            cmd += f' --where "{selection}"'

        return self.execute_shell(cmd)

    # Logcat
    def start_logcat(self, output_path: str,
                     package_filter: Optional[str] = None) -> bool:
        """Start capturing logcat."""
        self._logcat_output_path = output_path
        self._logcat_content = []

        # Clear logcat first
        self.execute_shell("logcat -c")

        return True

    def stop_logcat(self) -> str:
        """Stop logcat capture and return captured content."""
        if not self._logcat_output_path:
            return ""

        try:
            # Get logcat content
            success, output = self.execute_shell("logcat -d -v time")
            if success:
                with open(self._logcat_output_path, 'w') as f:
                    f.write(output)
                return output
        except Exception as e:
            logger.error(f"Failed to stop logcat: {e}")

        return ""

    # Network
    def set_proxy(self, host: str, port: int) -> bool:
        """Set HTTP proxy on device."""
        success, _ = self.execute_shell(
            f"settings put global http_proxy {host}:{port}"
        )
        return success

    def clear_proxy(self) -> bool:
        """Clear proxy settings."""
        success, _ = self.execute_shell("settings put global http_proxy :0")
        return success

    # Additional UIAutomator-specific methods
    def watcher_register(self, name: str, **selectors) -> bool:
        """Register a UI watcher to handle dialogs."""
        try:
            u2_selectors = self._build_selector(**selectors)
            self._device.watcher(name).when(**u2_selectors).click()
            return True
        except Exception:
            return False

    def watcher_remove(self, name: str) -> bool:
        """Remove a registered watcher."""
        try:
            self._device.watcher.remove(name)
            return True
        except Exception:
            return False

    def watchers_run(self) -> bool:
        """Run all registered watchers."""
        try:
            self._device.watcher.run()
            return True
        except Exception:
            return False

    def toast_get(self, timeout: float = 3.0) -> Optional[str]:
        """Get toast message if visible."""
        try:
            toast = self._device.toast.get_message(timeout)
            return toast
        except Exception:
            return None
