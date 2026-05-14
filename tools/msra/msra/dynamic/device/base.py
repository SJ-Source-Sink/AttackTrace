"""Abstract base class for device interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum


class ElementType(Enum):
    """Type of UI element."""
    BUTTON = "button"
    TEXT = "text"
    EDIT_TEXT = "edit_text"
    IMAGE = "image"
    CHECKBOX = "checkbox"
    SWITCH = "switch"
    LIST_ITEM = "list_item"
    SCROLL_VIEW = "scroll_view"
    WEB_VIEW = "webview"
    OTHER = "other"


@dataclass
class Bounds:
    """Element bounds on screen."""
    left: int
    top: int
    right: int
    bottom: int

    @property
    def center(self) -> Tuple[int, int]:
        """Get center point of bounds."""
        return ((self.left + self.right) // 2, (self.top + self.bottom) // 2)

    @property
    def width(self) -> int:
        """Get width."""
        return self.right - self.left

    @property
    def height(self) -> int:
        """Get height."""
        return self.bottom - self.top

    @classmethod
    def from_string(cls, bounds_str: str) -> 'Bounds':
        """Parse bounds from '[left,top][right,bottom]' format."""
        import re
        match = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
        if match:
            return cls(
                int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)),
                int(match.group(4))
            )
        raise ValueError(f"Invalid bounds format: {bounds_str}")


@dataclass
class Element:
    """Represents a UI element on the device screen."""
    resource_id: Optional[str] = None
    text: Optional[str] = None
    content_desc: Optional[str] = None
    class_name: Optional[str] = None
    package: Optional[str] = None
    bounds: Optional[Bounds] = None
    clickable: bool = False
    scrollable: bool = False
    checkable: bool = False
    checked: bool = False
    enabled: bool = True
    focused: bool = False
    selected: bool = False
    index: int = 0
    element_type: ElementType = ElementType.OTHER
    children: List['Element'] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def identifier(self) -> str:
        """Get best available identifier for this element."""
        if self.resource_id:
            return f"id:{self.resource_id}"
        if self.content_desc:
            return f"desc:{self.content_desc}"
        if self.text:
            return f"text:{self.text[:30]}"
        if self.class_name:
            return f"class:{self.class_name}"
        return f"index:{self.index}"

    def matches(self, **selectors) -> bool:
        """Check if element matches given selectors."""
        for key, value in selectors.items():
            if key == 'resourceId' or key == 'resource_id':
                if self.resource_id != value and not (value in (self.resource_id or '')):
                    return False
            elif key == 'text':
                if self.text != value and value not in (self.text or ''):
                    return False
            elif key == 'textContains':
                if value not in (self.text or ''):
                    return False
            elif key == 'contentDescription' or key == 'content_desc':
                if self.content_desc != value and value not in (self.content_desc or ''):
                    return False
            elif key == 'className' or key == 'class_name':
                if self.class_name != value:
                    return False
            elif key == 'clickable':
                if self.clickable != value:
                    return False
            elif key == 'scrollable':
                if self.scrollable != value:
                    return False
            elif key == 'enabled':
                if self.enabled != value:
                    return False
            elif key == 'package':
                if self.package != value:
                    return False
        return True


@dataclass
class ScreenState:
    """Represents the current screen state."""
    activity: str
    package: str
    elements: List[Element]
    hierarchy_xml: Optional[str] = None
    screenshot_path: Optional[str] = None
    timestamp: Optional[float] = None

    @property
    def clickables(self) -> List[Element]:
        """Get all clickable elements."""
        return [e for e in self.elements if e.clickable]

    @property
    def input_fields(self) -> List[Element]:
        """Get all input fields."""
        return [e for e in self.elements
                if e.class_name and 'EditText' in e.class_name]

    @property
    def webviews(self) -> List[Element]:
        """Get all WebView elements."""
        return [e for e in self.elements
                if e.class_name and 'WebView' in e.class_name]

    def find_element(self, **selectors) -> Optional[Element]:
        """Find first element matching selectors."""
        for element in self.elements:
            if element.matches(**selectors):
                return element
        return None

    def find_elements(self, **selectors) -> List[Element]:
        """Find all elements matching selectors."""
        return [e for e in self.elements if e.matches(**selectors)]


@dataclass
class DeviceInfo:
    """Device information."""
    serial: str
    model: str
    manufacturer: str = ""
    android_version: str = ""
    api_level: int = 0
    screen_width: int = 0
    screen_height: int = 0
    is_emulator: bool = False
    is_rooted: bool = False
    abi: str = ""
    properties: Dict[str, str] = field(default_factory=dict)


class DeviceInterface(ABC):
    """Abstract interface for device operations."""

    @abstractmethod
    def connect(self, serial: Optional[str] = None) -> bool:
        """Connect to device.

        Args:
            serial: Device serial number. If None, auto-select.

        Returns:
            True if connected successfully.
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from device."""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if device is connected."""
        pass

    @abstractmethod
    def get_device_info(self) -> DeviceInfo:
        """Get device information."""
        pass

    # App management
    @abstractmethod
    def install_apk(self, apk_path: str, reinstall: bool = True) -> bool:
        """Install APK on device.

        Args:
            apk_path: Path to APK file.
            reinstall: If True, reinstall if already installed.

        Returns:
            True if installed successfully.
        """
        pass

    @abstractmethod
    def uninstall_app(self, package: str) -> bool:
        """Uninstall application."""
        pass

    @abstractmethod
    def launch_app(self, package: str, activity: Optional[str] = None) -> bool:
        """Launch application.

        Args:
            package: Package name.
            activity: Activity to launch. If None, launch default.

        Returns:
            True if launched successfully.
        """
        pass

    @abstractmethod
    def stop_app(self, package: str) -> bool:
        """Force stop application."""
        pass

    @abstractmethod
    def clear_app_data(self, package: str) -> bool:
        """Clear application data."""
        pass

    @abstractmethod
    def is_app_running(self, package: str) -> bool:
        """Check if app is running."""
        pass

    @abstractmethod
    def get_current_activity(self) -> Tuple[str, str]:
        """Get current foreground activity.

        Returns:
            Tuple of (package_name, activity_name).
        """
        pass

    # UI operations
    @abstractmethod
    def find_element(self, **selectors) -> Optional[Element]:
        """Find element by selectors.

        Args:
            **selectors: Element selectors (resourceId, text, className, etc.)

        Returns:
            Element if found, None otherwise.
        """
        pass

    @abstractmethod
    def find_elements(self, **selectors) -> List[Element]:
        """Find all elements matching selectors."""
        pass

    @abstractmethod
    def click(self, element: Optional[Element] = None,
              x: Optional[int] = None, y: Optional[int] = None) -> bool:
        """Click on element or coordinates.

        Args:
            element: Element to click.
            x, y: Coordinates to click (if element not provided).

        Returns:
            True if clicked successfully.
        """
        pass

    @abstractmethod
    def long_click(self, element: Optional[Element] = None,
                   x: Optional[int] = None, y: Optional[int] = None,
                   duration: float = 1.0) -> bool:
        """Long click on element or coordinates."""
        pass

    @abstractmethod
    def input_text(self, text: str, element: Optional[Element] = None) -> bool:
        """Input text into element or focused field.

        Args:
            text: Text to input.
            element: Target element. If None, use currently focused.

        Returns:
            True if text entered successfully.
        """
        pass

    @abstractmethod
    def clear_text(self, element: Optional[Element] = None) -> bool:
        """Clear text from element or focused field."""
        pass

    @abstractmethod
    def scroll(self, direction: str = "down", distance: float = 0.5) -> bool:
        """Scroll screen.

        Args:
            direction: 'up', 'down', 'left', 'right'.
            distance: Scroll distance as fraction of screen (0.0-1.0).

        Returns:
            True if scrolled successfully.
        """
        pass

    @abstractmethod
    def swipe(self, start_x: int, start_y: int,
              end_x: int, end_y: int, duration: float = 0.5) -> bool:
        """Swipe from start to end coordinates."""
        pass

    @abstractmethod
    def press_key(self, keycode: int) -> bool:
        """Press key by keycode."""
        pass

    def press_back(self) -> bool:
        """Press back button."""
        return self.press_key(4)  # KEYCODE_BACK

    def press_home(self) -> bool:
        """Press home button."""
        return self.press_key(3)  # KEYCODE_HOME

    def press_enter(self) -> bool:
        """Press enter key."""
        return self.press_key(66)  # KEYCODE_ENTER

    # Screen state
    @abstractmethod
    def get_screen_state(self) -> ScreenState:
        """Get current screen state including all elements."""
        pass

    @abstractmethod
    def get_screen_hierarchy(self) -> Dict[str, Any]:
        """Get screen hierarchy as dictionary."""
        pass

    @abstractmethod
    def take_screenshot(self, path: str) -> bool:
        """Take screenshot and save to path."""
        pass

    @abstractmethod
    def wait_for_element(self, timeout: float = 10.0, **selectors) -> Optional[Element]:
        """Wait for element to appear.

        Args:
            timeout: Maximum wait time in seconds.
            **selectors: Element selectors.

        Returns:
            Element if found within timeout, None otherwise.
        """
        pass

    @abstractmethod
    def wait_for_idle(self, timeout: float = 10.0) -> bool:
        """Wait for UI to become idle."""
        pass

    # Shell/ADB
    @abstractmethod
    def execute_shell(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Execute shell command on device.

        Args:
            command: Shell command to execute.
            timeout: Command timeout in seconds.

        Returns:
            Tuple of (success, output).
        """
        pass

    @abstractmethod
    def push_file(self, local_path: str, remote_path: str) -> bool:
        """Push file to device."""
        pass

    @abstractmethod
    def pull_file(self, remote_path: str, local_path: str) -> bool:
        """Pull file from device."""
        pass

    # Intent operations
    @abstractmethod
    def start_activity(self, package: str, activity: str,
                       extras: Optional[Dict[str, Any]] = None,
                       flags: Optional[List[str]] = None,
                       data_uri: Optional[str] = None) -> bool:
        """Start activity with intent.

        Args:
            package: Target package.
            activity: Activity class name.
            extras: Intent extras.
            flags: Intent flags.
            data_uri: Data URI.

        Returns:
            True if started successfully.
        """
        pass

    @abstractmethod
    def send_broadcast(self, action: str, package: Optional[str] = None,
                       extras: Optional[Dict[str, Any]] = None) -> bool:
        """Send broadcast intent."""
        pass

    @abstractmethod
    def start_service(self, package: str, service: str,
                      extras: Optional[Dict[str, Any]] = None) -> bool:
        """Start service."""
        pass

    @abstractmethod
    def query_content_provider(self, uri: str,
                               projection: Optional[List[str]] = None,
                               selection: Optional[str] = None) -> Tuple[bool, str]:
        """Query content provider.

        Args:
            uri: Content URI.
            projection: Columns to return.
            selection: WHERE clause.

        Returns:
            Tuple of (success, output).
        """
        pass

    # Logcat
    @abstractmethod
    def start_logcat(self, output_path: str,
                     package_filter: Optional[str] = None) -> bool:
        """Start capturing logcat."""
        pass

    @abstractmethod
    def stop_logcat(self) -> str:
        """Stop logcat capture and return captured content."""
        pass

    # Network
    @abstractmethod
    def set_proxy(self, host: str, port: int) -> bool:
        """Set HTTP proxy on device."""
        pass

    @abstractmethod
    def clear_proxy(self) -> bool:
        """Clear proxy settings."""
        pass

    # Convenience methods (can be overridden)
    def open_url(self, url: str) -> bool:
        """Open URL in browser."""
        return self.start_activity(
            package="com.android.browser",
            activity="com.android.browser.BrowserActivity",
            data_uri=url
        )

    def open_deep_link(self, uri: str) -> bool:
        """Open deep link."""
        success, _ = self.execute_shell(
            f'am start -a android.intent.action.VIEW -d "{uri}"'
        )
        return success

    def get_installed_packages(self) -> List[str]:
        """Get list of installed packages."""
        success, output = self.execute_shell("pm list packages")
        if success:
            return [line.replace("package:", "").strip()
                    for line in output.strip().split("\n")
                    if line.startswith("package:")]
        return []

    def is_package_installed(self, package: str) -> bool:
        """Check if package is installed."""
        return package in self.get_installed_packages()

    def get_app_pid(self, package: str) -> Optional[int]:
        """Get PID of running app."""
        success, output = self.execute_shell(f"pidof {package}")
        if success and output.strip():
            try:
                return int(output.strip().split()[0])
            except (ValueError, IndexError):
                pass
        return None
