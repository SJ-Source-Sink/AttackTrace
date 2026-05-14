"""Advanced element finding utilities."""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable
from enum import Enum

from ..device.base import DeviceInterface, Element, ScreenState, ElementType

logger = logging.getLogger(__name__)


class SelectorType(Enum):
    """Type of element selector."""
    RESOURCE_ID = "resource_id"
    TEXT = "text"
    TEXT_CONTAINS = "text_contains"
    TEXT_REGEX = "text_regex"
    CONTENT_DESC = "content_desc"
    CLASS_NAME = "class_name"
    XPATH = "xpath"
    COMPOUND = "compound"


@dataclass
class ElementSelector:
    """Flexible element selector."""
    selector_type: SelectorType
    value: Any
    parent: Optional['ElementSelector'] = None
    child: Optional['ElementSelector'] = None
    sibling: Optional['ElementSelector'] = None
    index: int = 0  # For multiple matches

    @classmethod
    def by_id(cls, resource_id: str) -> 'ElementSelector':
        """Create selector by resource ID."""
        return cls(SelectorType.RESOURCE_ID, resource_id)

    @classmethod
    def by_text(cls, text: str, exact: bool = True) -> 'ElementSelector':
        """Create selector by text."""
        if exact:
            return cls(SelectorType.TEXT, text)
        return cls(SelectorType.TEXT_CONTAINS, text)

    @classmethod
    def by_text_regex(cls, pattern: str) -> 'ElementSelector':
        """Create selector by text regex pattern."""
        return cls(SelectorType.TEXT_REGEX, pattern)

    @classmethod
    def by_content_desc(cls, desc: str) -> 'ElementSelector':
        """Create selector by content description."""
        return cls(SelectorType.CONTENT_DESC, desc)

    @classmethod
    def by_class(cls, class_name: str) -> 'ElementSelector':
        """Create selector by class name."""
        return cls(SelectorType.CLASS_NAME, class_name)

    @classmethod
    def compound(cls, **selectors) -> 'ElementSelector':
        """Create compound selector with multiple criteria."""
        return cls(SelectorType.COMPOUND, selectors)

    def child_of(self, parent: 'ElementSelector') -> 'ElementSelector':
        """Add parent constraint."""
        self.parent = parent
        return self

    def with_child(self, child: 'ElementSelector') -> 'ElementSelector':
        """Add child constraint."""
        self.child = child
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for device.find_element()."""
        if self.selector_type == SelectorType.RESOURCE_ID:
            return {"resourceId": self.value}
        elif self.selector_type == SelectorType.TEXT:
            return {"text": self.value}
        elif self.selector_type == SelectorType.TEXT_CONTAINS:
            return {"textContains": self.value}
        elif self.selector_type == SelectorType.CONTENT_DESC:
            return {"contentDescription": self.value}
        elif self.selector_type == SelectorType.CLASS_NAME:
            return {"className": self.value}
        elif self.selector_type == SelectorType.COMPOUND:
            return self.value
        return {}


class ElementFinder:
    """Advanced element finding with smart matching."""

    # Common dialog button patterns
    DIALOG_BUTTONS = {
        "ok": ["OK", "Ok", "ok", "Okay", "Got it", "GOT IT"],
        "cancel": ["Cancel", "CANCEL", "No", "NO", "Dismiss"],
        "allow": ["Allow", "ALLOW", "Yes", "YES", "Accept", "ACCEPT"],
        "deny": ["Deny", "DENY", "Don't Allow", "Reject", "REJECT"],
        "continue": ["Continue", "CONTINUE", "Next", "NEXT", "Proceed"],
        "skip": ["Skip", "SKIP", "Later", "LATER", "Not Now"],
        "close": ["Close", "CLOSE", "X", "×"],
    }

    # Common input field patterns
    INPUT_FIELD_PATTERNS = {
        "username": [r"user.*name", r"login", r"email", r"phone"],
        "password": [r"pass.*word", r"pwd", r"secret"],
        "email": [r"email", r"e-mail", r"mail"],
        "phone": [r"phone", r"mobile", r"cell"],
        "name": [r"^name$", r"full.*name", r"first.*name", r"last.*name"],
        "search": [r"search", r"find", r"query"],
        "url": [r"url", r"link", r"address"],
    }

    def __init__(self, device: DeviceInterface):
        self._device = device

    def find(self, selector: ElementSelector, timeout: float = 0) -> Optional[Element]:
        """Find element using selector.

        Args:
            selector: Element selector.
            timeout: Wait timeout (0 for no wait).

        Returns:
            Element if found, None otherwise.
        """
        selectors = selector.to_dict()

        if timeout > 0:
            return self._device.wait_for_element(timeout=timeout, **selectors)
        return self._device.find_element(**selectors)

    def find_all(self, selector: ElementSelector) -> List[Element]:
        """Find all elements matching selector."""
        selectors = selector.to_dict()
        return self._device.find_elements(**selectors)

    def find_by_id(self, resource_id: str, timeout: float = 0) -> Optional[Element]:
        """Find element by resource ID."""
        selector = ElementSelector.by_id(resource_id)
        return self.find(selector, timeout)

    def find_by_text(self, text: str, exact: bool = True,
                     timeout: float = 0) -> Optional[Element]:
        """Find element by text."""
        selector = ElementSelector.by_text(text, exact)
        return self.find(selector, timeout)

    def find_by_text_regex(self, pattern: str) -> List[Element]:
        """Find elements matching text regex pattern."""
        state = self._device.get_screen_state()
        regex = re.compile(pattern, re.IGNORECASE)
        return [e for e in state.elements if e.text and regex.search(e.text)]

    def find_clickable(self) -> List[Element]:
        """Find all clickable elements."""
        return self._device.find_elements(clickable=True)

    def find_input_fields(self) -> List[Element]:
        """Find all input fields."""
        return self._device.find_elements(className="android.widget.EditText")

    def find_webviews(self) -> List[Element]:
        """Find all WebView elements."""
        webviews = self._device.find_elements(className="android.webkit.WebView")
        # Also check for custom WebViews
        state = self._device.get_screen_state()
        for elem in state.elements:
            if elem.class_name and "WebView" in elem.class_name:
                if elem not in webviews:
                    webviews.append(elem)
        return webviews

    def find_buttons(self) -> List[Element]:
        """Find all button elements."""
        buttons = self._device.find_elements(className="android.widget.Button")

        # Also find clickable TextViews and ImageViews that act as buttons
        state = self._device.get_screen_state()
        for elem in state.elements:
            if elem.clickable and elem not in buttons:
                if elem.class_name and any(cls in elem.class_name
                                           for cls in ["TextView", "ImageView", "ImageButton"]):
                    buttons.append(elem)

        return buttons

    def find_dialog_button(self, button_type: str) -> Optional[Element]:
        """Find common dialog button by type.

        Args:
            button_type: One of 'ok', 'cancel', 'allow', 'deny', 'continue', 'skip', 'close'.

        Returns:
            Button element if found.
        """
        patterns = self.DIALOG_BUTTONS.get(button_type.lower(), [])

        for text in patterns:
            elem = self.find_by_text(text)
            if elem and elem.clickable:
                return elem

        return None

    def find_input_by_type(self, input_type: str) -> Optional[Element]:
        """Find input field by semantic type.

        Args:
            input_type: One of 'username', 'password', 'email', 'phone', etc.

        Returns:
            Input element if found.
        """
        patterns = self.INPUT_FIELD_PATTERNS.get(input_type.lower(), [])
        state = self._device.get_screen_state()

        for elem in state.input_fields:
            # Check resource ID
            if elem.resource_id:
                for pattern in patterns:
                    if re.search(pattern, elem.resource_id, re.IGNORECASE):
                        return elem

            # Check content description
            if elem.content_desc:
                for pattern in patterns:
                    if re.search(pattern, elem.content_desc, re.IGNORECASE):
                        return elem

            # Check hint text
            if elem.text:
                for pattern in patterns:
                    if re.search(pattern, elem.text, re.IGNORECASE):
                        return elem

        return None

    def find_by_position(self, region: str) -> List[Element]:
        """Find elements in screen region.

        Args:
            region: 'top', 'bottom', 'left', 'right', 'center'.

        Returns:
            Elements in that region.
        """
        info = self._device.get_device_info()
        w, h = info.screen_width, info.screen_height
        state = self._device.get_screen_state()

        matches = []
        for elem in state.elements:
            if not elem.bounds:
                continue

            cx, cy = elem.bounds.center

            if region == "top" and cy < h // 3:
                matches.append(elem)
            elif region == "bottom" and cy > 2 * h // 3:
                matches.append(elem)
            elif region == "left" and cx < w // 3:
                matches.append(elem)
            elif region == "right" and cx > 2 * w // 3:
                matches.append(elem)
            elif region == "center":
                if w // 3 < cx < 2 * w // 3 and h // 3 < cy < 2 * h // 3:
                    matches.append(elem)

        return matches

    def find_near(self, anchor: Element, direction: str = "below",
                  max_distance: int = 200) -> List[Element]:
        """Find elements near an anchor element.

        Args:
            anchor: Reference element.
            direction: 'above', 'below', 'left', 'right'.
            max_distance: Maximum distance in pixels.

        Returns:
            Nearby elements.
        """
        if not anchor.bounds:
            return []

        state = self._device.get_screen_state()
        matches = []
        ax, ay = anchor.bounds.center

        for elem in state.elements:
            if elem is anchor or not elem.bounds:
                continue

            ex, ey = elem.bounds.center
            dx = ex - ax
            dy = ey - ay

            if direction == "below" and 0 < dy < max_distance and abs(dx) < max_distance:
                matches.append((dy, elem))
            elif direction == "above" and -max_distance < dy < 0 and abs(dx) < max_distance:
                matches.append((-dy, elem))
            elif direction == "right" and 0 < dx < max_distance and abs(dy) < max_distance:
                matches.append((dx, elem))
            elif direction == "left" and -max_distance < dx < 0 and abs(dy) < max_distance:
                matches.append((-dx, elem))

        # Sort by distance
        matches.sort(key=lambda x: x[0])
        return [elem for _, elem in matches]

    def find_scrollable(self) -> List[Element]:
        """Find scrollable containers."""
        return self._device.find_elements(scrollable=True)

    def find_visible_text(self, min_length: int = 1) -> List[str]:
        """Get all visible text on screen.

        Args:
            min_length: Minimum text length to include.

        Returns:
            List of visible text strings.
        """
        state = self._device.get_screen_state()
        texts = []

        for elem in state.elements:
            if elem.text and len(elem.text) >= min_length:
                texts.append(elem.text)
            if elem.content_desc and len(elem.content_desc) >= min_length:
                texts.append(elem.content_desc)

        return texts

    def wait_for_any(self, selectors: List[ElementSelector],
                     timeout: float = 10.0) -> Optional[Element]:
        """Wait for any of the selectors to match.

        Returns the first matching element.
        """
        import time
        start = time.time()

        while time.time() - start < timeout:
            for selector in selectors:
                elem = self.find(selector)
                if elem:
                    return elem
            time.sleep(0.5)

        return None

    def wait_for_text(self, text: str, timeout: float = 10.0) -> bool:
        """Wait for text to appear on screen."""
        elem = self.find_by_text(text, exact=False, timeout=timeout)
        return elem is not None

    def has_element(self, selector: ElementSelector) -> bool:
        """Check if element exists."""
        return self.find(selector) is not None

    def count(self, selector: ElementSelector) -> int:
        """Count matching elements."""
        return len(self.find_all(selector))
