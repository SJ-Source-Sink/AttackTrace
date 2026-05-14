"""Device abstraction layer for dynamic analysis."""

from .base import DeviceInterface, Element, ScreenState, Bounds, DeviceInfo
from .adb_device import ADBDevice
from .factory import create_device, detect_best_device, DevicePool

# UIAutomatorDevice is optional (requires uiautomator2)
try:
    from .uiautomator_device import UIAutomatorDevice
except ImportError:
    UIAutomatorDevice = None

__all__ = [
    'DeviceInterface',
    'Element',
    'ScreenState',
    'Bounds',
    'DeviceInfo',
    'ADBDevice',
    'UIAutomatorDevice',
    'create_device',
    'detect_best_device',
    'DevicePool',
]
