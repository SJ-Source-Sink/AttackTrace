"""Device factory for auto-detection and creation."""

import logging
import subprocess
from typing import Optional, List, Tuple

from .base import DeviceInterface, DeviceInfo
from .adb_device import ADBDevice
from .uiautomator_device import UIAutomatorDevice, is_uiautomator2_available
from ..config import DeviceType
from ..exceptions import DeviceNotFoundError, DeviceConnectionError

logger = logging.getLogger(__name__)


def list_connected_devices(adb_path: str = "adb") -> List[Tuple[str, str, bool]]:
    """List all connected devices.

    Returns:
        List of tuples: (serial, model, is_emulator)
    """
    try:
        result = subprocess.run(
            [adb_path, "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=10
        )

        devices = []
        for line in result.stdout.strip().split("\n")[1:]:
            if not line.strip() or "offline" in line:
                continue

            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                serial = parts[0]
                model = "unknown"
                for part in parts[2:]:
                    if part.startswith("model:"):
                        model = part.split(":")[1]
                        break

                is_emulator = (
                    "emulator" in serial.lower() or
                    "vbox" in serial.lower()
                )
                devices.append((serial, model, is_emulator))

        return devices

    except Exception as e:
        logger.error(f"Failed to list devices: {e}")
        return []


def detect_best_device(adb_path: str = "adb") -> Tuple[Optional[str], DeviceType]:
    """Detect the best available device and connection type.

    Prioritizes:
    1. uiautomator2 if available
    2. Genymotion/emulators over physical devices

    Returns:
        Tuple of (device_serial, device_type)
    """
    devices = list_connected_devices(adb_path)

    if not devices:
        return None, DeviceType.ADB_ONLY

    # Prefer emulators for testing
    emulators = [d for d in devices if d[2]]
    physical = [d for d in devices if not d[2]]

    selected = emulators[0] if emulators else physical[0]
    serial = selected[0]

    # Check if uiautomator2 is available
    if is_uiautomator2_available():
        return serial, DeviceType.UIAUTOMATOR
    else:
        return serial, DeviceType.ADB_ONLY


def create_device(
    serial: Optional[str] = None,
    device_type: DeviceType = DeviceType.AUTO,
    adb_path: str = "adb"
) -> DeviceInterface:
    """Create appropriate device instance.

    Args:
        serial: Device serial. Auto-selects if None.
        device_type: Preferred device type. AUTO will detect.
        adb_path: Path to ADB executable.

    Returns:
        Connected DeviceInterface instance.

    Raises:
        DeviceNotFoundError: No devices available.
        DeviceConnectionError: Failed to connect.
    """
    # Auto-detect if needed
    if device_type == DeviceType.AUTO:
        detected_serial, detected_type = detect_best_device(adb_path)

        if not detected_serial:
            raise DeviceNotFoundError("No connected devices found")

        if not serial:
            serial = detected_serial
        device_type = detected_type

        logger.info(f"Auto-detected device: {serial} ({device_type.value})")

    # Create device instance
    if device_type == DeviceType.UIAUTOMATOR and is_uiautomator2_available():
        try:
            device = UIAutomatorDevice(adb_path=adb_path)
            device.connect(serial)
            logger.info(f"Connected via uiautomator2: {serial}")
            return device
        except ImportError:
            logger.warning("uiautomator2 not available, falling back to ADB")
            device_type = DeviceType.ADB_ONLY
        except Exception as e:
            logger.warning(f"uiautomator2 connection failed: {e}, falling back to ADB")
            device_type = DeviceType.ADB_ONLY

    # Fallback to ADB
    if device_type == DeviceType.ADB_ONLY or device_type == DeviceType.UIAUTOMATOR:
        device = ADBDevice(adb_path=adb_path)
        device.connect(serial)
        logger.info(f"Connected via ADB: {serial}")
        return device

    raise DeviceConnectionError(f"Unknown device type: {device_type}")


def get_device_with_fallback(
    serial: Optional[str] = None,
    prefer_uiautomator: bool = True,
    adb_path: str = "adb"
) -> DeviceInterface:
    """Get device with automatic fallback.

    Tries uiautomator2 first if available and preferred,
    falls back to ADB if connection fails.

    Args:
        serial: Device serial. Auto-selects if None.
        prefer_uiautomator: Try uiautomator2 first.
        adb_path: Path to ADB executable.

    Returns:
        Connected DeviceInterface instance.
    """
    if prefer_uiautomator and is_uiautomator2_available():
        try:
            device = UIAutomatorDevice(adb_path=adb_path)
            device.connect(serial)
            return device
        except Exception as e:
            logger.warning(f"uiautomator2 failed ({e}), trying ADB")

    # Fallback to ADB
    device = ADBDevice(adb_path=adb_path)
    device.connect(serial)
    return device


class DevicePool:
    """Pool of connected devices for parallel testing."""

    def __init__(self, adb_path: str = "adb"):
        self._adb_path = adb_path
        self._devices: List[DeviceInterface] = []
        self._in_use: List[bool] = []

    def connect_all(self) -> int:
        """Connect to all available devices.

        Returns:
            Number of connected devices.
        """
        devices = list_connected_devices(self._adb_path)

        for serial, model, _ in devices:
            try:
                device = create_device(
                    serial=serial,
                    device_type=DeviceType.AUTO,
                    adb_path=self._adb_path
                )
                self._devices.append(device)
                self._in_use.append(False)
                logger.info(f"Added device to pool: {serial} ({model})")
            except Exception as e:
                logger.warning(f"Failed to connect to {serial}: {e}")

        return len(self._devices)

    def acquire(self) -> Optional[DeviceInterface]:
        """Acquire an available device from pool.

        Returns:
            Device instance or None if none available.
        """
        for i, in_use in enumerate(self._in_use):
            if not in_use:
                self._in_use[i] = True
                return self._devices[i]
        return None

    def release(self, device: DeviceInterface) -> None:
        """Release device back to pool."""
        for i, d in enumerate(self._devices):
            if d is device:
                self._in_use[i] = False
                return

    def disconnect_all(self) -> None:
        """Disconnect all devices."""
        for device in self._devices:
            try:
                device.disconnect()
            except Exception:
                pass
        self._devices.clear()
        self._in_use.clear()

    @property
    def available_count(self) -> int:
        """Number of available devices."""
        return sum(1 for in_use in self._in_use if not in_use)

    @property
    def total_count(self) -> int:
        """Total number of devices in pool."""
        return len(self._devices)


def check_device_capabilities(device: DeviceInterface) -> dict:
    """Check what capabilities a device has.

    Returns:
        Dict of capability -> bool.
    """
    capabilities = {
        "connected": device.is_connected(),
        "ui_automation": isinstance(device, UIAutomatorDevice),
        "rooted": False,
        "frida_server": False,
        "tcpdump": False,
    }

    if capabilities["connected"]:
        info = device.get_device_info()
        capabilities["rooted"] = info.is_rooted

        # Check for frida-server
        success, output = device.execute_shell("ls /data/local/tmp/frida-server")
        capabilities["frida_server"] = success and "frida-server" in output

        # Check for tcpdump
        success, _ = device.execute_shell("which tcpdump")
        capabilities["tcpdump"] = success

    return capabilities
