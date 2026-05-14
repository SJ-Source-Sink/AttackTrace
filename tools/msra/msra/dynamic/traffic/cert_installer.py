"""CA certificate installation for traffic interception."""

import os
import logging
import hashlib
from typing import Optional

from ..device.base import DeviceInterface
from ..exceptions import CertInstallError

logger = logging.getLogger(__name__)


class CertInstaller:
    """Install CA certificates on Android devices for MITM."""

    def __init__(self, device: DeviceInterface):
        self._device = device

    def install_ca_cert(self, cert_path: str) -> bool:
        """Install CA certificate on device.

        For Android < 7 (API < 24): User CA store
        For Android >= 7 (API >= 24): Requires root for system CA store

        Args:
            cert_path: Path to CA certificate file.

        Returns:
            True if installed successfully.
        """
        if not os.path.exists(cert_path):
            raise CertInstallError(f"Certificate not found: {cert_path}")

        device_info = self._device.get_device_info()
        api_level = device_info.api_level

        if api_level < 24:
            return self._install_user_cert(cert_path)
        elif device_info.is_rooted:
            return self._install_system_cert(cert_path)
        else:
            logger.warning(
                f"Device API {api_level} requires root for system CA. "
                "Traffic may not be decrypted for apps with Network Security Config."
            )
            return self._install_user_cert(cert_path)

    def _install_user_cert(self, cert_path: str) -> bool:
        """Install certificate in user CA store."""
        try:
            # Push cert to device
            remote_path = "/sdcard/Download/mitmproxy-ca-cert.crt"
            self._device.push_file(cert_path, remote_path)

            # Trigger certificate installation UI
            # User needs to manually approve
            success, _ = self._device.execute_shell(
                f'am start -a android.settings.SECURITY_SETTINGS'
            )

            logger.info(
                f"Certificate pushed to {remote_path}. "
                "User must manually install via Settings > Security > Install from storage"
            )

            return success

        except Exception as e:
            logger.error(f"Failed to install user cert: {e}")
            return False

    def _install_system_cert(self, cert_path: str) -> bool:
        """Install certificate in system CA store (requires root)."""
        try:
            # Convert PEM to Android system format
            cert_hash = self._get_cert_hash(cert_path)
            system_cert_name = f"{cert_hash}.0"
            remote_path = f"/system/etc/security/cacerts/{system_cert_name}"

            # Remount /system as rw
            self._device.execute_shell("mount -o rw,remount /system")

            # Push certificate
            self._device.push_file(cert_path, remote_path)

            # Set permissions
            self._device.execute_shell(f"chmod 644 {remote_path}")
            self._device.execute_shell(f"chown root:root {remote_path}")

            # Remount as ro
            self._device.execute_shell("mount -o ro,remount /system")

            logger.info(f"System CA installed: {system_cert_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to install system cert: {e}")
            return False

    def _get_cert_hash(self, cert_path: str) -> str:
        """Get certificate hash for Android system CA naming."""
        try:
            import subprocess
            result = subprocess.run(
                ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", cert_path],
                capture_output=True,
                text=True
            )
            return result.stdout.strip().split('\n')[0]
        except Exception:
            # Fallback: use file hash
            with open(cert_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()[:8]

    def is_cert_installed(self, cert_path: str) -> bool:
        """Check if certificate is already installed."""
        cert_hash = self._get_cert_hash(cert_path)

        # Check system store
        success, output = self._device.execute_shell(
            f"ls /system/etc/security/cacerts/ | grep {cert_hash}"
        )
        if success and cert_hash in output:
            return True

        # Check user store
        success, output = self._device.execute_shell(
            f"ls /data/misc/user/0/cacerts-added/ 2>/dev/null | grep {cert_hash}"
        )
        if success and cert_hash in output:
            return True

        return False

    def remove_cert(self, cert_path: str) -> bool:
        """Remove installed certificate."""
        cert_hash = self._get_cert_hash(cert_path)
        system_cert_path = f"/system/etc/security/cacerts/{cert_hash}.0"
        user_cert_path = f"/data/misc/user/0/cacerts-added/{cert_hash}.0"

        removed = False

        # Try system store (requires root)
        device_info = self._device.get_device_info()
        if device_info.is_rooted:
            self._device.execute_shell("mount -o rw,remount /system")
            success, _ = self._device.execute_shell(f"rm {system_cert_path}")
            self._device.execute_shell("mount -o ro,remount /system")
            removed = removed or success

        # Try user store
        success, _ = self._device.execute_shell(f"rm {user_cert_path}")
        removed = removed or success

        return removed

    def setup_for_interception(self, proxy_manager) -> bool:
        """Setup device for traffic interception.

        Args:
            proxy_manager: ProxyManager instance.

        Returns:
            True if setup successful.
        """
        # Get CA certificate
        ca_path = proxy_manager.get_ca_cert_path()
        if not ca_path:
            logger.error("mitmproxy CA certificate not found")
            return False

        # Check if already installed
        if self.is_cert_installed(ca_path):
            logger.info("CA certificate already installed")
            return True

        # Install certificate
        return self.install_ca_cert(ca_path)

    def get_trust_status(self) -> dict:
        """Get certificate trust status on device."""
        status = {
            "api_level": 0,
            "is_rooted": False,
            "system_certs": 0,
            "user_certs": 0,
            "can_intercept_all": False,
            "notes": [],
        }

        device_info = self._device.get_device_info()
        status["api_level"] = device_info.api_level
        status["is_rooted"] = device_info.is_rooted

        # Count system certs
        success, output = self._device.execute_shell(
            "ls /system/etc/security/cacerts/ | wc -l"
        )
        if success:
            try:
                status["system_certs"] = int(output.strip())
            except ValueError:
                pass

        # Count user certs
        success, output = self._device.execute_shell(
            "ls /data/misc/user/0/cacerts-added/ 2>/dev/null | wc -l"
        )
        if success:
            try:
                status["user_certs"] = int(output.strip())
            except ValueError:
                pass

        # Determine interception capability
        if device_info.api_level < 24:
            status["can_intercept_all"] = True
            status["notes"].append("Pre-Nougat: User CA trusted by all apps")
        elif device_info.is_rooted:
            status["can_intercept_all"] = True
            status["notes"].append("Rooted: Can install system CA")
        else:
            status["can_intercept_all"] = False
            status["notes"].append(
                "Android 7+: Apps with Network Security Config may not trust user CAs"
            )
            status["notes"].append(
                "Use Frida SSL bypass for complete interception"
            )

        return status
