"""Intent vulnerability verifier."""

import time
import logging
from typing import Dict, Any, List, Optional

from .base import BaseVerifier, VerificationResult, VerificationStatus

logger = logging.getLogger(__name__)


class IntentVerifier(BaseVerifier):
    """Verify Intent-related vulnerabilities including hijacking and injection."""

    CATEGORY = "intent"

    # Sensitive intent actions
    SENSITIVE_ACTIONS = [
        "android.intent.action.VIEW",
        "android.intent.action.SEND",
        "android.intent.action.SENDTO",
        "android.intent.action.DIAL",
        "android.intent.action.CALL",
        "android.intent.action.INSTALL_PACKAGE",
        "android.intent.action.UNINSTALL_PACKAGE",
    ]

    def can_verify(self, finding: Dict[str, Any]) -> bool:
        """Check if this is an Intent-related finding."""
        fid = finding.get('fid', '').lower()
        category = finding.get('category', '').lower()
        title = finding.get('title', '').lower()

        return (
            'intent' in fid or
            'intent' in category or
            'exported' in fid or
            'activity' in fid or
            'service' in fid or
            'receiver' in fid or
            'broadcast' in fid or
            'implicit' in fid or
            'redirect' in fid or
            'hijack' in fid
        )

    def verify(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify Intent vulnerability."""
        finding_id = self._extract_finding_id(finding)
        start_time = time.time()

        fid = finding.get('fid', '').lower()

        try:
            if 'redirect' in fid or 'hijack' in fid:
                result = self._verify_intent_redirect(finding)
            elif 'exported' in fid and 'activity' in fid:
                result = self._verify_exported_activity(finding)
            elif 'exported' in fid and 'service' in fid:
                result = self._verify_exported_service(finding)
            elif 'exported' in fid and ('receiver' in fid or 'broadcast' in fid):
                result = self._verify_exported_receiver(finding)
            elif 'implicit' in fid:
                result = self._verify_implicit_intent(finding)
            elif 'pending' in fid:
                result = self._verify_pending_intent(finding)
            else:
                result = self._verify_generic_intent(finding)

            result.duration = time.time() - start_time
            return result

        except Exception as e:
            logger.error(f"Intent verification failed: {e}")
            return self._create_result(
                finding_id,
                VerificationStatus.ERROR,
                error_message=str(e),
                duration=time.time() - start_time
            )

    def _verify_intent_redirect(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify Intent redirect/hijacking vulnerability."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        package = self._get_package(finding)
        extra = finding.get('extra', {})
        activity = extra.get('activity') or extra.get('component')

        if not package or not activity:
            result.notes = "Missing package or activity information"
            return result

        # Setup Frida monitoring if available
        if self._frida and self._frida.is_attached():
            # Monitor intent operations
            code = """
            Java.perform(function() {
                var Activity = Java.use("android.app.Activity");
                Activity.setResult.overload("int", "android.content.Intent").implementation = function(code, data) {
                    send({
                        class: "Activity",
                        method: "setResult",
                        args: [code],
                        extra: {
                            data: data ? data.getDataString() : null,
                            action: data ? data.getAction() : null,
                            type: "intent_result"
                        }
                    });
                    return this.setResult(code, data);
                };
            });
            """
            self._frida.load_script("intent_redirect_monitor", code)

        # Test intent redirect by sending controlled intent
        test_uri = "http://attacker.controlled.com/redirect"

        success = self._device.start_activity(
            package, activity,
            data_uri=test_uri,
            extras={"redirect_url": test_uri, "next_url": test_uri, "url": test_uri}
        )

        if success:
            time.sleep(2)

            # Check if app is still in foreground or redirected
            current_pkg, current_act = self._device.get_current_activity()

            if current_pkg != package:
                result.status = VerificationStatus.VERIFIED
                result.confidence = 0.85
                result.add_evidence(
                    "behavior",
                    f"App redirected to: {current_pkg}/{current_act}",
                    severity="high"
                )
                screenshot = self.take_screenshot("intent_redirect")
                if screenshot:
                    result.add_evidence("screenshot", "Redirect screenshot", screenshot)
                return result

            # Check Frida hooks
            if self._frida:
                hooks = self._frida.get_hook_results("intent_redirect_monitor")
                if hooks:
                    result.status = VerificationStatus.LIKELY
                    result.confidence = 0.7
                    result.hook_results = hooks
                    result.add_evidence(
                        "hook",
                        "setResult called with external data",
                        severity="high"
                    )

        return result

    def _verify_exported_activity(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify exported activity can be launched."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        package = self._get_package(finding)
        extra = finding.get('extra', {})
        activity = extra.get('activity') or extra.get('component')

        if not package or not activity:
            result.notes = "Missing package or activity information"
            return result

        # Ensure activity has full path
        if not activity.startswith(package):
            if activity.startswith('.'):
                activity = package + activity
            else:
                activity = f"{package}.{activity}"

        # Try to launch the activity
        success = self._device.start_activity(package, activity)

        if success:
            time.sleep(1.5)

            # Check if activity launched
            current_pkg, current_act = self._device.get_current_activity()

            if current_pkg == package:
                result.status = VerificationStatus.VERIFIED
                result.confidence = 0.9
                result.add_evidence(
                    "behavior",
                    f"Exported activity accessible: {activity}",
                    severity="medium"
                )

                screenshot = self.take_screenshot("exported_activity")
                if screenshot:
                    result.add_evidence("screenshot", "Activity screenshot", screenshot)

                # Check for sensitive data on screen
                state = self._device.get_screen_state()
                sensitive_indicators = ['password', 'token', 'admin', 'settings', 'debug']

                for elem in state.elements:
                    if elem.text:
                        text_lower = elem.text.lower()
                        if any(ind in text_lower for ind in sensitive_indicators):
                            result.confidence = 0.95
                            result.add_evidence(
                                "data",
                                f"Sensitive UI element found: {elem.text[:50]}",
                                severity="high"
                            )
                            break

                return result

        # Try with intent filter actions
        for action in ["android.intent.action.VIEW", "android.intent.action.MAIN"]:
            cmd = f'am start -a {action} -n {package}/{activity}'
            success, output = self._device.execute_shell(cmd)

            if success and 'error' not in output.lower():
                result.status = VerificationStatus.VERIFIED
                result.confidence = 0.8
                result.add_evidence(
                    "command",
                    f"Activity launched via action: {action}",
                    severity="medium"
                )
                break

        return result

    def _verify_exported_service(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify exported service can be started."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        package = self._get_package(finding)
        extra = finding.get('extra', {})
        service = extra.get('service') or extra.get('component')

        if not package or not service:
            result.notes = "Missing package or service information"
            return result

        # Ensure service has full path
        if not service.startswith(package):
            if service.startswith('.'):
                service = package + service
            else:
                service = f"{package}.{service}"

        # Try to start the service
        success = self._device.start_service(package, service)

        if success:
            time.sleep(1)

            # Check if service is running
            cmd = f"dumpsys activity services {package}"
            success, output = self._device.execute_shell(cmd)

            if success and service in output:
                result.status = VerificationStatus.VERIFIED
                result.confidence = 0.85
                result.add_evidence(
                    "behavior",
                    f"Exported service started: {service}",
                    severity="high"
                )
                return result

        # Check ADB commands from finding
        adb_commands = finding.get('adb_commands', [])
        for cmd in adb_commands:
            if 'startservice' in cmd.lower() or 'am start' in cmd.lower():
                success, output = self.execute_adb_command(cmd)
                if success:
                    result.status = VerificationStatus.LIKELY
                    result.confidence = 0.6
                    result.add_evidence(
                        "command",
                        f"Service command executed",
                        data=output[:200],
                        severity="medium"
                    )

        return result

    def _verify_exported_receiver(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify exported broadcast receiver can receive broadcasts."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        package = self._get_package(finding)
        extra = finding.get('extra', {})
        receiver = extra.get('receiver') or extra.get('component')
        actions = extra.get('actions', [])

        if not package:
            result.notes = "Missing package information"
            return result

        # Try to send broadcasts
        if actions:
            for action in actions[:3]:  # Test first 3 actions
                success = self._device.send_broadcast(action, package)

                if success:
                    time.sleep(0.5)

                    # Check logcat for receiver activity
                    logcat = self.get_logcat_excerpt(package, 20)
                    if receiver and receiver in logcat:
                        result.status = VerificationStatus.VERIFIED
                        result.confidence = 0.8
                        result.add_evidence(
                            "logcat",
                            f"Receiver triggered by action: {action}",
                            data=logcat[:300],
                            severity="medium"
                        )
                        return result

        # Try common broadcast actions
        common_actions = [
            "android.intent.action.BOOT_COMPLETED",
            "android.net.conn.CONNECTIVITY_CHANGE",
            f"{package}.ACTION_TEST",
        ]

        for action in common_actions:
            cmd = f"am broadcast -a {action} -p {package}"
            success, output = self._device.execute_shell(cmd)

            if success and 'broadcast' in output.lower():
                result.status = VerificationStatus.LIKELY
                result.confidence = 0.5
                result.add_evidence(
                    "command",
                    f"Broadcast sent: {action}",
                    data=output[:200],
                    severity="low"
                )

        return result

    def _verify_implicit_intent(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify implicit intent vulnerability."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(
            finding_id,
            VerificationStatus.LIKELY,
            confidence=0.6
        )

        # Implicit intents are inherently risky for sensitive actions
        extra = finding.get('extra', {})
        action = extra.get('action', '')

        if action in self.SENSITIVE_ACTIONS:
            result.status = VerificationStatus.VERIFIED
            result.confidence = 0.8
            result.add_evidence(
                "static",
                f"Sensitive action uses implicit intent: {action}",
                severity="high"
            )
        else:
            result.add_evidence(
                "static",
                "Implicit intent detected in code",
                severity="medium"
            )

        return result

    def _verify_pending_intent(self, finding: Dict[str, Any]) -> VerificationResult:
        """Verify PendingIntent vulnerability."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(
            finding_id,
            VerificationStatus.LIKELY,
            confidence=0.5
        )

        extra = finding.get('extra', {})

        # Check for mutable PendingIntent (Android 12+ vulnerability)
        if extra.get('is_mutable'):
            result.status = VerificationStatus.VERIFIED
            result.confidence = 0.85
            result.add_evidence(
                "static",
                "Mutable PendingIntent detected (FLAG_MUTABLE without FLAG_IMMUTABLE)",
                severity="high"
            )

        # Check for implicit base intent
        if extra.get('implicit_base'):
            result.confidence = min(1.0, result.confidence + 0.2)
            result.add_evidence(
                "static",
                "PendingIntent uses implicit base intent",
                severity="high"
            )

        return result

    def _verify_generic_intent(self, finding: Dict[str, Any]) -> VerificationResult:
        """Generic Intent verification."""
        finding_id = self._extract_finding_id(finding)
        result = self._create_result(finding_id, VerificationStatus.NOT_VULNERABLE)

        # Execute any ADB commands from the finding
        adb_commands = finding.get('adb_commands', [])
        for cmd in adb_commands:
            success, output = self.execute_adb_command(cmd)
            if success:
                result.status = VerificationStatus.POSSIBLE
                result.confidence = 0.4
                result.add_evidence(
                    "command",
                    f"Command executed: {cmd[:50]}",
                    data=output[:300],
                    severity="medium"
                )

        return result
