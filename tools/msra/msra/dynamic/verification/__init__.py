"""Exploit verification module for dynamic analysis."""

from typing import Dict, Any, Optional, TYPE_CHECKING

from .base import BaseVerifier, VerificationResult, VerificationStatus, Evidence
from .webview import WebViewVerifier
from .provider import ProviderVerifier
from .intent import IntentVerifier
from .deeplink import DeepLinkVerifier

if TYPE_CHECKING:
    from ..device.base import DeviceInterface
    from ..instrumentation import FridaManager


# Verifier registry
_VERIFIERS = [
    WebViewVerifier,
    ProviderVerifier,
    IntentVerifier,
    DeepLinkVerifier,
]


def get_verifier_for_finding(
    finding: Dict[str, Any],
    device: Optional['DeviceInterface'] = None,
    frida: Optional['FridaManager'] = None,
    output_dir: str = "./output",
) -> Optional[BaseVerifier]:
    """Get appropriate verifier for a finding.

    Args:
        finding: Finding dictionary from static analysis
        device: Device interface
        frida: Frida manager (optional)
        output_dir: Output directory for screenshots

    Returns:
        Appropriate verifier instance or None
    """
    for verifier_class in _VERIFIERS:
        try:
            verifier = verifier_class(
                device=device,
                frida=frida,
                output_dir=output_dir,
            )
            if verifier.can_verify(finding):
                return verifier
        except Exception:
            continue

    return None


__all__ = [
    'BaseVerifier',
    'VerificationResult',
    'VerificationStatus',
    'Evidence',
    'WebViewVerifier',
    'ProviderVerifier',
    'IntentVerifier',
    'DeepLinkVerifier',
    'get_verifier_for_finding',
]
