"""Frida instrumentation module for runtime hooking."""

from .frida_manager import FridaManager, HookResult, is_frida_available
from .script_runner import ScriptRunner, ScriptResult

__all__ = [
    'FridaManager',
    'HookResult',
    'is_frida_available',
    'ScriptRunner',
    'ScriptResult',
]
