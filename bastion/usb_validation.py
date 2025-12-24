"""
USB Device Validation Utilities

Centralized validation and sanitization for USB device data.
Used by both rules manager and device extraction.
"""

import re
from datetime import datetime
from typing import Literal

Verdict = Literal['allow', 'block']
Scope = Literal['device', 'model', 'vendor']


class USBValidation:
    """Centralized USB validation and sanitization."""

    @staticmethod
    def validate_verdict(value: str) -> Verdict:
        """Validate verdict is 'allow' or 'block'."""
        return 'allow' if value == 'allow' else 'block'

    @staticmethod
    def validate_scope(value: str) -> Scope:
        """Validate scope is 'device', 'model', or 'vendor'."""
        if value in ('device', 'model', 'vendor'):
            return value
        return 'device'

    @staticmethod
    def sanitize_hex_id(hex_id: str) -> str:
        """
        Sanitize vendor/product ID (4 hex chars only).

        Removes non-hex characters, limits to 4 chars, pads with zeros.
        """
        clean = re.sub(r'[^0-9a-fA-F]', '', str(hex_id))[:4].lower()
        return clean.zfill(4) if clean else '0000'

    @staticmethod
    def sanitize_string(value: str, max_len: int = 128) -> str:
        """
        Sanitize general string (names, serial).

        Removes control characters, limits length.
        """
        if not isinstance(value, str):
            value = str(value)
        # Remove control characters except space
        clean = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
        return clean[:max_len]

    @staticmethod
    def sanitize_timestamp(ts: str) -> str:
        """
        Validate/sanitize ISO timestamp.

        Returns valid ISO timestamp or current time if invalid.
        """
        try:
            datetime.fromisoformat(ts)
            return ts
        except (ValueError, TypeError):
            return datetime.now().isoformat()

