"""
USB Device Validation Utilities

Centralized validation and sanitization for USB device data.
Used by both rules manager and device extraction.

Security notes:
- All sanitization functions are designed to be safe against injection attacks
- Serial numbers and keys use a restricted character set to prevent shell/code injection
- Functions strip invalid characters rather than rejecting input (defensive approach)
"""

import logging
import re
from datetime import datetime
from typing import Literal, Optional

logger = logging.getLogger(__name__)

Verdict = Literal['allow', 'block']
Scope = Literal['device', 'model', 'vendor']

# Character sets for sanitization
# Serial: alphanumeric plus safe punctuation (no quotes, spaces, or shell metacharacters)
SERIAL_SAFE_CHARS = re.compile(r'[^0-9A-Za-z._-]')
# Hex ID: only hex digits
HEX_CHARS = re.compile(r'[^0-9a-fA-F]')
# Key pattern for validation (matches sanitized keys only)
KEY_PATTERN = re.compile(
    r'^[0-9a-f]{4}:[0-9a-f]{4}:[A-Za-z0-9._-]+$|'  # device: vid:pid:serial
    r'^[0-9a-f]{4}:[0-9a-f]{4}:\*$|'                # model: vid:pid:*
    r'^[0-9a-f]{4}:\*:\*$'                          # vendor: vid:*:*
)


class USBValidation:
    """
    Centralized USB validation and sanitization.

    All methods are designed to:
    - Never raise exceptions (return safe defaults)
    - Strip/replace invalid characters rather than rejecting
    - Log warnings when input is modified
    """

    # Maximum lengths
    MAX_SERIAL_LEN = 128
    MAX_STRING_LEN = 256
    MAX_KEY_LEN = 256

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
        Always returns a valid 4-character lowercase hex string.
        """
        if not isinstance(hex_id, str):
            hex_id = str(hex_id) if hex_id is not None else ''
        clean = HEX_CHARS.sub('', hex_id)[:4].lower()
        return clean.zfill(4) if clean else '0000'

    @staticmethod
    def sanitize_serial(serial: Optional[str], max_len: int = 128) -> str:
        """
        Sanitize USB device serial number.

        Uses a strict character set to prevent injection attacks:
        - Only alphanumeric characters, dots, dashes, and underscores
        - No spaces, quotes, or shell metacharacters
        - Limited length

        Args:
            serial: The raw serial number from the device
            max_len: Maximum allowed length (default 128)

        Returns:
            Sanitized serial, or 'no-serial' if empty/None
        """
        if serial is None or not isinstance(serial, str):
            return 'no-serial'

        # Strip dangerous characters (keep only safe set)
        original = serial
        clean = SERIAL_SAFE_CHARS.sub('', serial)

        # Limit length
        clean = clean[:min(max_len, USBValidation.MAX_SERIAL_LEN)]

        # Log if we modified the serial (could indicate attack or unusual device)
        if clean != original and original:
            logger.debug(f"Sanitized serial: '{original[:20]}...' -> '{clean[:20]}...'")

        return clean if clean else 'no-serial'

    @staticmethod
    def sanitize_string(value: str, max_len: int = 256) -> str:
        """
        Sanitize general string (names, descriptions).

        Removes control characters but keeps spaces and most punctuation.
        For user-facing strings only, not for keys or identifiers.

        Args:
            value: The string to sanitize
            max_len: Maximum allowed length

        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            value = str(value) if value is not None else ''
        # Remove control characters except space
        clean = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
        return clean[:min(max_len, USBValidation.MAX_STRING_LEN)]

    @staticmethod
    def sanitize_key(key: str) -> Optional[str]:
        """
        Sanitize and validate a USB rule key.

        Keys have the format:
        - Device: vendor_id:product_id:serial (e.g., '046d:c52b:ABC123')
        - Model: vendor_id:product_id:* (e.g., '046d:c52b:*')
        - Vendor: vendor_id:*:* (e.g., '046d:*:*')

        Args:
            key: The raw key to validate

        Returns:
            Sanitized key if valid format, None if invalid
        """
        if not key or not isinstance(key, str):
            return None

        if len(key) > USBValidation.MAX_KEY_LEN:
            logger.warning(f"Key too long: {len(key)} chars")
            return None

        # Try to parse and reconstruct the key
        parts = key.split(':')

        if len(parts) == 2:
            # Old format: vid:pid (model scope) - convert to vid:pid:*
            vendor_id = USBValidation.sanitize_hex_id(parts[0])
            product_id = USBValidation.sanitize_hex_id(parts[1])
            return f"{vendor_id}:{product_id}:*"

        elif len(parts) == 3:
            vendor_id = USBValidation.sanitize_hex_id(parts[0])

            # Handle vendor scope (vid:*:*)
            if parts[1] == '*' and parts[2] == '*':
                return f"{vendor_id}:*:*"

            product_id = USBValidation.sanitize_hex_id(parts[1])

            # Handle model scope (vid:pid:*)
            if parts[2] == '*':
                return f"{vendor_id}:{product_id}:*"

            # Device scope: sanitize serial
            serial = USBValidation.sanitize_serial(parts[2])
            return f"{vendor_id}:{product_id}:{serial}"

        else:
            logger.warning(f"Invalid key format: {key[:50]}")
            return None

    @staticmethod
    def validate_key(key: str) -> bool:
        """
        Validate that a key matches the expected format.

        This is a strict check - returns False for any deviation.
        Use sanitize_key() to fix/normalize keys.

        Args:
            key: The key to validate

        Returns:
            True if key is valid, False otherwise
        """
        if not key or not isinstance(key, str):
            return False
        if len(key) > USBValidation.MAX_KEY_LEN:
            return False
        return KEY_PATTERN.match(key) is not None

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

