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
        """
        Normalize a verdict string to either 'allow' or 'block'.
        
        Returns:
            'allow' if the input is exactly 'allow', 'block' otherwise.
        """
        return 'allow' if value == 'allow' else 'block'

    @staticmethod
    def validate_scope(value: str) -> Scope:
        """
        Ensure the scope is one of 'device', 'model', or 'vendor'.
        
        Returns:
        	scope (Scope): The original value if it is 'device', 'model', or 'vendor'; otherwise 'device'.
        """
        if value in ('device', 'model', 'vendor'):
            return value
        return 'device'

    @staticmethod
    def sanitize_hex_id(hex_id: str) -> str:
        """
        Normalize a vendor or product hexadecimal identifier to a 4-character lowercase hex string.
        
        Strips any non-hex characters, truncates to at most four characters, and pads with leading zeros. Treats None as empty input and converts non-string inputs to strings.
        
        Parameters:
            hex_id (str): Vendor or product identifier to normalize; may be non-string and will be converted.
        
        Returns:
            str: A 4-character lowercase hexadecimal string (for example, "00af"). If input yields no hex digits, returns "0000".
        """
        if not isinstance(hex_id, str):
            hex_id = str(hex_id) if hex_id is not None else ''
        clean = HEX_CHARS.sub('', hex_id)[:4].lower()
        return clean.zfill(4) if clean else '0000'

    @staticmethod
    def sanitize_serial(serial: Optional[str], max_len: int = 128) -> str:
        """
        Sanitize a USB device serial number.
        
        Removes characters except letters, digits, dot (.), underscore (_) and dash (-), truncates the result to at most `max_len` (bounded by the module maximum), and logs when a modification occurs. If `serial` is None or the sanitized result is empty, returns 'no-serial'.
        
        Parameters:
            serial (Optional[str]): Raw serial number to sanitize.
            max_len (int): Maximum allowed length for the returned serial.
        
        Returns:
            str: The sanitized serial, or 'no-serial' if input is None or empty after sanitization.
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
        Normalize a user-facing string by removing control characters and enforcing length limits.
        
        Accepts non-string inputs (converted to string); removes Unicode control characters except space and returns the result truncated to at most `max_len` and `USBValidation.MAX_STRING_LEN`.
        
        Parameters:
            value: The value to sanitize; non-strings are converted to a string (None becomes '').
            max_len: Maximum number of characters to keep (subject to a global maximum).
        
        Returns:
            The sanitized string with control characters removed (spaces preserved) and length constrained.
        """
        if not isinstance(value, str):
            value = str(value) if value is not None else ''
        # Remove control characters except space
        clean = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
        return clean[:min(max_len, USBValidation.MAX_STRING_LEN)]

    @staticmethod
    def sanitize_key(key: str) -> Optional[str]:
        """
        Normalize and validate a USB rule key into one of the canonical forms: vendor, model, or device.
        
        Parameters:
            key (str): Raw key using formats like "vid:pid:serial", "vid:pid:*", "vid:*:*", or legacy "vid:pid".
        
        Returns:
            Sanitized key in the canonical form "vvvv:pppp:serial" / "vvvv:pppp:*" / "vvvv:*:*" if valid, `None` if the input is missing, malformed, or exceeds allowed length.
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
        Determine whether a USB rule key is syntactically valid.
        
        Performs a strict check against the module's KEY_PATTERN and USBValidation.MAX_KEY_LEN.
        
        Parameters:
            key (str): The key string to validate.
        
        Returns:
            bool: `True` if the key matches the required pattern and length constraints, `False` otherwise.
        """
        if not key or not isinstance(key, str):
            return False
        if len(key) > USBValidation.MAX_KEY_LEN:
            return False
        return KEY_PATTERN.match(key) is not None

    @staticmethod
    def sanitize_timestamp(ts: str) -> str:
        """
        Validate an ISO 8601 timestamp string and supply a safe current-time fallback when invalid.
        
        Parameters:
            ts (str): Candidate ISO 8601 timestamp string.
        
        Returns:
            `ts` if it is a valid ISO 8601 timestamp, otherwise the current time in ISO 8601 format.
        """
        try:
            datetime.fromisoformat(ts)
            return ts
        except (ValueError, TypeError):
            return datetime.now().isoformat()
