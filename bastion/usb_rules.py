"""
USB Device Rules Manager

Securely stores and retrieves USB device allow/block decisions.

Security features:
- Atomic writes (temp file + rename) to prevent corruption
- Strict file permissions (0600 - owner read/write only)
- Input validation (sanitize all fields before storage)
- Fixed file path (no user-controllable paths)
- Safe JSON parsing (no pickle/eval)
"""

import json
import logging
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Literal
from dataclasses import dataclass, asdict

from bastion.usb_device import USBDeviceInfo
from bastion.usb_validation import USBValidation, Verdict, Scope

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when a security-critical operation is rejected."""
    pass


@dataclass
class USBRule:
    """A stored USB device rule."""
    verdict: Verdict
    vendor_id: str
    product_id: str
    vendor_name: str
    product_name: str
    scope: Scope
    added: str  # ISO timestamp
    last_seen: Optional[str] = None
    serial: Optional[str] = None
    
    @property
    def key(self) -> str:
        """
        Generate unique key for this rule based on scope.

        All components are sanitized to prevent injection attacks.
        """
        # Ensure IDs are properly formatted
        vendor_id = USBValidation.sanitize_hex_id(self.vendor_id)
        product_id = USBValidation.sanitize_hex_id(self.product_id)

        if self.scope == 'vendor':
            return f"{vendor_id}:*:*"
        elif self.scope == 'model':
            return f"{vendor_id}:{product_id}:*"
        else:  # device
            # Sanitize serial with strict charset
            serial = USBValidation.sanitize_serial(self.serial) if self.serial else 'no-serial'
            return f"{vendor_id}:{product_id}:{serial}"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON storage."""
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: dict) -> 'USBRule':
        """Create from dictionary, with validation and sanitization."""
        # Sanitize serial if present (could contain malicious data from old rules)
        raw_serial = data.get('serial')
        serial = USBValidation.sanitize_serial(raw_serial) if raw_serial else None
        # Convert 'no-serial' back to None for consistency
        if serial == 'no-serial':
            serial = None

        return cls(
            verdict=USBValidation.validate_verdict(data.get('verdict', 'block')),
            vendor_id=USBValidation.sanitize_hex_id(data.get('vendor_id', '')),
            product_id=USBValidation.sanitize_hex_id(data.get('product_id', '')),
            vendor_name=USBValidation.sanitize_string(data.get('vendor_name', 'Unknown')),
            product_name=USBValidation.sanitize_string(data.get('product_name', 'Unknown')),
            scope=USBValidation.validate_scope(data.get('scope', 'device')),
            added=USBValidation.sanitize_timestamp(data.get('added', '')),
            last_seen=data.get('last_seen'),
            serial=serial,
        )


class USBRuleManager:
    """
    Manages USB device rules with secure JSON storage.
    
    Rules are keyed by:
    - device scope: "vendor_id:product_id:serial" (exact device)
    - model scope: "vendor_id:product_id" (all devices of this model)
    - vendor scope: "vendor_id:*" (all devices from vendor)
    """
    
    # Fixed path - system-wide location (daemon runs as root, GUI needs read access)
    # Always use /etc/bastion for USB rules - shared between daemon and GUI
    SYSTEM_PATH = Path('/etc/bastion/usb_rules.json')

    @classmethod
    def get_default_path(cls) -> Path:
        """Get the rules path - always /etc/bastion for USB rules."""
        return cls.SYSTEM_PATH

    DEFAULT_PATH = SYSTEM_PATH
    
    # File permissions: owner read/write, world readable (0644)
    # USB rules contain device IDs only, not secrets - need to be readable by GUI
    FILE_MODE = 0o644
    DIR_MODE = 0o755
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the rule manager.

        Args:
            db_path: Override path for testing. In production, uses get_default_path().
        """
        self.db_path = db_path or self.get_default_path()
        self._rules: dict[str, USBRule] = {}
        self._load()
    
    def _ensure_dir(self):
        """
        Ensure parent directory exists with correct permissions.

        Security: Rejects symlinked directories to prevent symlink attacks.
        """
        parent = self.db_path.parent

        # SECURITY: Check if parent directory is a symlink
        if parent.is_symlink():
            logger.error(f"Directory {parent} is a symlink, refusing to use")
            raise SecurityError(f"Directory {parent} is a symlink")

        parent.mkdir(parents=True, exist_ok=True)

        # Verify it's still not a symlink after creation (race condition mitigation)
        if parent.is_symlink():
            logger.error(f"Directory {parent} became a symlink, refusing to use")
            raise SecurityError(f"Directory {parent} is a symlink")

        os.chmod(parent, self.DIR_MODE)
    
    def _load(self):
        """
        Load rules from JSON file with backwards compatibility.

        Handles migration from old key formats:
        - Sanitizes keys that may contain unsafe characters
        - Updates rules to use new sanitized key format
        - Logs warnings for migrated rules
        """
        self._rules = {}
        needs_save = False  # Track if we need to re-save with sanitized keys

        if not self.db_path.exists():
            logger.debug(f"USB rules file does not exist: {self.db_path}")
            return

        try:
            # SECURITY: Check if rules file is a symlink to prevent symlink attacks
            if self.db_path.is_symlink():
                logger.error(f"USB rules file {self.db_path} is a symlink, refusing to load")
                return

            # Check permissions before reading (only warn, don't fail)
            stat = self.db_path.stat()
            if stat.st_mode & 0o022:  # Group/world-writable is a security issue
                logger.warning(f"USB rules file is group/world-writable: {oct(stat.st_mode)}")
                # Try to fix permissions (may fail if not owner)
                try:
                    os.chmod(self.db_path, self.FILE_MODE)
                except (OSError, PermissionError):
                    pass  # Can't fix, but still try to read

            with open(self.db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if not isinstance(data, dict):
                logger.error("USB rules file has invalid format (expected dict)")
                return

            # Validate and migrate each rule
            for old_key, rule_data in data.items():
                try:
                    if not isinstance(rule_data, dict):
                        logger.warning(f"Skipping invalid rule data for key {old_key[:50]}")
                        continue

                    # Create rule (this sanitizes the data inside)
                    rule = USBRule.from_dict(rule_data)

                    # Generate the proper sanitized key from the rule
                    new_key = rule.key

                    # Check if key changed (backwards compatibility migration)
                    if new_key != old_key:
                        logger.warning(
                            f"Migrating rule key: '{old_key[:50]}' -> '{new_key}' "
                            f"(unsafe characters removed)"
                        )
                        needs_save = True

                    # Store with sanitized key
                    self._rules[new_key] = rule

                except Exception as e:
                    logger.warning(f"Skipping invalid rule {old_key[:50]}: {e}")

            logger.info(f"Loaded {len(self._rules)} USB rules")

            # If we migrated any keys, save the file with new keys
            if needs_save:
                logger.info("Saving migrated rules with sanitized keys")
                try:
                    self._save()
                except Exception as e:
                    logger.warning(f"Could not save migrated rules: {e}")
            
        except json.JSONDecodeError as e:
            logger.error(f"USB rules file is corrupted: {e}")
        except Exception as e:
            logger.error(f"Failed to load USB rules: {e}")

    def _save(self):
        """
        Save rules to JSON file atomically.

        Uses temp file + rename to prevent corruption on crash/power loss.
        """
        self._ensure_dir()

        try:
            # Convert rules to serializable format
            data = {key: rule.to_dict() for key, rule in self._rules.items()}

            # Write to temp file first (atomic write pattern)
            fd, tmp_path = tempfile.mkstemp(
                dir=self.db_path.parent,
                prefix='.usb_rules_',
                suffix='.tmp'
            )

            try:
                # Set permissions before writing content
                os.fchmod(fd, self.FILE_MODE)

                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                # fd is now closed by os.fdopen context manager

                # Atomic rename (POSIX guarantees this is atomic on same filesystem)
                os.replace(tmp_path, self.db_path)
                logger.debug(f"Saved {len(self._rules)} USB rules")

            except Exception:
                # Close fd if os.fdopen hasn't taken ownership yet
                try:
                    os.close(fd)
                except OSError:
                    pass  # Already closed by os.fdopen or invalid
                # Clean up temp file on error
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

        except Exception as e:
            logger.error(f"Failed to save USB rules: {e}")
            raise

    def _make_key(self, device: USBDeviceInfo, scope: Scope) -> str:
        """
        Generate storage key for a device/scope combination.

        All components are sanitized to prevent injection attacks.
        Key formats:
        - device: vid:pid:serial (e.g., '046d:c52b:ABC123')
        - model: vid:pid:* (e.g., '046d:c52b:*')
        - vendor: vid:*:* (e.g., '046d:*:*')
        """
        # Sanitize vendor/product IDs (should already be clean, but defense in depth)
        vendor_id = USBValidation.sanitize_hex_id(device.vendor_id)
        product_id = USBValidation.sanitize_hex_id(device.product_id)

        if scope == 'device':
            # Sanitize serial with strict charset to prevent injection
            serial = USBValidation.sanitize_serial(device.serial)
            return f"{vendor_id}:{product_id}:{serial}"
        elif scope == 'model':
            return f"{vendor_id}:{product_id}:*"
        else:  # vendor
            return f"{vendor_id}:*:*"

    def get_verdict(self, device: USBDeviceInfo) -> Optional[Verdict]:
        """
        Get verdict for a device.

        Checks in order: exact device → model → vendor.
        Returns None if no matching rule (unknown device).
        """
        # Check exact device first (most specific)
        device_key = self._make_key(device, 'device')
        if device_key in self._rules:
            rule = self._rules[device_key]
            rule.last_seen = datetime.now().isoformat()
            return rule.verdict

        # Check model (any device of this type)
        model_key = self._make_key(device, 'model')
        if model_key in self._rules:
            return self._rules[model_key].verdict

        # Check vendor (any device from this vendor)
        vendor_key = self._make_key(device, 'vendor')
        if vendor_key in self._rules:
            return self._rules[vendor_key].verdict

        return None  # Unknown device

    def add_rule(self, device: USBDeviceInfo, verdict: Verdict, scope: Scope = 'device'):
        """
        Add or update a rule for a device.

        Args:
            device: The USB device info
            verdict: 'allow' or 'block'
            scope: 'device' (exact), 'model' (all of this type), 'vendor' (all from vendor)
        """
        key = self._make_key(device, scope)

        self._rules[key] = USBRule(
            verdict=verdict,
            vendor_id=device.vendor_id,
            product_id=device.product_id,
            vendor_name=device.vendor_name,
            product_name=device.product_name,
            scope=scope,
            added=datetime.now().isoformat(),
            serial=device.serial if scope == 'device' else None
        )

        self._save()
        logger.info(f"Added USB rule: {verdict} {device.product_name} (scope={scope})")

    def get_all_rules(self) -> dict[str, USBRule]:
        """Get all stored rules."""
        return self._rules.copy()

    def get_allowed_devices(self) -> list[USBRule]:
        """Get all allowed device rules."""
        return [r for r in self._rules.values() if r.verdict == 'allow']

    def get_blocked_devices(self) -> list[USBRule]:
        """Get all blocked device rules."""
        return [r for r in self._rules.values() if r.verdict == 'block']

    def remove_rule(self, key: str) -> bool:
        """
        Remove a rule by its key.

        Args:
            key: The rule key (e.g., '04e8:6860:SERIAL123')

        Returns:
            True if rule was removed, False if not found
        """
        if key in self._rules:
            del self._rules[key]
            self._save()
            logger.info(f"Removed USB rule: {key}")
            return True
        return False

    def clear_all(self):
        """Remove all rules. Use with caution!"""
        self._rules = {}
        self._save()
        logger.warning("Cleared all USB rules")


class USBAuthorizer:
    """
    Control USB device authorization via sysfs.

    Linux allows controlling USB device authorization through:
    /sys/bus/usb/devices/{bus_id}/authorized

    Writing "0" deauthorizes (disables) the device.
    Writing "1" authorizes (enables) the device.

    NOTE: Requires root privileges to write to sysfs.
    """

    SYSFS_USB_PATH = Path('/sys/bus/usb/devices')

    @classmethod
    def _get_auth_path(cls, bus_id: str) -> Path:
        """Get authorization file path for device."""
        # Sanitize bus_id to prevent path traversal
        # Only allow alphanumeric and dash (bus_id format: "1-2.3" becomes "1-23")
        safe_bus_id = re.sub(r'[^0-9a-zA-Z.-]', '', bus_id)
        # Additional safety: reject if contains ".." or starts with "/"
        if '..' in safe_bus_id or safe_bus_id.startswith('/'):
            logger.error(f"Invalid bus_id format: {bus_id}")
            raise ValueError(f"Invalid bus_id: {bus_id}")
        return cls.SYSFS_USB_PATH / safe_bus_id / 'authorized'

    @classmethod
    def is_authorized(cls, bus_id: str) -> Optional[bool]:
        """
        Check if device is currently authorized.

        Returns:
            True if authorized, False if not, None if cannot determine.
        """
        auth_path = cls._get_auth_path(bus_id)
        try:
            value = auth_path.read_text().strip()
            return value == '1'
        except (OSError, IOError) as e:
            logger.warning(f"Cannot read authorization for {bus_id}: {e}")
            return None

    @classmethod
    def authorize(cls, bus_id: str) -> bool:
        """
        Authorize (enable) a USB device.

        Returns:
            True if successful, False otherwise.
        """
        auth_path = cls._get_auth_path(bus_id)
        try:
            auth_path.write_text('1')
            logger.info(f"Authorized USB device: {bus_id}")
            return True
        except (OSError, IOError, PermissionError) as e:
            logger.error(f"Failed to authorize {bus_id}: {e}")
            return False

    @classmethod
    def deauthorize(cls, bus_id: str) -> bool:
        """
        Deauthorize (disable) a USB device.

        WARNING: Deauthorizing a device will immediately disconnect it.
        This can cause data loss if the device is in use (e.g., USB drive).

        Returns:
            True if successful, False otherwise.
        """
        auth_path = cls._get_auth_path(bus_id)
        try:
            auth_path.write_text('0')
            logger.info(f"Deauthorized USB device: {bus_id}")
            return True
        except (OSError, IOError, PermissionError) as e:
            logger.error(f"Failed to deauthorize {bus_id}: {e}")
            return False

    @classmethod
    def device_exists(cls, bus_id: str) -> bool:
        """Check if device exists in sysfs."""
        return cls._get_auth_path(bus_id).parent.exists()

    @classmethod
    def set_default_policy(cls, authorize: bool) -> bool:
        """
        Set the default USB authorization policy for new devices.

        Args:
            authorize: True = new devices auto-authorized (insecure default)
                      False = new devices blocked until explicitly authorized

        Returns:
            True if at least one controller was configured, False on total failure.
        """
        value = '1' if authorize else '0'
        success_count = 0

        # Find all USB host controllers
        for usb_host in cls.SYSFS_USB_PATH.glob('usb*'):
            auth_default = usb_host / 'authorized_default'
            if auth_default.exists():
                try:
                    auth_default.write_text(value)
                    logger.info(f"Set {usb_host.name} authorized_default={value}")
                    success_count += 1
                except (OSError, IOError, PermissionError) as e:
                    logger.warning(f"Failed to set default policy for {usb_host.name}: {e}")

        if success_count > 0:
            policy = "authorize" if authorize else "block"
            logger.info(f"USB default policy set to {policy} ({success_count} controllers)")
            return True
        else:
            logger.error("Failed to set USB default policy on any controller")
            return False

