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
        Produce the unique storage key for this USB rule based on its scope.
        
        The returned key encodes the rule's scope as one of:
        - vendor: "vendor_id:*:*"
        - model:  "vendor_id:product_id:*"
        - device: "vendor_id:product_id:serial" (uses "no-serial" when serial is not set)
        
        All identifier components are sanitized before being incorporated into the key.
        
        Returns:
            key (str): The sanitized, colon-separated storage key for this rule.
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
        """
        Return a dictionary representation of the USBRule suitable for JSON storage.
        
        Only include fields whose value is not None; keys are the dataclass field names and values are the corresponding field values.
        """
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: dict) -> 'USBRule':
        """
        Create a USBRule from a dictionary, applying validation and sanitization.
        
        Parameters:
            data (dict): Serialized rule data (typically from JSON). Expected keys include
                'verdict', 'vendor_id', 'product_id', 'vendor_name', 'product_name',
                'scope', 'added', 'last_seen', and 'serial'.
        
        Returns:
            USBRule: A USBRule instance constructed from the input data. Fields are
            validated/sanitized; missing fields receive safe defaults (e.g., verdict -> 'block',
            vendor/product names -> 'Unknown'); a serial value of 'no-serial' is converted to None.
        """
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
        """
        Return the fixed filesystem path used for storing USB rules.
        
        Returns:
            Path: The system path for the USB rules file (`/etc/bastion/usb_rules.json`).
        """
        return cls.SYSTEM_PATH

    DEFAULT_PATH = SYSTEM_PATH
    
    # File permissions: owner read/write, world readable (0644)
    # USB rules contain device IDs only, not secrets - need to be readable by GUI
    FILE_MODE = 0o644
    DIR_MODE = 0o755
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Create a USBRuleManager using the provided database path or the module default.
        
        Parameters:
            db_path (Optional[Path]): Optional override for the rules JSON file path (primarily for testing); when omitted the manager uses the configured default system path.
        
        """
        self.db_path = db_path or self.get_default_path()
        self._rules: dict[str, USBRule] = {}
        self._load()
    
    def _ensure_dir(self):
        """
        Ensure the rule database's parent directory exists with the configured directory permissions.
        
        Creates the parent directory path if missing and enforces non-symlink ownership; updates the directory mode to DIR_MODE.
        
        Raises:
            SecurityError: If the parent directory is a symbolic link.
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
        Load USB rules from the manager's JSON database, validate each entry, and migrate stored keys to the sanitized format when necessary.
        
        Refuses to read symlinked files, warns about and attempts to fix insecure file permissions, skips invalid entries, constructs sanitized USBRule objects for valid entries, records and logs any key migrations, and triggers a save when migrations were applied. 
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
            if stat.st_mode & 0o002:  # World-writable is a security issue
                logger.warning(f"USB rules file is world-writable: {oct(stat.st_mode)}")
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
        Generate the normalized storage key for a USB device at the given scope.
        
        All components are sanitized to prevent injection. Key formats:
        - device: `vid:pid:serial` (e.g., `046d:c52b:ABC123`)
        - model:  `vid:pid:*`      (e.g., `046d:c52b:*`)
        - vendor: `vid:*:*`        (e.g., `046d:*:*`)
        
        Returns:
            key (str): The sanitized storage key for the device and scope.
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
        Determine the stored verdict for a USB device by checking specific-to-general rules.
        
        Checks rule keys in this order: device (most specific), model, then vendor. If a device-scoped rule matches, its `last_seen` timestamp is updated to the current time.
        
        Returns:
            `Verdict` if a matching rule exists, `None` otherwise.
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
        """
        Get a shallow copy of all stored USB rules keyed by their storage key.
        
        Returns:
            dict: Mapping from rule storage key (str) to corresponding USBRule instance; the mapping is a shallow copy of the manager's internal rules.
        """
        return self._rules.copy()

    def get_allowed_devices(self) -> list[USBRule]:
        """
        Retrieve rules with verdict `allow`.
        
        Returns:
            List of USBRule objects for stored rules whose `verdict` is `allow`.
        """
        return [r for r in self._rules.values() if r.verdict == 'allow']

    def get_blocked_devices(self) -> list[USBRule]:
        """
        Return all stored rules that have a verdict of 'block'.
        
        Returns:
            blocked_rules (list[USBRule]): List of USBRule objects with `verdict == 'block'`.
        """
        return [r for r in self._rules.values() if r.verdict == 'block']

    def remove_rule(self, key: str) -> bool:
        """
        Remove the USB rule identified by the given storage key.
        
        Parameters:
            key (str): Storage key of the rule (e.g., '04e8:6860:SERIAL123').
        
        Returns:
            bool: True if the rule was removed, False otherwise.
        """
        if key in self._rules:
            del self._rules[key]
            self._save()
            logger.info(f"Removed USB rule: {key}")
            return True
        return False

    def clear_all(self):
        """
        Remove all stored USB rules and persist the empty rule set.
        
        Clears the in-memory rules dictionary and writes the empty rules database to storage.
        """
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
        """
        Builds a sanitized path to the USB device's sysfs "authorized" file.
        
        The provided `bus_id` is cleaned to remove unsafe characters and validated to prevent path traversal or absolute paths; a `ValueError` is raised for invalid inputs.
        
        Parameters:
            bus_id (str): Raw bus identifier (for example "1-2.3").
        
        Returns:
            Path: Filesystem path to the device's "authorized" file under sysfs.
        
        """
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
        Determine whether the USB device identified by bus_id is currently authorized.
        
        Parameters:
            bus_id (str): USB device bus ID as exposed in sysfs (for example '1-1.2').
        
        Returns:
            bool | None: `True` if the device is authorized, `False` if it is not, `None` if the authorization status cannot be determined (for example, if the sysfs file is unreadable).
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
        Enable a USB device by writing '1' to its authorized sysfs file.
        
        Parameters:
            bus_id (str): Identifier of the USB device directory in sysfs (will be validated/sanitized).
        
        Returns:
            True if the device was successfully authorized, False otherwise.
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
        Disable a USB device by clearing its sysfs 'authorized' flag.
        
        This will immediately disconnect the device; doing so may cause data loss if the device is in use.
        
        Parameters:
            bus_id (str): Sysfs USB bus ID (e.g., "1-1"); the value will be validated/sanitized before use.
        
        Returns:
            True if the device was successfully deauthorized, False otherwise.
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
        """
        Determine whether a sysfs directory exists for the given USB bus identifier.
        
        Parameters:
            bus_id (str): The bus filesystem identifier of the USB device.
        
        Returns:
            bool: `True` if a sysfs device directory for `bus_id` exists, `False` otherwise.
        """
        return cls._get_auth_path(bus_id).parent.exists()

    @classmethod
    def set_default_policy(cls, authorize: bool) -> bool:
        """
        Set the default USB authorization policy applied to new devices on USB host controllers.
        
        Parameters:
            authorize (bool): If True, new devices are authorized by default; if False, new devices are blocked by default.
        
        Returns:
            bool: True if at least one controller's `authorized_default` was successfully configured, False otherwise.
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
