#!/usr/bin/env python3
"""
Bastion Root Helper - Privileged Operations CLI

This is a minimal, auditable CLI for operations that require root privileges.
It is invoked via pkexec from the GUI and performs only specific, validated actions.

Security design:
- Fixed command set (no arbitrary code execution)
- All inputs validated before use
- No shell interpretation of arguments
- Audit logging to syslog

Commands:
    bastion-root-helper usb-default-policy set --authorize|--block
    bastion-root-helper usb-rule delete --key KEY
    bastion-root-helper usb-rule clear-all
"""

import argparse
import logging
import logging.handlers
import os
import re
import sys
from pathlib import Path
from typing import Optional

# Module version for tracking
__version__ = "1.0.0"

# Setup syslog for audit trail
def setup_logging() -> logging.Logger:
    """
    Create and return a module logger configured for audit-style output.
    
    Attempts to add a SysLogHandler using /dev/log with the LOG_AUTH facility for audit logging; if syslog is unavailable, falls back to using stderr. Always adds a stderr StreamHandler for immediate feedback.
    
    Returns:
        logging.Logger: A logger named "bastion-root-helper" with handlers and INFO level configured.
    """
    logger = logging.getLogger("bastion-root-helper")
    logger.setLevel(logging.INFO)
    
    # Syslog handler for audit trail
    try:
        syslog_handler = logging.handlers.SysLogHandler(
            address='/dev/log',
            facility=logging.handlers.SysLogHandler.LOG_AUTH
        )
        syslog_handler.setFormatter(
            logging.Formatter('bastion-root-helper[%(process)d]: %(message)s')
        )
        logger.addHandler(syslog_handler)
    except Exception:
        # Fallback to stderr if syslog unavailable
        pass
    
    # Also log to stderr for immediate feedback
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(stderr_handler)
    
    return logger


logger = setup_logging()


# =============================================================================
# Validation
# =============================================================================

# Valid key pattern: vendor_id:product_id:serial or vendor_id:* or vendor_id:product_id:*
# vendor_id/product_id: 4 hex chars
# serial: alphanumeric, dots, dashes, underscores, or * for wildcard
KEY_PATTERN = re.compile(
    r'^[0-9a-f]{4}:[0-9a-f]{4}:[A-Za-z0-9._\-]+$|'  # device key
    r'^[0-9a-f]{4}:[0-9a-f]{4}:\*$|'                  # model key
    r'^[0-9a-f]{4}:\*:\*$'                            # vendor key
)


def validate_key(key: str) -> bool:
    """
    Validate a USB rule key string against the expected format.
    
    Rejects non-strings, empty values, or strings longer than 256 characters. Uses the module's KEY_PATTERN to determine whether the key matches a valid USB rule key (vendor:product:identifier, vendor:product:*, or vendor:*:*).
    
    Returns:
        True if the key matches the expected USB rule format, False otherwise.
    """
    if not isinstance(key, str):
        return False
    if not key or len(key) > 256:
        return False
    return KEY_PATTERN.match(key) is not None


# =============================================================================
# USB Default Policy Command
# =============================================================================

def cmd_usb_default_policy_set(authorize: bool) -> int:
    """
    Set the system-wide default USB device authorization policy for all USB host controllers.
    
    Parameters:
        authorize (bool): True to allow newly connected USB devices, False to block them.
    
    Returns:
        int: Exit code — `0` if at least one controller was updated, `1` otherwise.
    """
    value = '1' if authorize else '0'
    policy_name = 'authorize' if authorize else 'block'
    
    sysfs_path = Path('/sys/bus/usb/devices')
    if not sysfs_path.is_dir():
        logger.error("USB sysfs path not found")
        print("ERROR: USB sysfs not available", file=sys.stderr)
        return 1
    
    success_count = 0
    error_count = 0
    
    for usb_host in sysfs_path.glob('usb*'):
        auth_default = usb_host / 'authorized_default'
        if auth_default.exists() and auth_default.is_file():
            try:
                auth_default.write_text(value)
                logger.info(f"Set {usb_host.name}/authorized_default={value}")
                success_count += 1
            except (OSError, IOError, PermissionError) as e:
                logger.warning(f"Failed to set {usb_host.name}: {e}")
                error_count += 1
    
    if success_count > 0:
        logger.info(f"USB default policy set to {policy_name} ({success_count} controllers)")
        print(f"SUCCESS: Set {success_count} controller(s) to {policy_name}")
        return 0
    else:
        logger.error(f"Failed to set USB policy on any controller")
        print("ERROR: Failed to set policy on any controller", file=sys.stderr)
        return 1


# =============================================================================
# USB Rule Commands
# =============================================================================

def cmd_usb_rule_delete(key: str) -> int:
    """
    Remove a USB rule identified by its key.
    
    Parameters:
        key (str): The USB rule key to remove; expected to be validated before calling.
    
    Returns:
        int: 0 on success, 1 if the rule was not found, 2 on error (including import failures or exceptions).
    """
    # Import here to avoid import errors when bastion package not installed
    try:
        from bastion.usb_rules import USBRuleManager
    except ImportError:
        # Try adding common install paths
        for path in ['/usr/lib/python3/dist-packages', '/usr/local/lib/python3/dist-packages']:
            if path not in sys.path:
                sys.path.insert(0, path)
        try:
            from bastion.usb_rules import USBRuleManager
        except ImportError as e:
            logger.error(f"Cannot import USBRuleManager: {e}")
            print(f"ERROR: Cannot import bastion modules", file=sys.stderr)
            return 2
    
    try:
        manager = USBRuleManager()
        if manager.remove_rule(key):
            logger.info(f"Deleted USB rule: {key}")
            print("SUCCESS")
            return 0
        else:
            logger.info(f"USB rule not found: {key}")
            print("NOT_FOUND")
            return 1
    except Exception as e:
        logger.error(f"Error deleting rule {key}: {e}")
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


def cmd_usb_rule_clear_all() -> int:
    """
    Remove all configured USB rules.
    
    Returns:
        int: 0 on success, 2 on error
    """
    try:
        from bastion.usb_rules import USBRuleManager
    except ImportError:
        for path in ['/usr/lib/python3/dist-packages', '/usr/local/lib/python3/dist-packages']:
            if path not in sys.path:
                sys.path.insert(0, path)
        try:
            from bastion.usb_rules import USBRuleManager
        except ImportError as e:
            logger.error(f"Cannot import USBRuleManager: {e}")
            print(f"ERROR: Cannot import bastion modules", file=sys.stderr)
            return 2

    try:
        manager = USBRuleManager()
        manager.clear_all()
        logger.warning("Cleared ALL USB rules")
        print("SUCCESS: All rules cleared")
        return 0
    except Exception as e:
        logger.error(f"Error clearing rules: {e}")
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


# =============================================================================
# CLI Entry Point
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for the root helper CLI."""
    parser = argparse.ArgumentParser(
        prog='bastion-root-helper',
        description='Bastion Firewall privileged operations helper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  bastion-root-helper usb-default-policy set --authorize
  bastion-root-helper usb-default-policy set --block
  bastion-root-helper usb-rule delete --key 046d:c52b:1234567890
  bastion-root-helper usb-rule clear-all
"""
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # usb-default-policy command
    policy_parser = subparsers.add_parser(
        'usb-default-policy',
        help='Manage USB default authorization policy'
    )
    policy_subparsers = policy_parser.add_subparsers(dest='policy_action')

    policy_set = policy_subparsers.add_parser('set', help='Set the default policy')
    policy_group = policy_set.add_mutually_exclusive_group(required=True)
    policy_group.add_argument('--authorize', action='store_true', help='Allow new USB devices by default')
    policy_group.add_argument('--block', action='store_true', help='Block new USB devices by default')

    # usb-rule command
    rule_parser = subparsers.add_parser(
        'usb-rule',
        help='Manage USB device rules'
    )
    rule_subparsers = rule_parser.add_subparsers(dest='rule_action')

    rule_delete = rule_subparsers.add_parser('delete', help='Delete a USB rule')
    rule_delete.add_argument('--key', required=True, help='Rule key to delete')

    rule_subparsers.add_parser('clear-all', help='Delete ALL USB rules (use with caution)')

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """
    Parse CLI arguments, dispatch the requested privileged USB command, and return an exit code.
    
    Args:
        argv (Optional[list[str]]): Command-line arguments to parse; if None, defaults to sys.argv[1:].
    
    Returns:
        int: Exit code — `0` for success; `1` for usage/dispatch errors or missing command; `2` for invalid input (e.g., malformed key) or import/operation failures surfaced by subcommands.
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    # Log invocation for audit trail
    invoking_user = os.environ.get('PKEXEC_UID', os.environ.get('SUDO_UID', 'unknown'))
    logger.info(f"Invoked by uid={invoking_user}, args={sys.argv[1:]}")

    if not args.command:
        parser.print_help()
        return 1

    # Dispatch commands
    if args.command == 'usb-default-policy':
        if args.policy_action == 'set':
            return cmd_usb_default_policy_set(authorize=args.authorize)
        else:
            parser.print_help()
            return 1

    elif args.command == 'usb-rule':
        if args.rule_action == 'delete':
            # Validate key before proceeding
            if not validate_key(args.key):
                logger.warning(f"Invalid key format rejected: {args.key[:50]}")
                print("ERROR: Invalid key format", file=sys.stderr)
                return 2
            return cmd_usb_rule_delete(args.key)
        elif args.rule_action == 'clear-all':
            return cmd_usb_rule_clear_all()
        else:
            parser.print_help()
            return 1

    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
