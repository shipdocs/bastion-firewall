#!/usr/bin/env python3
"""
Bastion Firewall - Log Parser Module
Parses structured log entries from the daemon's journal output.
"""

import re
import logging
from dataclasses import dataclass
from typing import Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """
    Represents a parsed log entry from the Bastion Firewall daemon.
    """
    timestamp: str
    event_type: str  # POPUP, RULE, USER, LEARN, BLOCK, AUTO
    action: Optional[str]  # ALLOW, BLOCK, or None
    app_name: str
    app_path: str
    dest_ip: str
    dest_port: str
    protocol: str
    user_id: str
    raw_line: str  # Original line for reference


class LogParser:
    """
    Parses structured log entries from Bastion Firewall daemon logs.
    """

    # Regex patterns for different log formats
    # Pattern 1: [POPUP] app_name (app_path) -> dest_ip:dest_port
    POPUP_PATTERN = re.compile(r'\[POPUP\] (.+?) \((.+?)\) -> (.+?):(\d+)')

    # Pattern 2: [RULE:ALLOW] app="X" path="Y" dst="IP:PORT" user=UID protocol="PROTO"
    RULE_PATTERN = re.compile(
        r'\[RULE:(ALLOW|BLOCK)\] app="(.+?)" path="(.+?)" dst="(.+?):(\d+)" user=(\d+)'
    )

    # Pattern 3: [RULE:ALLOW:NAME] app="X" dst="IP:PORT" user=UID protocol="PROTO"
    RULE_NAME_PATTERN = re.compile(
        r'\[RULE:(ALLOW|BLOCK):NAME\] app="(.+?)" dst="(.+?):(\d+)" user=(\d+)'
    )

    # Pattern 4: [USER:ALLOW] app="X" dst="IP:PORT" user=UID protocol="PROTO"
    USER_PATTERN = re.compile(
        r'\[USER:(ALLOW|BLOCK)\] app="(.+?)" dst="(.+?):(\d+)" user=(\d+)'
    )

    # Pattern 5: [SESSION:ALLOW] app="X" dst="IP:PORT"
    SESSION_PATTERN = re.compile(
        r'\[SESSION:(ALLOW|BLOCK)\] app="(.+?)" dst="(.+?):(\d+)'
    )

    # Pattern 6: [CACHED:ALLOW] unknown app dst="IP:PORT"
    CACHED_PATTERN = re.compile(
        r'\[CACHED:(ALLOW|BLOCK)\] unknown app dst="(.+?):(\d+)"'
    )

    # Pattern 7: [LEARN] app="X" path="Y" dst="IP:PORT" user=UID
    LEARN_PATTERN = re.compile(
        r'\[LEARN\] app="(.+?)" path="(.+?)" dst="(.+?):(\d+)" user=(\d+)'
    )

    # Pattern 8: [BLOCK] app="X" dst="IP:PORT" user=UID
    BLOCK_PATTERN = re.compile(
        r'\[BLOCK\] app="(.+?)" dst="(.+?):(\d+)" user=(\d+)'
    )

    # Pattern 9: [AUTO] app_name - reason
    AUTO_PATTERN = re.compile(r'\[AUTO\] (.+?) - (.+)')

    # Pattern 10: [DEBUG] messages
    DEBUG_PATTERN = re.compile(r'\[DEBUG\] (.+)')

    @classmethod
    def parse_line(cls, line: str) -> Optional[LogEntry]:
        """
        Parse a single log line into a LogEntry.

        Args:
            line: Raw log line from journalctl

        Returns:
            LogEntry if parsing successful, None otherwise
        """
        try:
            # Extract timestamp from journalctl format (first part before the log message)
            parts = line.strip().split(' ', 1)
            if len(parts) < 2:
                return None

            timestamp = parts[0]
            log_message = parts[1]

            # Try each pattern
            # Pattern 1: POPUP
            match = cls.POPUP_PATTERN.search(log_message)
            if match:
                app_name, app_path, dest_ip, dest_port = match.groups()
                return LogEntry(
                    timestamp=timestamp,
                    event_type='POPUP',
                    action=None,
                    app_name=app_name,
                    app_path=app_path,
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    protocol='TCP',  # Default to TCP for POPUP
                    user_id='-',
                    raw_line=line.strip()
                )

            # Pattern 2: RULE
            match = cls.RULE_PATTERN.search(log_message)
            if match:
                action, app_name, app_path, dest_ip, dest_port, user_id = match.groups()
                return LogEntry(
                    timestamp=timestamp,
                    event_type='RULE',
                    action=action,
                    app_name=app_name,
                    app_path=app_path,
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    protocol='TCP',  # Default to TCP
                    user_id=user_id,
                    raw_line=line.strip()
                )

            # Pattern 3: RULE:NAME
            match = cls.RULE_NAME_PATTERN.search(log_message)
            if match:
                action, app_name, dest_ip, dest_port, user_id = match.groups()
                return LogEntry(
                    timestamp=timestamp,
                    event_type='RULE',
                    action=action,
                    app_name=app_name,
                    app_path='-',
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    protocol='TCP',
                    user_id=user_id,
                    raw_line=line.strip()
                )

            # Pattern 4: USER
            match = cls.USER_PATTERN.search(log_message)
            if match:
                action, app_name, dest_ip, dest_port, user_id = match.groups()
                return LogEntry(
                    timestamp=timestamp,
                    event_type='USER',
                    action=action,
                    app_name=app_name,
                    app_path='-',
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    protocol='TCP',
                    user_id=user_id,
                    raw_line=line.strip()
                )

            # Pattern 5: SESSION
            match = cls.SESSION_PATTERN.search(log_message)
            if match:
                action, app_name, dest_ip, dest_port = match.groups()
                return LogEntry(
                    timestamp=timestamp,
                    event_type='SESSION',
                    action=action,
                    app_name=app_name,
                    app_path='-',
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    protocol='TCP',
                    user_id='-',
                    raw_line=line.strip()
                )

            # Pattern 6: CACHED
            match = cls.CACHED_PATTERN.search(log_message)
            if match:
                action, dest_ip, dest_port = match.groups()
                return LogEntry(
                    timestamp=timestamp,
                    event_type='CACHED',
                    action=action,
                    app_name='unknown',
                    app_path='-',
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    protocol='TCP',
                    user_id='-',
                    raw_line=line.strip()
                )

            # Pattern 7: LEARN
            match = cls.LEARN_PATTERN.search(log_message)
            if match:
                app_name, app_path, dest_ip, dest_port, user_id = match.groups()
                return LogEntry(
                    timestamp=timestamp,
                    event_type='LEARN',
                    action='ALLOW',
                    app_name=app_name,
                    app_path=app_path,
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    protocol='TCP',
                    user_id=user_id,
                    raw_line=line.strip()
                )

            # Pattern 8: BLOCK
            match = cls.BLOCK_PATTERN.search(log_message)
            if match:
                app_name, dest_ip, dest_port, user_id = match.groups()
                return LogEntry(
                    timestamp=timestamp,
                    event_type='BLOCK',
                    action='BLOCK',
                    app_name=app_name,
                    app_path='-',
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    protocol='TCP',
                    user_id=user_id,
                    raw_line=line.strip()
                )

            # Pattern 9: AUTO
            match = cls.AUTO_PATTERN.search(log_message)
            if match:
                app_name, reason = match.groups()
                return LogEntry(
                    timestamp=timestamp,
                    event_type='AUTO',
                    action='ALLOW',
                    app_name=app_name,
                    app_path='-',
                    dest_ip='-',
                    dest_port='-',
                    protocol='-',
                    user_id='-',
                    raw_line=line.strip()
                )

            # Pattern 10: DEBUG (skip, not useful for users)
            match = cls.DEBUG_PATTERN.search(log_message)
            if match:
                return None

            # If no pattern matches, return None
            return None

        except Exception as e:
            logger.warning(f"Failed to parse log line: {e} - Line: {line[:100]}")
            return None

    @classmethod
    def parse_lines(cls, lines: List[str]) -> List[LogEntry]:
        """
        Parse multiple log lines into LogEntry objects.

        Args:
            lines: List of raw log lines from journalctl

        Returns:
            List of parsed LogEntry objects
        """
        entries = []
        for line in lines:
            entry = cls.parse_line(line)
            if entry:
                entries.append(entry)
        return entries

    @classmethod
    def get_event_type_display(cls, event_type: str) -> str:
        """Get user-friendly display name for event type"""
        display_names = {
            'POPUP': 'Popup',
            'RULE': 'Rule',
            'USER': 'User Decision',
            'SESSION': 'Session',
            'CACHED': 'Cached',
            'LEARN': 'Learning Mode',
            'BLOCK': 'Blocked',
            'AUTO': 'Auto-allow'
        }
        return display_names.get(event_type, event_type)

    @classmethod
    def get_event_severity(cls, event_type: str) -> str:
        """Get severity level for event type"""
        severity_map = {
            'POPUP': 'info',
            'RULE': 'info',
            'USER': 'info',
            'SESSION': 'info',
            'CACHED': 'info',
            'LEARN': 'info',
            'BLOCK': 'warning',
            'AUTO': 'debug'
        }
        return severity_map.get(event_type, 'info')
