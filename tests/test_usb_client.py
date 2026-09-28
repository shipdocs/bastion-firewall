"""Tests for the Qt-free USB helpers (message building, sanitising, socket calls)."""
import json
import os
import socket
import tempfile
import threading

import pytest

from bastion.usb_client import (build_usb_response, dialog_timeout, delete_usb_rule, list_usb_rules,
                                sanitize_text)


def test_sanitize_strips_control_and_format_characters():
    assert sanitize_text("Log\x1b[31mi\ntech‮") == "Log[31mitech"
    assert sanitize_text(None) == ""
    assert len(sanitize_text("a" * 500, 64)) == 64


def test_build_usb_response():
    msg = build_usb_response("abc", True, "device", True)
    assert msg == {"type": "usb_response", "nonce": "abc", "allow": True,
                   "scope": "device", "permanent": True}
    with pytest.raises(ValueError):
        build_usb_response("abc", True, "everything", False)


class FakeDaemon(threading.Thread):
    """Answers one connection; sends a stats line first like the real primary connection does."""

    def __init__(self, path, reply):
        super().__init__(daemon=True)
        self.path = path
        self.reply = reply
        self.received = None
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen(1)

    def run(self):
        conn, _ = self.server.accept()
        conn.sendall(b'{"type":"stats_update","stats":{}}\n')
        self.received = json.loads(conn.makefile().readline())
        conn.sendall((json.dumps(self.reply) + "\n").encode())
        conn.close()
        self.server.close()


@pytest.fixture
def sock_path():
    with tempfile.TemporaryDirectory() as d:
        yield os.path.join(d, "d.sock")


def test_list_usb_rules(sock_path):
    daemon = FakeDaemon(sock_path, {"type": "usb_rules_list", "enabled": True,
                                    "rules": {"046d:*:*": {"verdict": "allow"}}})
    daemon.start()
    enabled, rules = list_usb_rules(sock_path)
    daemon.join(2)
    assert enabled is True
    assert "046d:*:*" in rules
    assert daemon.received == {"type": "list_usb_rules"}


def test_delete_usb_rule(sock_path):
    daemon = FakeDaemon(sock_path, {"type": "usb_rule_deleted", "key": "046d:*:*", "success": True})
    daemon.start()
    assert delete_usb_rule("046d:*:*", sock_path) is True
    daemon.join(2)
    assert daemon.received == {"type": "delete_usb_rule", "key": "046d:*:*"}


def test_unreachable_daemon(sock_path):
    assert list_usb_rules(sock_path) is None
    assert delete_usb_rule("046d:*:*", sock_path) is False


def test_dialog_timeout_follows_daemon_timeout():
    assert dialog_timeout(30) == 28
    assert dialog_timeout(300) == 298
    assert dialog_timeout(5) == 3
    assert dialog_timeout(1) == 3
    assert dialog_timeout(0) == 25
    assert dialog_timeout(None) == 25
    assert dialog_timeout("abc") == 25
