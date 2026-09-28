"""
Qt-free helpers for USB device control: display sanitising, the decision
message sent to the daemon, and request/response calls for the rule list.
"""

import json
import socket
import unicodedata

DAEMON_SOCKET_PATH = "/var/run/bastion/bastion-daemon.sock"

VALID_SCOPES = ("device", "model", "vendor")


def sanitize_text(value, max_len=128):
    """Make untrusted device strings safe to show: no control/format characters, bounded length."""
    text = "" if value is None else str(value)
    text = "".join(c for c in text if unicodedata.category(c)[0] != "C")
    return text[:max_len]


def build_usb_response(nonce, allow, scope, permanent):
    """Message answering a daemon `usb_request`."""
    if scope not in VALID_SCOPES:
        raise ValueError(f"invalid USB rule scope: {scope!r}")
    return {
        "type": "usb_response",
        "nonce": str(nonce),
        "allow": bool(allow),
        "scope": scope,
        "permanent": bool(permanent),
    }


def _request(command, expected_type, socket_path=DAEMON_SOCKET_PATH, timeout=3.0):
    """Send one command on a fresh connection and return the matching reply, or None."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(socket_path)
        sock.sendall((json.dumps(command) + "\n").encode())
        buf = b""
        while True:
            # The primary connection also receives periodic stats updates; skip those.
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(msg, dict) and msg.get("type") == expected_type:
                    return msg
            chunk = sock.recv(65536)
            if not chunk:
                return None
            buf += chunk
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()


def list_usb_rules(socket_path=DAEMON_SOCKET_PATH):
    """Returns (enabled, rules_dict) or None if the daemon could not be reached."""
    reply = _request({"type": "list_usb_rules"}, "usb_rules_list", socket_path)
    if reply is None:
        return None
    rules = reply.get("rules")
    return bool(reply.get("enabled")), rules if isinstance(rules, dict) else {}


def delete_usb_rule(key, socket_path=DAEMON_SOCKET_PATH):
    """True if the daemon confirmed the rule was removed."""
    reply = _request({"type": "delete_usb_rule", "key": key}, "usb_rule_deleted", socket_path)
    return bool(reply and reply.get("success"))
