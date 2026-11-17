"""
Qt-free helpers for answering connection popups.
"""

import json


def build_learning_add_rule(req, allow, all_ports, duration, permanent=False):
    """Message the tray sends after a learning-mode popup, or None.

    In learning mode the daemon has already let the connection through, so only
    decisions that should be remembered are sent:
    - "always" (or ``permanent``): saved as a rule in /etc/bastion/rules.json
    - "session": remembered by the daemon until it restarts
    - "once": nothing to send

    The rule is keyed on the bare process name (``process_name``), never on the
    popup's display name, which can carry a domain hint like "curl (example.com.)".
    """
    if permanent:
        duration = "always"
    if duration not in ("session", "always"):
        return None

    msg = {
        "type": "add_rule",
        "app_name": req.get("process_name") or req.get("app_name"),
        "app_path": req.get("app_path"),
        "port": req.get("dest_port"),
        "dest_ip": req.get("dest_ip"),  # For @dest rules on unknown apps
        "allow": bool(allow),
        "all_ports": bool(all_ports),
        "duration": duration,
    }
    return json.dumps(msg) + "\n"
