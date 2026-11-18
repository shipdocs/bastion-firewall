import json
import os
import socket
import threading

import pytest

gui_qt = pytest.importorskip("bastion.gui_qt")


def test_stats_client_asks_for_stats_on_a_secondary_connection(tmp_path):
    """While the tray owns the primary connection, the daemon pushes nothing to
    the control panel; it only answers get_stats. The client must ask."""
    path = str(tmp_path / "daemon.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)
    received = []

    def daemon():
        conn, _ = server.accept()
        with conn, conn.makefile("rb") as f:
            for line in f:
                received.append(json.loads(line))
                if received[-1].get("type") == "get_stats":
                    reply = {"type": "stats_update", "stats": {
                        "total_connections": 42, "allowed_connections": 40,
                        "blocked_connections": 2, "learning_mode": False}}
                    conn.sendall((json.dumps(reply) + "\n").encode())
                    return

    threading.Thread(target=daemon, daemon=True).start()
    got = threading.Event()
    stats = {}

    def callback(s):
        stats.update(s)
        got.set()

    client = gui_qt.DaemonStatsClient(callback)
    client.socket_path = path
    client.start()
    try:
        assert got.wait(5), "no stats received"
    finally:
        client.stop()
        server.close()
        os.unlink(path)
    assert received[0] == {"type": "get_stats"}
    assert stats["total_connections"] == 42
    assert stats["blocked_connections"] == 2
