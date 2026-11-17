import json

from bastion.connection_client import build_learning_add_rule

REQ = {
    "app_name": "Socket Thread (start.thunderbird.net.)",
    "process_name": "Socket Thread",
    "app_path": "",
    "dest_ip": "1.2.3.4",
    "dest_port": 443,
}


def test_once_sends_nothing():
    assert build_learning_add_rule(REQ, True, False, "once") is None


def test_always_uses_bare_process_name():
    msg = json.loads(build_learning_add_rule(REQ, True, False, "always"))
    assert msg["type"] == "add_rule"
    assert msg["app_name"] == "Socket Thread"
    assert msg["duration"] == "always"
    assert msg["port"] == 443


def test_permanent_flag_wins():
    msg = json.loads(build_learning_add_rule(REQ, False, True, "once", permanent=True))
    assert msg["duration"] == "always"
    assert msg["allow"] is False and msg["all_ports"] is True


def test_session_is_sent():
    msg = json.loads(build_learning_add_rule(REQ, True, False, "session"))
    assert msg["duration"] == "session"


def test_older_daemon_without_process_name_falls_back():
    req = dict(REQ)
    del req["process_name"]
    msg = json.loads(build_learning_add_rule(req, True, False, "always"))
    assert msg["app_name"] == REQ["app_name"]
