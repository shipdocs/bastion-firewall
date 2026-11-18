import types

import pytest

gui_qt = pytest.importorskip("bastion.gui_qt")


def test_rule_count_ignores_meta_fields():
    window = types.SimpleNamespace(data_rules={
        "applications": {}, "services": {},
        "/usr/bin/curl:443": True, "/usr/bin/wget:80": False,
    })
    assert gui_qt.DashboardWindow._rule_count(window) == 2
