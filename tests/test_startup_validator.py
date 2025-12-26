from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from bastion import startup_validator as sv


def _fake_import_factory(responses):
    """Create a fake importer that can raise exceptions for specific modules."""

    def _fake_import(module_path):
        behavior = responses.get(module_path)
        if isinstance(behavior, Exception):
            raise behavior
        return behavior or object()

    return _fake_import


def test_collect_dependency_statuses_marks_missing(monkeypatch):
    fake_import = _fake_import_factory({"netfilterqueue": ModuleNotFoundError("no module named netfilterqueue")})
    statuses = sv.collect_dependency_statuses(include_gui=False, importer=fake_import)
    status_map = {status.definition.key: status for status in statuses}

    assert status_map["netfilterqueue"].state == "missing"
    assert status_map["psutil"].state == "ok"
    assert status_map["scapy"].state == "ok"


def test_require_dependency_distinguishes_broken(monkeypatch):
    fake_import = _fake_import_factory({"netfilterqueue": RuntimeError("libnetfilter-queue not present")})
    with pytest.raises(sv.BrokenDependencyError) as excinfo:
        sv.require_dependency("netfilterqueue", importer=fake_import)

    assert "libnetfilter-queue not present" in str(excinfo.value)


def test_ensure_runtime_dependencies_raises_missing(monkeypatch):
    fake_import = _fake_import_factory({"scapy.all": ModuleNotFoundError("scapy missing")})
    with pytest.raises(sv.MissingDependencyError) as excinfo:
        sv.ensure_runtime_dependencies(include_gui=False, importer=fake_import)

    assert "Scapy is not installed" in excinfo.value.user_message


def test_run_self_check_reports_statuses(capsys):
    fake_import = _fake_import_factory({})
    success = sv.run_self_check(include_gui=False, importer=fake_import)

    out = capsys.readouterr().out
    assert success is True
    assert "dependency self-check" in out
    assert "[OK" in out
