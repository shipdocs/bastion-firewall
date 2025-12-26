"""
Centralized runtime dependency validation for Bastion.

This module consolidates checks for core libraries that the daemon
and GUI rely on. It provides clear, actionable error messages so
operators understand what to install or fix before starting the
firewall.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DependencyDefinition:
    """Static definition of a dependency."""

    key: str
    module_path: str
    display_name: str
    install_hint: str
    category: str  # e.g. core, packet, gui


@dataclass
class DependencyStatus:
    """Result of attempting to import a dependency."""

    definition: DependencyDefinition
    state: str  # ok, missing, error
    detail: str = ""

    @property
    def is_failure(self) -> bool:
        return self.state != "ok"

    def describe(self) -> str:
        if self.state == "ok":
            return f"{self.definition.display_name} available"

        qualifier = "is not installed" if self.state == "missing" else "is installed but failed to load"
        detail = f" ({self.detail})" if self.detail else ""
        return f"{self.definition.display_name} {qualifier}{detail}. {self.definition.install_hint}"


class DependencyValidationError(RuntimeError):
    """Raised when one or more dependencies are unavailable."""

    def __init__(self, failures: Iterable[DependencyStatus]):
        self.failures: List[DependencyStatus] = list(failures)
        message = "Runtime dependency validation failed:\n" + "\n".join(
            f"- {failure.describe()}" for failure in self.failures
        )
        super().__init__(message)
        self.user_message = message


class MissingDependencyError(DependencyValidationError):
    """Raised when a dependency is missing entirely."""


class BrokenDependencyError(DependencyValidationError):
    """Raised when a dependency exists but cannot be imported/used."""


DEPENDENCIES: List[DependencyDefinition] = [
    DependencyDefinition(
        key="psutil",
        module_path="psutil",
        display_name="psutil",
        install_hint="Install psutil (e.g., pip install psutil or your distro's python3-psutil package).",
        category="core",
    ),
    DependencyDefinition(
        key="netfilterqueue",
        module_path="netfilterqueue",
        display_name="NetfilterQueue",
        install_hint="Install NetfilterQueue and libnetfilter-queue (pip install NetfilterQueue or apt install python3-netfilterqueue).",
        category="packet",
    ),
    DependencyDefinition(
        key="scapy",
        module_path="scapy.all",
        display_name="Scapy",
        install_hint="Install scapy (pip install scapy or your distro's python3-scapy package).",
        category="packet",
    ),
    DependencyDefinition(
        key="tkinter",
        module_path="tkinter",
        display_name="Tkinter",
        install_hint="Install the Tkinter bindings (e.g., apt install python3-tk).",
        category="gui",
    ),
]

DEPENDENCY_MAP: Dict[str, DependencyDefinition] = {dep.key: dep for dep in DEPENDENCIES}


def _import_dependency(module_path: str):
    """Separated for testability."""
    return importlib.import_module(module_path)


def _check_dependency(
    definition: DependencyDefinition,
    importer: Callable[[str], object] = _import_dependency,
) -> DependencyStatus:
    try:
        importer(definition.module_path)
        return DependencyStatus(definition=definition, state="ok")
    except ModuleNotFoundError as exc:
        logger.debug("Dependency %s missing: %s", definition.display_name, exc)
        return DependencyStatus(definition=definition, state="missing", detail=str(exc))
    except Exception as exc:  # pragma: no cover - exercised via tests
        logger.debug("Dependency %s failed to import: %s", definition.display_name, exc)
        return DependencyStatus(definition=definition, state="error", detail=str(exc))


def collect_dependency_statuses(
    include_gui: bool = True,
    importer: Callable[[str], object] = _import_dependency,
) -> List[DependencyStatus]:
    """Collect the status of all runtime dependencies."""
    statuses: List[DependencyStatus] = []
    for definition in DEPENDENCIES:
        if definition.category == "gui" and not include_gui:
            continue
        statuses.append(_check_dependency(definition, importer=importer))
    return statuses


def ensure_runtime_dependencies(
    include_gui: bool = True,
    importer: Callable[[str], object] = _import_dependency,
) -> List[DependencyStatus]:
    """
    Validate that all required dependencies are importable.

    Raises:
        DependencyValidationError: when any dependency is missing or broken.
    """
    statuses = collect_dependency_statuses(include_gui=include_gui, importer=importer)
    failures = [status for status in statuses if status.is_failure]
    if failures:
        # Distinguish missing vs broken to surface clear root causes
        if all(status.state == "missing" for status in failures):
            raise MissingDependencyError(failures)
        raise BrokenDependencyError(failures)
    return statuses


def require_dependency(
    key: str, importer: Callable[[str], object] = _import_dependency
):
    """
    Import a specific dependency and raise a clear error on failure.

    This is intended for code paths that truly need the module object.
    """
    if key not in DEPENDENCY_MAP:
        raise KeyError(f"Unknown dependency key '{key}'")

    definition = DEPENDENCY_MAP[key]
    status = _check_dependency(definition, importer=importer)
    if status.state == "ok":
        return importer(definition.module_path)
    if status.state == "missing":
        raise MissingDependencyError([status])
    raise BrokenDependencyError([status])


def run_self_check(include_gui: bool = True, importer: Callable[[str], object] = _import_dependency) -> bool:
    """
    Run dependency validation and print a human-friendly report.

    Returns:
        bool: True when all required dependencies are available, False otherwise.
    """
    statuses = collect_dependency_statuses(include_gui=include_gui, importer=importer)
    critical_failures = [status for status in statuses if status.is_failure]

    print("Running Bastion dependency self-check...\n")
    for status in statuses:
        label = "OK" if not status.is_failure else ("MISSING" if status.state == "missing" else "ERROR")
        print(f"[{label:<7}] {status.describe()}")

    if critical_failures:
        print("\nOne or more critical dependencies are unavailable. Address the issues above and retry.")
        return False

    print("\nAll critical dependencies satisfied. You can start Bastion safely.")
    return True
