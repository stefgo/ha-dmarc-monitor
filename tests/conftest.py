"""Shared test setup.

The integration's modules import each other relatively (``from .const import
…``). Loading them via ``custom_components.dmarc_monitor`` would execute
``__init__.py`` and drag in Home Assistant, so the directory is registered as a
package of its own without running ``__init__.py``.
"""

from __future__ import annotations

import copy
import json
import sys
import types
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1] / "custom_components" / "dmarc_monitor"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Deliberately not "dmarc_monitor": it must not collide with a real package.
PACKAGE = "dmarc_monitor_component"


def register_package() -> None:
    if PACKAGE in sys.modules:
        return
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(COMPONENT)]
    sys.modules[PACKAGE] = package


def fixture(name: str) -> dict:
    """A fresh copy of a recorded Stalwart object."""
    data = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return copy.deepcopy(data)


register_package()
