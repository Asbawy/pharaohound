#!/usr/bin/env python3
"""
analyzers.registry — Dynamic analyzer discovery + registration.

To add a new analyzer:
1. Create a new file in this package (e.g. `my_check.py`).
2. Define a class inheriting from `BaseAnalyzer`.
3. Set `name`, `description`, and implement `analyze(store)`.
4. Import the module from `analyzers/__init__.py` (or just drop the
   file in — the registry will auto-discover any module that imports
   `BaseAnalyzer`).

The engine iterates the registry and runs every analyzer.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, List, Type

from .base import BaseAnalyzer


class AnalyzerRegistry:
    """Auto-discovering registry of analyzer classes."""

    def __init__(self) -> None:
        self._classes: Dict[str, Type[BaseAnalyzer]] = {}
        self._discover()

    def _discover(self) -> None:
        # Import every module in this package so BaseAnalyzer subclasses register.
        # We're inside `analyzers/registry.py`, so the package is one level up.
        import os as _os
        pkg_dir = _os.path.dirname(_os.path.abspath(__file__))
        pkg_name = __name__.rsplit(".", 1)[0]   # pharaohound.analyzers
        skip = {"base", "registry", "__init__"}
        for entry in sorted(_os.listdir(pkg_dir)):
            if not entry.endswith(".py"):
                continue
            name = entry[:-3]
            if name in skip:
                continue
            full = f"{pkg_name}.{name}"
            try:
                importlib.import_module(full)
            except Exception as e:  # pragma: no cover
                # Don't let a single broken analyzer break the whole run
                print(f"[!] Failed to import analyzer module {full}: {e}", flush=True)

        # Now collect all subclasses of BaseAnalyzer (recursively, in case of
        # multi-level inheritance)
        seen: set = set()
        def collect(cls):
            for sub in cls.__subclasses__():
                if sub.__name__ in seen or sub.__name__ == "BaseAnalyzer":
                    continue
                seen.add(sub.__name__)
                self._classes[sub.__name__] = sub
                collect(sub)
        collect(BaseAnalyzer)

    def register(self, cls: Type[BaseAnalyzer]) -> Type[BaseAnalyzer]:
        """Manual registration hook."""
        self._classes[cls.__name__] = cls
        return cls

    def all_analyzers(self) -> List[Type[BaseAnalyzer]]:
        return list(self._classes.values())

    def instantiate_all(self) -> List[BaseAnalyzer]:
        return [cls() for cls in self._classes.values()]


# Singleton
REGISTRY = AnalyzerRegistry()
