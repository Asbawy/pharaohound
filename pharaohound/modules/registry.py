"""
Pharaohound Module Registry
============================
Central registry that discovers, loads, and provides access to all
exploitation modules. The interactive shell uses this to list, search,
and instantiate modules at runtime.
"""

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from .base import ExploitModule, Severity

logger = logging.getLogger("pharaohound.registry")


class ModuleRegistry:
    """
    Singleton-style registry for exploit modules.

    Usage::

        registry = ModuleRegistry()
        registry.discover("pharaohound_modules.modules")

        # list all
        for mod in registry.list_modules():
            print(mod["name"], mod["edge_type"])

        # get by edge type
        cls = registry.get_by_edge("DCSync")
        instance = cls(connection=ldap_conn, config=cfg)
    """

    def __init__(self):
        self._modules: Dict[str, Type[ExploitModule]] = {}
        self._by_edge: Dict[str, str] = {}  # edge_type → internal name

    # -- Discovery ---------------------------------------------------------

    def discover(self, package_name: str) -> int:
        """
        Import every submodule inside *package_name* and register any
        class that inherits from ExploitModule (but is not the base itself).

        Returns the number of modules registered.
        """
        try:
            package = importlib.import_module(package_name)
        except ImportError as exc:
            logger.error("Cannot import package '%s': %s", package_name, exc)
            return 0

        pkg_path = getattr(package, "__path__", None)
        if not pkg_path:
            logger.error("Package '%s' has no __path__.", package_name)
            return 0

        count = 0
        for importer, modname, is_pkg in pkgutil.iter_modules(pkg_path):
            if is_pkg:
                continue
            fqn = f"{package_name}.{modname}"
            try:
                mod = importlib.import_module(fqn)
            except Exception as exc:
                logger.warning("Failed to import '%s': %s", fqn, exc)
                continue

            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, ExploitModule)
                    and attr is not ExploitModule
                ):
                    self.register(attr)
                    count += 1

        logger.info("Discovered %d module(s) from '%s'.", count, package_name)
        return count

    def register(self, cls: Type[ExploitModule]):
        """Manually register a module class."""
        name = cls.name or cls.__name__
        key = name.lower()
        if key in self._modules:
            logger.warning("Overwriting existing module '%s'.", name)
        self._modules[key] = cls
        if cls.edge_type:
            self._by_edge[cls.edge_type.lower()] = key

    # -- Lookup ------------------------------------------------------------

    def get(self, name: str) -> Optional[Type[ExploitModule]]:
        """Get module class by internal name (case-insensitive)."""
        return self._modules.get(name.lower())

    def get_by_edge(self, edge_type: str) -> Optional[Type[ExploitModule]]:
        """Get module class by BloodHound edge name (case-insensitive)."""
        return self._modules.get(self._by_edge.get(edge_type.lower(), ""))

    def list_modules(self) -> List[Dict[str, Any]]:
        """Return summary info for every registered module."""
        results = []
        for name, cls in self._modules.items():
            results.append({
                "name":       cls.name or name,
                "edge_type":  cls.edge_type,
                "severity":   cls.severity.value,
                "description": cls.description,
                "class":      cls.__name__,
            })
        return sorted(results, key=lambda m: m["edge_type"])

    def list_by_severity(self, severity: Severity) -> List[Dict[str, Any]]:
        return [m for m in self.list_modules() if m["severity"] == severity.value]

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Fuzzy search across name, edge_type, and description."""
        q = query.lower()
        return [
            m for m in self.list_modules()
            if q in m["name"].lower()
            or q in m["edge_type"].lower()
            or q in m["description"].lower()
        ]

    @property
    def count(self) -> int:
        return len(self._modules)

    def __len__(self) -> int:
        return self.count

    def __repr__(self) -> str:
        return f"<ModuleRegistry modules={self.count}>"
