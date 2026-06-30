"""
Pharaohound Exploit Module Base Class
======================================
Defines the abstract interface and common data structures for all
auto-exploitation modules. Every module MUST inherit from ExploitModule
and implement the required abstract methods.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Enums & Data Classes
# ---------------------------------------------------------------------------

class ExploitResult(Enum):
    """Standardised result codes returned by every module."""
    SUCCESS  = "success"
    FAILED   = "failed"
    PARTIAL  = "partial"
    ERROR    = "error"
    SKIPPED  = "skipped"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


@dataclass
class ModuleOption:
    """Describes a single configurable option for a module."""
    name: str
    display_name: str
    description: str
    required: bool = False
    default: Any = None
    value_type: type = str
    choices: Optional[List[str]] = None


@dataclass
class ExploitOutput:
    """
    Unified output envelope returned by exploit() and rollback().

    Attributes:
        success:       Whether the exploitation achieved its primary goal.
        result_type:   Granular result classification.
        message:       Human-readable summary (what happened / why it failed).
        data:          Arbitrary key-value payload (e.g. dumped hashes, new
                       group memberships, modified attributes).
        artifacts:     List of file paths written to disk (hash dumps, etc.).
        rollback_data: Data the module stores so rollback() can undo the change.
    """
    success: bool
    result_type: ExploitResult
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)
    rollback_data: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Abstract Base Module
# ---------------------------------------------------------------------------

class ExploitModule(ABC):
    """
    Abstract base class for every Pharaohound auto-exploitation module.

    Lifecycle (called by the framework):
        1. __init__(connection, config)
        2. info()           → static metadata
        3. get_options()    → configurable parameters
        4. validate(**opts) → optional pre-check on user-supplied values
        5. check_prerequisites(**opts) → runtime readiness check
        6. exploit(**opts)  → main exploitation logic
        7. rollback(**opts) → (optional) undo
    """

    # -- Module metadata (override in subclass) ---------------------------
    name: str            = ""
    description: str     = ""
    author: str          = "Pharaohound"
    edge_type: str       = ""          # BloodHound edge name
    severity: Severity   = Severity.MEDIUM
    references: List[str] = []
    tools_required: List[str] = []     # external tools (impacket, etc.)
    needs_da: bool       = False       # must run on a Domain Controller?
    needs_privileged: bool = False     # needs elevated session?

    def __init__(
        self,
        connection: Any = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Args:
            connection: A live LDAP / SMB / Drsuapi connection object
                        provided by the framework.
            config:     Global configuration dict (domain, creds, etc.).
        """
        self.connection = connection
        self.config = config or {}
        self.logger = logging.getLogger(f"pharaohound.{self.__class__.__name__}")
        self._options: Dict[str, ModuleOption] = {}
        self._register_options()

    # -- Options management ------------------------------------------------

    def _register_options(self):
        """Override in subclass to call self._add_option(...) for each param."""
        pass

    def _add_option(self, option: ModuleOption):
        self._options[option.name] = option

    def get_options(self) -> Dict[str, Dict[str, Any]]:
        """Return serialisable option descriptors (for the interactive shell)."""
        out = {}
        for name, opt in self._options.items():
            out[name] = {
                "display_name": opt.display_name,
                "description":  opt.description,
                "required":     opt.required,
                "default":      opt.default,
                "type":         opt.value_type.__name__,
                "choices":      opt.choices,
            }
        return out

    def set_option(self, name: str, value: Any):
        if name in self._options:
            self._options[name] = ModuleOption(
                name=self._options[name].name,
                display_name=self._options[name].display_name,
                description=self._options[name].description,
                required=self._options[name].required,
                default=value,
                value_type=self._options[name].value_type,
                choices=self._options[name].choices,
            )
        else:
            raise KeyError(f"Unknown option '{name}' for module '{self.name}'")

    def _opt(self, name: str, overrides: Optional[Dict[str, Any]] = None) -> Any:
        """Resolve an option value: explicit override > module default."""
        overrides = overrides or {}
        if name in overrides:
            return overrides[name]
        if name in self._options:
            return self._options[name].default
        return None

    # -- Validation -------------------------------------------------------

    def validate(self, **kwargs) -> Tuple[bool, str]:
        """
        Validate user-supplied option values before exploitation.
        Returns (is_valid, error_message).
        Default implementation checks required fields are present.
        """
        for name, opt in self._options.items():
            val = kwargs.get(name)
            if opt.required and val in (None, ""):
                return False, f"Required option '{opt.display_name}' ({name}) is missing."
            if opt.choices and val is not None and val not in opt.choices:
                return False, (
                    f"Invalid value '{val}' for '{name}'. "
                    f"Allowed: {opt.choices}"
                )
        return True, ""

    # -- Abstract interface ------------------------------------------------

    @abstractmethod
    def check_prerequisites(self, **kwargs) -> Tuple[bool, str]:
        """
        Runtime readiness check (e.g. verify connection is alive,
        required tools are on PATH, target object exists in LDAP).

        Returns:
            (ready, reason)  – if not ready, reason explains why.
        """
        ...

    @abstractmethod
    def exploit(self, **kwargs) -> ExploitOutput:
        """
        Core exploitation logic. Must be implemented by every module.

        All keyword arguments come from the user / framework and correspond
        to the options registered via _add_option().

        Returns:
            ExploitOutput with standardised result data.
        """
        ...

    # -- Rollback (optional) -----------------------------------------------

    def rollback(self, **kwargs) -> ExploitOutput:
        """
        Undo the changes made by exploit(). Default = not supported.
        """
        return ExploitOutput(
            success=False,
            result_type=ExploitResult.SKIPPED,
            message="Rollback not supported for this module.",
        )

    # -- Info ---------------------------------------------------------------

    def info(self) -> Dict[str, Any]:
        """Return module metadata (used by 'show modules' / help)."""
        return {
            "name":            self.name,
            "description":     self.description,
            "author":          self.author,
            "edge_type":       self.edge_type,
            "severity":        self.severity.value,
            "references":      self.references,
            "tools_required":  self.tools_required,
            "needs_da":        self.needs_da,
            "needs_privileged": self.needs_privileged,
            "options":         self.get_options(),
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} edge={self.edge_type!r} severity={self.severity.value!r}>"


def new_security_descriptor() -> Any:
    """Create a new, empty, initialized SR_SECURITY_DESCRIPTOR."""
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
    sd = SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 0
    sd['OffsetOwner'] = 0
    sd['OffsetGroup'] = 0
    sd['OffsetSacl'] = 0
    sd['OffsetDacl'] = 0
    sd['OwnerSid'] = b''
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    sd['Dacl'] = b''
    return sd

