#!/usr/bin/env python3
"""
analyzers.base — Abstract analyzer base class + finding dataclass.

Every analyzer is a small, self-contained class with a single
`analyze(store)` method that returns a `Finding` (or None). The
registry discovers all subclasses automatically, so adding a new
check is a one-file drop-in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models import ObjectStore
from ..theme import Severity


@dataclass
class Finding:
    title: str
    summary: str
    severity: str
    data: List[Dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""
    eli5: Optional[str] = None
    remediation: Optional[str] = None
    playbooks: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "data": self.data,
            "recommendation": self.recommendation,
            "eli5": self.eli5,
            "remediation": self.remediation,
            "playbooks": self.playbooks,
            "timestamp": self.timestamp,
        }


class BaseAnalyzer:
    """
    Base class for every analyzer module.

    Subclasses should set:
      - `name`: short identifier used in progress logs
      - `description`: human-readable description

    And implement:
      - `analyze(store) -> Optional[Finding]`
    """

    name: str = "base"
    description: str = "Base analyzer"
    default_severity: str = Severity.INFO

    def __init__(self) -> None:
        pass

    def analyze(self, store: ObjectStore) -> Optional[Finding]:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<Analyzer:{self.name}>"
