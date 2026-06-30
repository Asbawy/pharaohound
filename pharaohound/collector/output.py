#!/usr/bin/env python3
"""
output.py — BloodHound-compatible JSON file writer.

Writes collected AD data into JSON files that match the SharpHound
export format, so they can be ingested by Pharaohound's existing
parsers and by the BloodHound GUI.

Supports output to:
  - A directory of individual JSON files
  - A ZIP archive containing all JSON files
"""

from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..theme import Colors


# COLLECTION METADATA
BLOODHOUND_VERSION = 5
COLLECTOR_NAME = "Pharaohound"


def _build_meta(data_type: str, count: int, methods: int = 0) -> Dict[str, Any]:
    """Build a BloodHound-compatible meta block."""
    return {
        "methods": methods,
        "type": data_type,
        "count": count,
        "version": BLOODHOUND_VERSION,
    }


# JSON FILE NAMES
# Maps data type to the file suffix used by SharpHound.
TYPE_FILE_MAP = {
    "users": "users",
    "groups": "groups",
    "computers": "computers",
    "domains": "domains",
    "gpos": "gpos",
    "ous": "ous",
    "containers": "containers",
    "cas": "cas",
    "certtemplates": "certtemplates",
}


# COLLECTION OUTPUT
class CollectionOutput:
    """
    Writes collected AD data to BloodHound-compatible JSON files.

    Usage:
        output = CollectionOutput(output_dir="/path/to/output", use_zip=True)
        output.write("users", user_objects)
        output.write("groups", group_objects)
        output.finalize()  # Creates ZIP if use_zip=True
    """

    def __init__(
        self,
        output_dir: str = ".",
        use_zip: bool = True,
        domain_name: str = "",
    ) -> None:
        self.output_dir = os.path.abspath(output_dir)
        self.use_zip = use_zip
        self.domain_name = domain_name
        self.timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

        # Track written files for ZIP creation
        self._written_files: List[str] = []
        self._stats: Dict[str, int] = {}

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

    def write(self, data_type: str, objects: List[Dict[str, Any]]) -> Optional[str]:
        """
        Write a collection of objects to a BloodHound JSON file.

        Args:
            data_type: The type of objects (e.g., "users", "groups").
            objects: List of BloodHound-format object dicts.

        Returns:
            The path to the written file, or None on failure.
        """
        if not objects:
            return None

        file_suffix = TYPE_FILE_MAP.get(data_type, data_type)
        filename = f"{self.timestamp}_{file_suffix}.json"
        filepath = os.path.join(self.output_dir, filename)

        meta = _build_meta(data_type, len(objects))

        bloodhound_json = {
            "data": objects,
            "meta": meta,
        }

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(bloodhound_json, f, indent=2, default=str)

            self._written_files.append(filepath)
            self._stats[data_type] = len(objects)

            print(
                f"  {Colors.MALACHITE}[✓]{Colors.RESET} "
                f"Saved {Colors.TURQUOISE}{len(objects)}{Colors.RESET} "
                f"{data_type} → {Colors.DIM}{filename}{Colors.RESET}"
            )
            return filepath

        except Exception as e:
            print(
                f"  {Colors.CARNELIAN}[✗]{Colors.RESET} "
                f"Failed to write {data_type}: {e}"
            )
            return None

    def finalize(self) -> Optional[str]:
        """
        Finalize the output. If use_zip is True, creates a ZIP archive
        containing all written JSON files and removes the individual files.

        Returns:
            The path to the ZIP file (if created), or the output directory.
        """
        if not self._written_files:
            print(f"  {Colors.OCHRE}[!] No data files to finalize.{Colors.RESET}")
            return None

        zip_path = None

        if self.use_zip:
            domain_slug = self.domain_name.replace(".", "_").lower() if self.domain_name else "collection"
            zip_name = f"{self.timestamp}_{domain_slug}_pharaohound.zip"
            zip_path = os.path.join(self.output_dir, zip_name)

            try:
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for fpath in self._written_files:
                        zf.write(fpath, os.path.basename(fpath))

                # Remove individual JSON files after zipping
                for fpath in self._written_files:
                    try:
                        os.remove(fpath)
                    except OSError:
                        pass

                # Get ZIP size
                zip_size = os.path.getsize(zip_path)
                size_str = _format_size(zip_size)

                print(
                    f"\n  {Colors.MALACHITE}[✓]{Colors.RESET} "
                    f"Collection archived → {Colors.TURQUOISE}{zip_name}{Colors.RESET} "
                    f"({size_str})"
                )
                return zip_path

            except Exception as e:
                print(
                    f"  {Colors.OCHRE}[!]{Colors.RESET} "
                    f"Failed to create ZIP: {e}. JSON files kept in {self.output_dir}"
                )

        # Print summary for non-zip output
        print(
            f"\n  {Colors.MALACHITE}[✓]{Colors.RESET} "
            f"Collection saved to: {Colors.TURQUOISE}{self.output_dir}{Colors.RESET}"
        )
        return self.output_dir

    @property
    def stats(self) -> Dict[str, int]:
        """Return collection statistics by type."""
        return dict(self._stats)

    @property
    def total_objects(self) -> int:
        """Return total number of collected objects."""
        return sum(self._stats.values())

    @property
    def file_count(self) -> int:
        """Return number of written files."""
        return len(self._written_files)

    def summary_text(self) -> str:
        """Return a formatted summary of the collection."""
        lines = [f"Collection Summary ({self.domain_name}):"]
        for dtype, count in sorted(self._stats.items()):
            lines.append(f"  {dtype}: {count}")
        lines.append(f"  Total: {self.total_objects}")
        return "\n".join(lines)


def _format_size(size_bytes: int) -> str:
    """Format a byte count as a human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
