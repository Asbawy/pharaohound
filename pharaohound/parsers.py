#!/usr/bin/env python3
"""
parsers.py — Streaming, concurrent BloodHound JSON ingestion.

Two performance upgrades over the legacy single-threaded `json.load()`:

1. **Streaming with ijson** — each BloodHound JSON file is parsed one
   record at a time using ijson's iterative parser. Memory usage stays
   roughly flat regardless of file size (10MB or 10GB).

2. **Parallel loading** — separate JSON files (users / computers / groups /
   domains / gpos / ous / containers) are parsed concurrently in a
   `ThreadPoolExecutor` because parsing is I/O-bound on disk reads.

The streaming parser is also resilient: it tolerates SharpHound files that
mix `meta` types (`users`, `computers`, …) and falls back to a pure-Python
chunked reader if ijson is unavailable.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from .models import BUILDERS, ObjectStore
from .theme import Colors

# ijson is the preferred backend; fall back to a Python chunked reader.
try:
    import ijson  # type: ignore
    _HAVE_IJSON = True
except ImportError:  # pragma: no cover
    _HAVE_IJSON = False


# ═══════════════════════════════════════════════════════════════════════════════
# FILE DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════
def discover_bloodhound_files(directory: str) -> List[Path]:
    """
    Find BloodHound JSON files in `directory`. Matches the SharpHound naming
    convention (`bloodhound.js_*` / `*_computers.json` / `*_users.json` etc.)
    as well as arbitrary `.json` files that contain BloodHound data.
    """
    base = Path(directory)
    if not base.exists():
        return []

    patterns = [
        "bloodhound*.json",
        "*_users.json", "*_computers.json", "*_groups.json",
        "*_domains.json", "*_gpos.json", "*_ous.json",
        "*_containers.json",
        # AD CS (Certipy / SharpHound)
        "*_cas.json", "*_certtemplates.json", "*_certificates.json",
        "*_certificateauthorities.json", "*_certificatetemplates.json",
        # Azure / AzureHound
        "*_azureusers.json", "*_azuregroups.json", "*_azuredevices.json",
        "*_azuretenants.json", "*_azureserviceprincipals.json", "*_azureapps.json",
        "bloodhound.js_*",
    ]
    found: Dict[str, Path] = {}
    for pat in patterns:
        for p in base.glob(pat):
            if p.is_file() and p.stat().st_size > 0:
                found[str(p.resolve())] = p
    return sorted(found.values(), key=lambda p: p.name)


# ═══════════════════════════════════════════════════════════════════════════════
# STREAMING PARSERS
# ═══════════════════════════════════════════════════════════════════════════════
def _stream_with_ijson(filepath: Path) -> Iterator[dict]:
    """Yield BloodHound data records one at a time using ijson."""
    with open(filepath, "rb") as f:
        # ijson.items yields each element of the `data` array
        # Use the `c_backend` if available for ~5x speedup
        try:
            backend = getattr(ijson.backend, "c_backend", "python")
        except AttributeError:
            backend = "python"
        try:
            for record in ijson.items(f, "data.item", use_float=True):
                if isinstance(record, dict):
                    yield record
        except ijson.common.IncompleteJSONError as e:
            raise RuntimeError(f"ijson could not parse {filepath.name}: {e}") from e


def _stream_python_chunked(filepath: Path) -> Iterator[dict]:
    """
    Fallback streaming parser used when ijson is not installed.

    Reads the file in 1MB chunks and uses a lightweight state machine to
    emit top-level records from the `data` array without loading the whole
    JSON document into memory.
    """
    try:
        f = open(filepath, "r", encoding="utf-8", errors="replace")
    except OSError:
        return

    try:
        target = '"data"'
        target_idx = 0
        found_data = False
        remaining_chunk = ""
        
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                return
            
            if not found_data:
                for char_idx, ch in enumerate(chunk):
                    if ch == target[target_idx]:
                        target_idx += 1
                        if target_idx == len(target):
                            found_data = True
                            remaining_chunk = chunk[char_idx + 1:]
                            break
                    else:
                        if ch == target[0]:
                            target_idx = 1
                        else:
                            target_idx = 0
                if not found_data:
                    continue
            else:
                remaining_chunk = chunk

            found_bracket = False
            for char_idx, ch in enumerate(remaining_chunk):
                if ch == "[":
                    found_bracket = True
                    remaining_chunk = remaining_chunk[char_idx + 1:]
                    break
            
            if found_bracket:
                break
            
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    return
                found_bracket = False
                for char_idx, ch in enumerate(chunk):
                    if ch == "[":
                        found_bracket = True
                        remaining_chunk = chunk[char_idx + 1:]
                        break
                if found_bracket:
                    break

            break

        depth = 0
        in_string = False
        escape = False
        obj_chars = []
        
        chunk = remaining_chunk
        while True:
            for ch in chunk:
                if in_string:
                    obj_chars.append(ch)
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == '"':
                        in_string = False
                else:
                    if ch == '"':
                        in_string = True
                        obj_chars.append(ch)
                    elif ch == "{":
                        if depth == 0:
                            obj_chars = ["{"]
                        else:
                            obj_chars.append(ch)
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        obj_chars.append(ch)
                        if depth == 0:
                            obj_text = "".join(obj_chars)
                            try:
                                yield json.loads(obj_text)
                            except json.JSONDecodeError:
                                pass
                            obj_chars = []
                    elif ch == "]" and depth == 0:
                        return
                    elif depth > 0:
                        obj_chars.append(ch)
            
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
    finally:
        f.close()


def stream_records(filepath: Path) -> Iterator[dict]:
    """Yield records from a BloodHound JSON file, preferring ijson."""
    if _HAVE_IJSON:
        try:
            yield from _stream_with_ijson(filepath)
            return
        except Exception:
            # Fall through to python chunked parser
            pass
    yield from _stream_python_chunked(filepath)


# ═══════════════════════════════════════════════════════════════════════════════
# META EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════
def read_meta(filepath: Path) -> Dict[str, Any]:
    """
    Read the `meta` block of a BloodHound JSON file without loading the
    whole file. We do a small bounded read of the first ~64KB and parse
    just the meta portion.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(65536)
        # Find the meta object literal
        idx = head.find('"meta"')
        if idx == -1:
            return {}
        # Find the balanced-brace meta object
        start = head.find("{", idx)
        if start == -1:
            return {}
        depth = 0
        for i in range(start, len(head)):
            c = head[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(head[start : i + 1])
                    except json.JSONDecodeError:
                        return {}
        return {}
    except OSError:
        return {}


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLE-FILE LOADER
# ═══════════════════════════════════════════════════════════════════════════════
@dataclass
class LoadResult:
    filepath: Path
    data_type: str
    count: int = 0
    objects: List[dict] = field(default_factory=list)
    error: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)


def load_single_file(filepath: Path) -> LoadResult:
    """Stream-parse one BloodHound JSON file and return normalized ADObjects."""
    meta = read_meta(filepath)
    data_type = meta.get("type", "").lower()
    # If meta is missing, try to infer from filename
    if not data_type:
        name_lower = filepath.name.lower()
        for t in (
            "users", "computers", "groups", "domains", "gpos", "ous", "containers",
            "cas", "certtemplates", "certificateauthorities", "certificatetemplates",
            "certificates", "azureusers", "azuregroups", "azuredevices", "azuretenants",
            "azureserviceprincipals", "azureapps",
        ):
            if t in name_lower:
                # Normalize legacy names to our canonical builder keys
                if t == "certificateauthorities":
                    data_type = "cas"
                elif t in ("certificatetemplates", "certificates"):
                    data_type = "certtemplates"
                else:
                    data_type = t
                break
    if not data_type:
        data_type = "unknown"

    result = LoadResult(filepath=filepath, data_type=data_type, meta=meta)
    builder: Optional[Callable[[dict], Any]] = BUILDERS.get(data_type)

    try:
        count = 0
        for record in stream_records(filepath):
            if not isinstance(record, dict):
                continue
            if builder:
                result.objects.append(builder(record))
            else:
                # Unknown type — stash raw for completeness
                result.objects.append(record)
            count += 1
        result.count = count
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
        # Print traceback to stderr for debugging without crashing the run
        traceback.print_exc(file=sys.stderr)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# PARALLEL LOADER
# ═══════════════════════════════════════════════════════════════════════════════
def load_directory(
    directory: str,
    max_workers: Optional[int] = None,
    log: Callable[[str], None] = lambda s: None,
) -> ObjectStore:
    """
    Load every BloodHound JSON file in `directory` in parallel and
    register the resulting objects in a single ObjectStore.
    """
    files = discover_bloodhound_files(directory)
    if not files:
        log(f"{Colors.CARNELIAN}[✗] No BloodHound JSON files found in: {directory}{Colors.RESET}")
        log(f"{Colors.OCHRE}    Expected files matching: bloodhound*.json / *_users.json / *_computers.json …{Colors.RESET}")
        return ObjectStore()

    workers = max_workers or min(8, max(2, len(files)))
    log(f"{Colors.GOLD}[☥] Streaming {len(files)} JSON file(s) with {workers} parallel workers…{Colors.RESET}")

    store = ObjectStore()
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pharaohound") as pool:
        futures = {pool.submit(load_single_file, fp): fp for fp in files}
        for fut in as_completed(futures):
            fp = futures[fut]
            try:
                result = fut.result()
            except Exception as e:
                log(f"{Colors.CARNELIAN}[✗] {fp.name}: {type(e).__name__}: {e}{Colors.RESET}")
                continue

            if result.error:
                log(f"{Colors.CARNELIAN}[✗] {fp.name} ({result.data_type}): {result.error}{Colors.RESET}")
                # Still register anything we got before the error
            else:
                backend_tag = "ijson" if _HAVE_IJSON else "py"
                log(
                    f"{Colors.MALACHITE}[✓]{Colors.RESET} "
                    f"{Colors.BOLD}{fp.name}{Colors.RESET}  "
                    f"{Colors.TURQUOISE}({result.data_type}: {result.count} objects, "
                    f"backend={backend_tag}){Colors.RESET}"
                )

            builder = BUILDERS.get(result.data_type)
            if not builder:
                continue
            for obj in result.objects:
                # objects were already built; register directly
                try:
                    store.register(obj)
                except Exception:
                    # Don't let a single bad object kill the whole run
                    continue

    log(f"{Colors.GOLD}[☥] Ingestion complete. Beginning ritual of analysis…{Colors.RESET}\n")
    return store


__all__ = [
    "discover_bloodhound_files",
    "load_single_file",
    "load_directory",
    "stream_records",
    "read_meta",
    "LoadResult",
]
