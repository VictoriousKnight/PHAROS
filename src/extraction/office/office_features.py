"""
Office document feature extraction.

This module aggregates static Office-document analysis into a single,
ML-friendly feature representation.

Supported document families:
    - OOXML: .docx, .docm, .dotx, .dotm
    - OOXML: .xlsx, .xlsm, .xltx, .xltm
    - OOXML: .pptx, .pptm, .potx, .potm, .ppsx, .ppsm
    - Legacy OLE/Compound File documents when sufficient metadata is available

The module is intentionally static-only:
    - no Office application is launched
    - no VBA/XLM/script is executed
    - no external URL is contacted
    - no embedded payload is executed
    - no macros are evaluated

Architecture:

    document
        |
        +--> relationships
        +--> embedded objects
        +--> OLE analysis
        +--> XLM analysis
        |
        v
    OfficeAnalysis
        |
        +--> semantic Office indicators
        +--> scalar ML features
        |
        v
    feature_pipeline.py

The feature names are deliberately explicit and stable so that downstream
ML training and inference can consume them deterministically.
"""

from __future__ import annotations

import hashlib
import math
import re
import zipfile

from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import (
    Any,
    BinaryIO,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

try:
    from .relationships import (
        RelationshipAnalysis,
        RelationshipRecord,
        analyze_relationships,
        analyze_relationships_file,
    )
except ImportError:
    RelationshipAnalysis = Any
    RelationshipRecord = Any

    def analyze_relationships(*args: Any, **kwargs: Any) -> Any:
        raise ImportError("relationships.py is required")

    def analyze_relationships_file(*args: Any, **kwargs: Any) -> Any:
        raise ImportError("relationships.py is required")


try:
    from .embedded_objects import (
        EmbeddedObjectAnalysis,
        EmbeddedObjectRecord,
        analyze_embedded_objects,
        analyze_embedded_objects_file,
    )
except ImportError:
    EmbeddedObjectAnalysis = Any
    EmbeddedObjectRecord = Any

    def analyze_embedded_objects(*args: Any, **kwargs: Any) -> Any:
        raise ImportError("embedded_objects.py is required")

    def analyze_embedded_objects_file(*args: Any, **kwargs: Any) -> Any:
        raise ImportError("embedded_objects.py is required")


try:
    from .ole import (
        OLEAnalysis,
        analyze_ole,
        analyze_ole_file,
    )
except ImportError:
    OLEAnalysis = Any

    def analyze_ole(*args: Any, **kwargs: Any) -> Any:
        raise ImportError("ole.py is required")

    def analyze_ole_file(*args: Any, **kwargs: Any) -> Any:
        raise ImportError("ole.py is required")


try:
    from .xlm import (
        XLMAnalysis,
        analyze_xlm,
        analyze_xlm_file,
    )
except ImportError:
    XLMAnalysis = Any

    def analyze_xlm(*args: Any, **kwargs: Any) -> Any:
        raise ImportError("xlm.py is required")

    def analyze_xlm_file(*args: Any, **kwargs: Any) -> Any:
        raise ImportError("xlm.py is required")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_FEATURE_STRING_LENGTH = 512
MAX_ZIP_ENTRIES = 100_000
MAX_ZIP_ENTRY_SIZE = 100 * 1024 * 1024

OOXML_EXTENSIONS = {
    ".docx",
    ".docm",
    ".dotx",
    ".dotm",
    ".xlsx",
    ".xlsm",
    ".xltx",
    ".xltm",
    ".pptx",
    ".pptm",
    ".potx",
    ".potm",
    ".ppsx",
    ".ppsm",
}

MACRO_ENABLED_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".pptm",
    ".potm",
    ".ppsm",
}

WORD_EXTENSIONS = {
    ".docx",
    ".docm",
    ".dotx",
    ".dotm",
}

EXCEL_EXTENSIONS = {
    ".xlsx",
    ".xlsm",
    ".xltx",
    ".xltm",
}

POWERPOINT_EXTENSIONS = {
    ".pptx",
    ".pptm",
    ".potx",
    ".potm",
    ".ppsx",
    ".ppsm",
}

# OOXML relationship type fragments.
REL_EXTERNAL = "external"
REL_HYPERLINK = "hyperlink"
REL_OLE = "oleobject"
REL_PACKAGE = "package"
REL_CONTROL = "control"
REL_IMAGE = "image"
REL_VML = "vml"
REL_ATTACHMENT = "attachment"

# Office ZIP parts commonly associated with active or executable content.
ACTIVE_CONTENT_PARTS = (
    "vbaproject.bin",
    "vbaProject.bin",
    "activeX/",
    "embeddings/",
    "customUI/",
    "customui/",
    "xl/macrosheets/",
    "xl/macroSheets/",
)

# Suspicious strings are used only as static indicators.
EXECUTION_TERMS = (
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "wmic.exe",
    "certutil.exe",
    "bitsadmin.exe",
)

DOWNLOAD_TERMS = (
    "urlmon",
    "winhttp",
    "wininet",
    "xmlhttp",
    "http://",
    "https://",
    "ftp://",
    "download",
)

PERSISTENCE_TERMS = (
    "run key",
    "runonce",
    "startup",
    "scheduled task",
    "schtasks",
    "service",
    "wmi subscription",
)

CREDENTIAL_TERMS = (
    "password",
    "credential",
    "logon",
    "token",
    "browser",
    "cookie",
    "wallet",
)

OBFUSCATION_TERMS = (
    "chr(",
    "char(",
    "concatenate",
    "indirect",
    "decode",
    "base64",
    "hex",
    "xor",
    "obfuscat",
)

NETWORK_TERMS = (
    "http://",
    "https://",
    "ftp://",
    "smtp://",
    "tcp://",
    "\\\\",
)

DYNAMIC_REFERENCE_TERMS = (
    "indirect",
    "offset",
    "evaluate",
    "get.cell",
    "get.document",
    "get.workbook",
)

# Generic URL / IP / Windows-path patterns used when examining XML/formulas.
URL_RE = re.compile(rb"(?i)\b(?:https?|ftp)://[^\s\"'<>]+")

IPV4_RE = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}" rb"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

WINDOWS_PATH_RE = re.compile(rb"(?i)(?:[a-z]:\\|\\\\)[^<>\"\r\n]{2,}")

XML_EXTERNAL_TARGET_RE = re.compile(
    rb"(?i)(?:TargetMode\s*=\s*[\"']External[\"']|"
    rb"Target\s*=\s*[\"'](?:https?|ftp)://)"
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OfficePartRecord:
    """Metadata for one OOXML ZIP member."""

    name: str
    size: int
    compressed_size: int
    compression_ratio: float
    is_xml: bool
    is_macro_related: bool
    is_embedding: bool
    is_active_x: bool
    is_relationship: bool


@dataclass(frozen=True)
class OfficeAnalysis:
    """
    Complete aggregated Office static analysis.

    `features` contains scalar values suitable for ML pipelines.

    `indicators` contains human-readable semantic findings.
    """

    file_name: str
    extension: str
    document_family: str

    is_ooxml: bool
    is_macro_enabled_extension: bool
    is_zip_based: bool
    is_legacy_ole: bool

    has_vba_project: bool
    has_xlm: bool
    has_embedded_objects: bool
    has_activex: bool
    has_external_relationships: bool
    has_external_targets: bool
    has_hyperlinks: bool

    part_count: int
    xml_part_count: int
    relationship_part_count: int
    macro_related_part_count: int
    embedding_part_count: int
    activex_part_count: int

    total_uncompressed_size: int
    total_compressed_size: int
    compression_ratio: float

    relationship_analysis: Optional[Any] = None
    embedded_analysis: Optional[Any] = None
    ole_analysis: Optional[Any] = None
    xlm_analysis: Optional[Any] = None

    parts: Tuple[OfficePartRecord, ...] = field(default_factory=tuple)

    indicators: Tuple[str, ...] = field(default_factory=tuple)

    feature_vector: Dict[str, float] = field(default_factory=dict)
    features: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------


def _read_input(
    source: Union[str, Path, bytes, bytearray, memoryview, BinaryIO],
    *,
    max_size: Optional[int] = None,
) -> Tuple[bytes, str]:
    """
    Read supported input into memory.

    Returns:
        (data, display_name)
    """

    if isinstance(source, bytes):
        data = source
        name = "<memory>"
    elif isinstance(source, bytearray):
        data = bytes(source)
        name = "<memory>"
    elif isinstance(source, memoryview):
        data = source.tobytes()
        name = "<memory>"
    elif isinstance(source, (str, Path)):
        path = Path(source)

        if not path.is_file():
            raise FileNotFoundError(str(path))

        if max_size is not None and path.stat().st_size > max_size:
            raise ValueError(
                f"File exceeds configured maximum size: {path.stat().st_size}"
            )

        data = path.read_bytes()
        name = path.name
    elif hasattr(source, "read"):
        name = Path(getattr(source, "name", "<stream>")).name
        data = source.read()

        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
    else:
        raise TypeError(
            "source must be a path, bytes-like object, or binary file object"
        )

    if max_size is not None and len(data) > max_size:
        raise ValueError(f"Input exceeds configured maximum size: {len(data)}")

    return data, name


def _extension(name: str) -> str:
    return Path(name).suffix.lower()


def _detect_ooxml(data: bytes) -> bool:
    """
    Detect OOXML using ZIP signature and expected Office parts.

    We do not rely solely on the extension.
    """

    if not data.startswith(b"PK"):
        return False

    try:
        with zipfile.ZipFile(
            __import__("io").BytesIO(data),
            "r",
        ) as zf:
            names = {name.replace("\\", "/").lower() for name in zf.namelist()}

            if "[content_types].xml" not in names:
                return False

            office_markers = (
                "word/",
                "xl/",
                "ppt/",
            )

            return any(
                any(name.startswith(marker) for marker in office_markers)
                for name in names
            )
    except (zipfile.BadZipFile, OSError, ValueError):
        return False


def _detect_legacy_ole(data: bytes) -> bool:
    """Detect a Compound File Binary/OLE container by magic."""

    return data.startswith(bytes.fromhex("D0CF11E0A1B11AE10000000000000000"))


def _document_family(extension: str, data: bytes) -> str:
    """
    Determine broad Office document family.
    """

    if extension in WORD_EXTENSIONS:
        return "word"

    if extension in EXCEL_EXTENSIONS:
        return "excel"

    if extension in POWERPOINT_EXTENSIONS:
        return "powerpoint"

    if _detect_ooxml(data):
        try:
            with zipfile.ZipFile(__import__("io").BytesIO(data), "r") as zf:
                names = {n.replace("\\", "/").lower() for n in zf.namelist()}

                if any(n.startswith("word/") for n in names):
                    return "word"

                if any(n.startswith("xl/") for n in names):
                    return "excel"

                if any(n.startswith("ppt/") for n in names):
                    return "powerpoint"
        except Exception:
            pass

    if _detect_legacy_ole(data):
        return "ole"

    return "unknown"


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0

    return float(numerator) / float(denominator)


def _normalise_text(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return str(value)


def _safe_get(obj: Any, *names: str, default: Any = None) -> Any:
    """
    Retrieve a field from either a dataclass/object or mapping.

    This allows this aggregation layer to tolerate minor implementation
    differences between lower-level analyzers.
    """

    for name in names:
        if obj is None:
            continue

        if isinstance(obj, Mapping):
            if name in obj:
                return obj[name]

        if hasattr(obj, name):
            try:
                return getattr(obj, name)
            except Exception:
                continue

    return default


def _safe_bool(obj: Any, *names: str) -> bool:
    value = _safe_get(obj, *names, default=False)

    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return value != 0

    if isinstance(value, str):
        return value.strip().lower() in {
            "true",
            "yes",
            "y",
            "1",
        }

    return bool(value)


def _safe_int(obj: Any, *names: str, default: int = 0) -> int:
    value = _safe_get(obj, *names, default=default)

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(obj: Any, *names: str, default: float = 0.0) -> float:
    value = _safe_get(obj, *names, default=default)

    try:
        result = float(value)

        if math.isfinite(result):
            return result

    except (TypeError, ValueError):
        pass

    return default


# ---------------------------------------------------------------------------
# ZIP/OOXML analysis
# ---------------------------------------------------------------------------


def _classify_part(name: str) -> OfficePartRecord:
    normalised = name.replace("\\", "/")
    lower = normalised.lower()

    is_xml = lower.endswith(".xml") or lower.endswith(".rels")

    is_macro_related = (
        "vbaproject.bin" in lower
        or "macrosheet" in lower
        or "/vba/" in lower
        or lower.endswith("/vba.bin")
    )

    is_embedding = (
        lower.startswith("word/embeddings/")
        or lower.startswith("xl/embeddings/")
        or lower.startswith("ppt/embeddings/")
        or "/embeddings/" in lower
    )

    is_active_x = (
        lower.startswith("word/activex/")
        or lower.startswith("xl/activex/")
        or lower.startswith("ppt/activex/")
        or "/activex/" in lower
        or lower.endswith("activeX".lower())
    )

    is_relationship = (
        lower.endswith(".rels") or "/_rels/" in lower or lower.startswith("_rels/")
    )

    return OfficePartRecord(
        name=normalised,
        size=0,
        compressed_size=0,
        compression_ratio=0.0,
        is_xml=is_xml,
        is_macro_related=is_macro_related,
        is_embedding=is_embedding,
        is_active_x=is_active_x,
        is_relationship=is_relationship,
    )


def _analyse_ooxml_parts(data: bytes) -> Tuple[
    Tuple[OfficePartRecord, ...],
    Dict[str, Any],
]:
    """
    Inspect OOXML package members without extracting them.

    Returns:
        parts, aggregate statistics
    """

    import io

    parts: List[OfficePartRecord] = []

    total_size = 0
    total_compressed = 0
    xml_count = 0
    relationship_count = 0
    macro_count = 0
    embedding_count = 0
    activex_count = 0

    if not data.startswith(b"PK"):
        return tuple(), {
            "part_count": 0,
            "xml_part_count": 0,
            "relationship_part_count": 0,
            "macro_related_part_count": 0,
            "embedding_part_count": 0,
            "activex_part_count": 0,
            "total_uncompressed_size": 0,
            "total_compressed_size": 0,
        }

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            infos = zf.infolist()

            if len(infos) > MAX_ZIP_ENTRIES:
                raise ValueError(
                    f"OOXML package contains too many entries: {len(infos)}"
                )

            for info in infos:
                name = info.filename.replace("\\", "/")

                if info.file_size > MAX_ZIP_ENTRY_SIZE:
                    # Do not read it; metadata is still useful.
                    pass

                is_xml = name.lower().endswith((".xml", ".rels"))

                is_relationship = (
                    name.lower().endswith(".rels")
                    or "/_rels/" in name.lower()
                    or name.lower().startswith("_rels/")
                )

                is_macro_related = (
                    "vbaproject.bin" in name.lower() or "macrosheet" in name.lower()
                )

                is_embedding = (
                    "/embeddings/" in name.lower()
                    or name.lower().startswith(
                        (
                            "word/embeddings/",
                            "xl/embeddings/",
                            "ppt/embeddings/",
                        )
                    )
                )

                is_activex = "/activex/" in name.lower()

                ratio = _safe_ratio(
                    info.file_size,
                    info.compress_size,
                )

                record = OfficePartRecord(
                    name=name,
                    size=int(info.file_size),
                    compressed_size=int(info.compress_size),
                    compression_ratio=ratio,
                    is_xml=is_xml,
                    is_macro_related=is_macro_related,
                    is_embedding=is_embedding,
                    is_active_x=is_activex,
                    is_relationship=is_relationship,
                )

                parts.append(record)

                total_size += int(info.file_size)
                total_compressed += int(info.compress_size)

                xml_count += int(is_xml)
                relationship_count += int(is_relationship)
                macro_count += int(is_macro_related)
                embedding_count += int(is_embedding)
                activex_count += int(is_activex)

    except zipfile.BadZipFile:
        return tuple(), {
            "part_count": 0,
            "xml_part_count": 0,
            "relationship_part_count": 0,
            "macro_related_part_count": 0,
            "embedding_part_count": 0,
            "activex_part_count": 0,
            "total_uncompressed_size": 0,
            "total_compressed_size": 0,
        }

    return tuple(parts), {
        "part_count": len(parts),
        "xml_part_count": xml_count,
        "relationship_part_count": relationship_count,
        "macro_related_part_count": macro_count,
        "embedding_part_count": embedding_count,
        "activex_part_count": activex_count,
        "total_uncompressed_size": total_size,
        "total_compressed_size": total_compressed,
    }


def _read_relevant_ooxml_content(
    data: bytes,
    *,
    max_total_bytes: int = 20 * 1024 * 1024,
) -> bytes:
    """
    Build a bounded static corpus from XML/relation parts.

    This is useful for broad semantic indicators that should not depend
    entirely on one lower-level analyzer.

    Only selected text-like XML parts are read.
    """

    import io

    chunks: List[bytes] = []
    consumed = 0

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            for info in zf.infolist():
                name = info.filename.replace("\\", "/").lower()

                if not (name.endswith(".xml") or name.endswith(".rels")):
                    continue

                if info.file_size > max_total_bytes:
                    continue

                remaining = max_total_bytes - consumed

                if remaining <= 0:
                    break

                try:
                    chunk = zf.read(info)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    continue

                if len(chunk) > remaining:
                    chunk = chunk[:remaining]

                chunks.append(chunk)
                consumed += len(chunk)

    except (zipfile.BadZipFile, OSError, ValueError):
        return b""

    return b"\n".join(chunks)


# ---------------------------------------------------------------------------
# Relationship helpers
# ---------------------------------------------------------------------------


def _relationship_records(analysis: Any) -> List[Any]:
    for name in (
        "relationships",
        "records",
        "relationship_records",
        "items",
    ):
        value = _safe_get(analysis, name, default=None)

        if value is not None:
            try:
                return list(value)
            except TypeError:
                pass

    return []


def _relationship_target(record: Any) -> str:
    return _normalise_text(
        _safe_get(
            record,
            "target",
            "target_ref",
            "target_url",
            "value",
            default="",
        )
    )


def _relationship_type(record: Any) -> str:
    return _normalise_text(
        _safe_get(
            record,
            "relationship_type",
            "type",
            "rel_type",
            default="",
        )
    ).lower()


def _relationship_is_external(record: Any) -> bool:
    if _safe_bool(
        record,
        "is_external",
        "external",
    ):
        return True

    return "external" in _relationship_type(record)


def _relationship_is_hyperlink(record: Any) -> bool:
    if _safe_bool(
        record,
        "is_hyperlink",
        "hyperlink",
    ):
        return True

    return REL_HYPERLINK in _relationship_type(record)


def _relationship_is_ole(record: Any) -> bool:
    if _safe_bool(
        record,
        "is_ole",
        "is_ole_object",
        "ole",
    ):
        return True

    rel_type = _relationship_type(record)

    return REL_OLE in rel_type or REL_PACKAGE in rel_type


def _relationship_is_control(record: Any) -> bool:
    if _safe_bool(
        record,
        "is_control",
        "control",
    ):
        return True

    return REL_CONTROL in _relationship_type(record)


def _relationship_statistics(analysis: Any) -> Dict[str, int]:
    records = _relationship_records(analysis)

    external = 0
    hyperlinks = 0
    ole = 0
    controls = 0
    network = 0
    targets_with_paths = 0

    for record in records:
        target = _relationship_target(record).lower()
        rel_type = _relationship_type(record)

        external += int(_relationship_is_external(record))
        hyperlinks += int(_relationship_is_hyperlink(record))
        ole += int(_relationship_is_ole(record))
        controls += int(_relationship_is_control(record))

        network += int(
            target.startswith(
                (
                    "http://",
                    "https://",
                    "ftp://",
                )
            )
            or any(term in target for term in NETWORK_TERMS)
            or "hyperlink" in rel_type
        )

        targets_with_paths += int(
            bool(
                re.search(
                    r"(?i)(?:[a-z]:\\|\\\\)",
                    target,
                )
            )
        )

    return {
        "relationship_count": len(records),
        "external_relationship_count": external,
        "hyperlink_relationship_count": hyperlinks,
        "ole_relationship_count": ole,
        "control_relationship_count": controls,
        "network_relationship_count": network,
        "path_relationship_count": targets_with_paths,
    }


# ---------------------------------------------------------------------------
# Embedded object helpers
# ---------------------------------------------------------------------------


def _embedded_records(analysis: Any) -> List[Any]:
    for name in (
        "objects",
        "embedded_objects",
        "records",
        "items",
    ):
        value = _safe_get(analysis, name, default=None)

        if value is not None:
            try:
                return list(value)
            except TypeError:
                pass

    return []


def _embedded_statistics(analysis: Any) -> Dict[str, int]:
    records = _embedded_records(analysis)

    ole = 0
    pe = 0
    pdf = 0
    script = 0
    archive = 0
    mismatches = 0
    active_x = 0

    for record in records:
        type_name = _normalise_text(
            _safe_get(
                record,
                "detected_type",
                "object_type",
                "file_type",
                "type",
                default="",
            )
        ).lower()

        ole += int("ole" in type_name or "compound" in type_name or "cfb" in type_name)

        pe += int(
            type_name
            in {
                "pe",
                "pe32",
                "pe32+",
                "windows_pe",
                "portable_executable",
            }
            or "portable executable" in type_name
        )

        pdf += int("pdf" in type_name)

        script += int(
            any(
                marker in type_name
                for marker in (
                    "script",
                    "javascript",
                    "vbscript",
                    "powershell",
                )
            )
        )

        archive += int(
            any(
                marker in type_name
                for marker in (
                    "zip",
                    "rar",
                    "7z",
                    "cab",
                    "gzip",
                    "archive",
                )
            )
        )

        mismatches += int(
            _safe_bool(
                record,
                "extension_mismatch",
                "type_extension_mismatch",
                "mismatch",
            )
        )

        active_x += int(
            _safe_bool(
                record,
                "is_activex",
                "activex",
                "is_control",
            )
        )

    return {
        "embedded_object_count": len(records),
        "embedded_ole_count": ole,
        "embedded_pe_count": pe,
        "embedded_pdf_count": pdf,
        "embedded_script_count": script,
        "embedded_archive_count": archive,
        "embedded_extension_mismatch_count": mismatches,
        "embedded_activex_count": active_x,
    }


# ---------------------------------------------------------------------------
# OLE helpers
# ---------------------------------------------------------------------------


def _ole_statistics(analysis: Any) -> Dict[str, int]:
    if analysis is None:
        return {
            "ole_stream_count": 0,
            "ole_storage_count": 0,
            "ole_vba_stream_count": 0,
            "ole_macro_indicator_count": 0,
            "ole_suspicious_stream_count": 0,
            "ole_external_link_count": 0,
        }

    return {
        "ole_stream_count": _safe_int(
            analysis,
            "stream_count",
            "total_streams",
            default=0,
        ),
        "ole_storage_count": _safe_int(
            analysis,
            "storage_count",
            "total_storages",
            default=0,
        ),
        "ole_vba_stream_count": _safe_int(
            analysis,
            "vba_stream_count",
            "macro_stream_count",
            default=0,
        ),
        "ole_macro_indicator_count": _safe_int(
            analysis,
            "macro_indicator_count",
            "suspicious_macro_count",
            default=0,
        ),
        "ole_suspicious_stream_count": _safe_int(
            analysis,
            "suspicious_stream_count",
            default=0,
        ),
        "ole_external_link_count": _safe_int(
            analysis,
            "external_link_count",
            "external_links",
            default=0,
        ),
    }


# ---------------------------------------------------------------------------
# XLM helpers
# ---------------------------------------------------------------------------


def _xlm_statistics(analysis: Any) -> Dict[str, int]:
    if analysis is None:
        return {
            "xlm_formula_count": 0,
            "xlm_suspicious_formula_count": 0,
            "xlm_macrosheet_count": 0,
            "xlm_hidden_macrosheet_count": 0,
            "xlm_very_hidden_macrosheet_count": 0,
            "xlm_defined_name_count": 0,
            "xlm_suspicious_defined_name_count": 0,
            "xlm_execution_indicator_count": 0,
            "xlm_network_indicator_count": 0,
            "xlm_download_indicator_count": 0,
            "xlm_obfuscation_indicator_count": 0,
            "xlm_dynamic_reference_indicator_count": 0,
        }

    return {
        "xlm_formula_count": _safe_int(
            analysis,
            "formula_count",
            "xlm_formula_count",
            default=0,
        ),
        "xlm_suspicious_formula_count": _safe_int(
            analysis,
            "suspicious_formula_count",
            "suspicious_formulas",
            default=0,
        ),
        "xlm_macrosheet_count": _safe_int(
            analysis,
            "macrosheet_count",
            "macro_sheet_count",
            default=0,
        ),
        "xlm_hidden_macrosheet_count": _safe_int(
            analysis,
            "hidden_macrosheet_count",
            default=0,
        ),
        "xlm_very_hidden_macrosheet_count": _safe_int(
            analysis,
            "very_hidden_macrosheet_count",
            default=0,
        ),
        "xlm_defined_name_count": _safe_int(
            analysis,
            "defined_name_count",
            default=0,
        ),
        "xlm_suspicious_defined_name_count": _safe_int(
            analysis,
            "suspicious_defined_name_count",
            default=0,
        ),
        "xlm_execution_indicator_count": _safe_int(
            analysis,
            "execution_indicator_count",
            "execution_count",
            default=0,
        ),
        "xlm_network_indicator_count": _safe_int(
            analysis,
            "network_indicator_count",
            "network_count",
            default=0,
        ),
        "xlm_download_indicator_count": _safe_int(
            analysis,
            "download_indicator_count",
            "download_count",
            default=0,
        ),
        "xlm_obfuscation_indicator_count": _safe_int(
            analysis,
            "obfuscation_indicator_count",
            "obfuscation_count",
            default=0,
        ),
        "xlm_dynamic_reference_indicator_count": _safe_int(
            analysis,
            "dynamic_reference_indicator_count",
            "dynamic_reference_count",
            default=0,
        ),
    }


# ---------------------------------------------------------------------------
# Raw static indicators
# ---------------------------------------------------------------------------


def _count_terms(corpus: bytes, terms: Sequence[str]) -> int:
    text = corpus.decode("utf-8", errors="ignore").lower()

    return sum(text.count(term.lower()) for term in terms)


def _static_content_statistics(
    data: bytes,
    corpus: bytes,
) -> Dict[str, int]:
    """
    Detect broad static indicators from OOXML XML/relation content.

    This is deliberately supplementary to the specialized analyzers.
    """

    lowered = corpus.lower()

    url_count = len(URL_RE.findall(corpus))
    ipv4_count = len(IPV4_RE.findall(corpus))
    windows_path_count = len(WINDOWS_PATH_RE.findall(corpus))

    return {
        "static_url_count": url_count,
        "static_ipv4_count": ipv4_count,
        "static_windows_path_count": windows_path_count,
        "static_execution_indicator_count": _count_terms(
            corpus,
            EXECUTION_TERMS,
        ),
        "static_download_indicator_count": _count_terms(
            corpus,
            DOWNLOAD_TERMS,
        ),
        "static_persistence_indicator_count": _count_terms(
            corpus,
            PERSISTENCE_TERMS,
        ),
        "static_credential_indicator_count": _count_terms(
            corpus,
            CREDENTIAL_TERMS,
        ),
        "static_obfuscation_indicator_count": _count_terms(
            corpus,
            OBFUSCATION_TERMS,
        ),
        "static_network_indicator_count": _count_terms(
            corpus,
            NETWORK_TERMS,
        ),
        "static_dynamic_reference_indicator_count": _count_terms(
            corpus,
            DYNAMIC_REFERENCE_TERMS,
        ),
        "static_external_target_count": len(XML_EXTERNAL_TARGET_RE.findall(corpus)),
        "static_unique_keyword_count": len(
            {
                token
                for token in re.findall(
                    rb"[A-Za-z][A-Za-z0-9_.-]{2,63}",
                    lowered,
                )
            }
        ),
        "static_corpus_size": len(corpus),
        "raw_size": len(data),
    }


# ---------------------------------------------------------------------------
# Semantic indicator generation
# ---------------------------------------------------------------------------


def _generate_indicators(
    *,
    extension: str,
    family: str,
    macro_enabled_extension: bool,
    has_vba: bool,
    has_xlm: bool,
    has_embedded: bool,
    has_activex: bool,
    has_external_relationships: bool,
    has_external_targets: bool,
    has_hyperlinks: bool,
    rel_stats: Mapping[str, int],
    embedded_stats: Mapping[str, int],
    ole_stats: Mapping[str, int],
    xlm_stats: Mapping[str, int],
    static_stats: Mapping[str, int],
) -> Tuple[str, ...]:

    indicators: List[str] = []

    if macro_enabled_extension:
        indicators.append("macro_enabled_extension")

    if has_vba:
        indicators.append("vba_project_present")

    if has_xlm:
        indicators.append("xlm_content_present")

    if has_embedded:
        indicators.append("embedded_objects_present")

    if has_activex:
        indicators.append("activex_content_present")

    if has_external_relationships:
        indicators.append("external_relationship_present")

    if has_external_targets:
        indicators.append("external_target_present")

    if has_hyperlinks:
        indicators.append("hyperlinks_present")

    if rel_stats.get("ole_relationship_count", 0) > 0:
        indicators.append("ole_relationship_present")

    if rel_stats.get("control_relationship_count", 0) > 0:
        indicators.append("control_relationship_present")

    if embedded_stats.get("embedded_ole_count", 0) > 0:
        indicators.append("embedded_ole_present")

    if embedded_stats.get("embedded_pe_count", 0) > 0:
        indicators.append("embedded_pe_present")

    if embedded_stats.get("embedded_script_count", 0) > 0:
        indicators.append("embedded_script_present")

    if embedded_stats.get("embedded_extension_mismatch_count", 0) > 0:
        indicators.append("embedded_extension_mismatch")

    if ole_stats.get("ole_vba_stream_count", 0) > 0:
        indicators.append("ole_vba_stream_present")

    if ole_stats.get("ole_suspicious_stream_count", 0) > 0:
        indicators.append("ole_suspicious_stream_present")

    if xlm_stats.get("xlm_macrosheet_count", 0) > 0:
        indicators.append("xlm_macrosheet_present")

    if xlm_stats.get("xlm_hidden_macrosheet_count", 0) > 0:
        indicators.append("xlm_hidden_macrosheet_present")

    if xlm_stats.get("xlm_very_hidden_macrosheet_count", 0) > 0:
        indicators.append("xlm_very_hidden_macrosheet_present")

    if xlm_stats.get("xlm_execution_indicator_count", 0) > 0:
        indicators.append("xlm_execution_indicator")

    if xlm_stats.get("xlm_network_indicator_count", 0) > 0:
        indicators.append("xlm_network_indicator")

    if xlm_stats.get("xlm_download_indicator_count", 0) > 0:
        indicators.append("xlm_download_indicator")

    if xlm_stats.get("xlm_obfuscation_indicator_count", 0) > 0:
        indicators.append("xlm_obfuscation_indicator")

    if xlm_stats.get("xlm_dynamic_reference_indicator_count", 0) > 0:
        indicators.append("xlm_dynamic_reference_indicator")

    if static_stats.get("static_execution_indicator_count", 0) > 0:
        indicators.append("static_execution_string")

    if static_stats.get("static_download_indicator_count", 0) > 0:
        indicators.append("static_download_string")

    if static_stats.get("static_persistence_indicator_count", 0) > 0:
        indicators.append("static_persistence_string")

    if static_stats.get("static_credential_indicator_count", 0) > 0:
        indicators.append("static_credential_string")

    if static_stats.get("static_obfuscation_indicator_count", 0) > 0:
        indicators.append("static_obfuscation_string")

    if static_stats.get("static_network_indicator_count", 0) > 0:
        indicators.append("static_network_indicator")

    if static_stats.get("static_dynamic_reference_indicator_count", 0) > 0:
        indicators.append("static_dynamic_reference")

    if static_stats.get("static_url_count", 0) > 0:
        indicators.append("url_present")

    if static_stats.get("static_ipv4_count", 0) > 0:
        indicators.append("ipv4_present")

    if static_stats.get("static_windows_path_count", 0) > 0:
        indicators.append("windows_path_present")

    # Higher-level combinations.
    if has_xlm and (
        xlm_stats.get("xlm_execution_indicator_count", 0) > 0
        or xlm_stats.get("xlm_download_indicator_count", 0) > 0
        or xlm_stats.get("xlm_network_indicator_count", 0) > 0
    ):
        indicators.append("xlm_capability_chain")

    if has_vba and has_external_relationships:
        indicators.append("vba_external_reference_combination")

    if has_activex and has_external_relationships:
        indicators.append("activex_external_reference_combination")

    if embedded_stats.get("embedded_pe_count", 0) > 0 and (
        has_vba or has_xlm or has_activex
    ):
        indicators.append("executable_embedding_combination")

    if (
        static_stats.get("static_execution_indicator_count", 0) > 0
        and static_stats.get("static_network_indicator_count", 0) > 0
    ):
        indicators.append("execution_network_combination")

    if (
        static_stats.get("static_download_indicator_count", 0) > 0
        and static_stats.get("static_obfuscation_indicator_count", 0) > 0
    ):
        indicators.append("download_obfuscation_combination")

    return tuple(sorted(set(indicators)))


# ---------------------------------------------------------------------------
# ML feature vector
# ---------------------------------------------------------------------------


def _build_feature_vector(
    *,
    extension: str,
    family: str,
    is_ooxml: bool,
    is_macro_enabled_extension: bool,
    is_legacy_ole: bool,
    has_vba: bool,
    has_xlm: bool,
    has_embedded: bool,
    has_activex: bool,
    has_external_relationships: bool,
    has_external_targets: bool,
    has_hyperlinks: bool,
    part_stats: Mapping[str, Any],
    rel_stats: Mapping[str, int],
    embedded_stats: Mapping[str, int],
    ole_stats: Mapping[str, int],
    xlm_stats: Mapping[str, int],
    static_stats: Mapping[str, int],
) -> Dict[str, float]:
    """
    Construct a deterministic numeric feature vector.

    Categorical document-family information is represented as one-hot
    features rather than strings.
    """

    vector: Dict[str, float] = {}

    # Container/document identity.
    vector["office_is_ooxml"] = float(is_ooxml)
    vector["office_is_macro_enabled_extension"] = float(is_macro_enabled_extension)
    vector["office_is_legacy_ole"] = float(is_legacy_ole)

    vector["office_family_word"] = float(family == "word")
    vector["office_family_excel"] = float(family == "excel")
    vector["office_family_powerpoint"] = float(family == "powerpoint")
    vector["office_family_ole"] = float(family == "ole")
    vector["office_family_unknown"] = float(family == "unknown")

    # Active content.
    vector["office_has_vba_project"] = float(has_vba)
    vector["office_has_xlm"] = float(has_xlm)
    vector["office_has_embedded_objects"] = float(has_embedded)
    vector["office_has_activex"] = float(has_activex)

    # External content.
    vector["office_has_external_relationships"] = float(has_external_relationships)
    vector["office_has_external_targets"] = float(has_external_targets)
    vector["office_has_hyperlinks"] = float(has_hyperlinks)

    # Package structure.
    vector["office_part_count"] = float(part_stats.get("part_count", 0))
    vector["office_xml_part_count"] = float(part_stats.get("xml_part_count", 0))
    vector["office_relationship_part_count"] = float(
        part_stats.get("relationship_part_count", 0)
    )
    vector["office_macro_related_part_count"] = float(
        part_stats.get("macro_related_part_count", 0)
    )
    vector["office_embedding_part_count"] = float(
        part_stats.get("embedding_part_count", 0)
    )
    vector["office_activex_part_count"] = float(part_stats.get("activex_part_count", 0))

    vector["office_total_uncompressed_size"] = float(
        part_stats.get("total_uncompressed_size", 0)
    )
    vector["office_total_compressed_size"] = float(
        part_stats.get("total_compressed_size", 0)
    )
    vector["office_compression_ratio"] = float(
        _safe_float(
            part_stats,
            "compression_ratio",
            default=_safe_ratio(
                int(part_stats.get("total_uncompressed_size", 0)),
                int(part_stats.get("total_compressed_size", 0)),
            ),
        )
    )

    # Relationships.
    vector["office_relationship_count"] = float(rel_stats.get("relationship_count", 0))
    vector["office_external_relationship_count"] = float(
        rel_stats.get("external_relationship_count", 0)
    )
    vector["office_hyperlink_relationship_count"] = float(
        rel_stats.get("hyperlink_relationship_count", 0)
    )
    vector["office_ole_relationship_count"] = float(
        rel_stats.get("ole_relationship_count", 0)
    )
    vector["office_control_relationship_count"] = float(
        rel_stats.get("control_relationship_count", 0)
    )
    vector["office_network_relationship_count"] = float(
        rel_stats.get("network_relationship_count", 0)
    )
    vector["office_path_relationship_count"] = float(
        rel_stats.get("path_relationship_count", 0)
    )

    # Embedded objects.
    for key, value in embedded_stats.items():
        vector[f"office_{key}"] = float(value)

    # OLE.
    for key, value in ole_stats.items():
        vector[f"office_{key}"] = float(value)

    # XLM.
    for key, value in xlm_stats.items():
        vector[f"office_{key}"] = float(value)

    # Broad static indicators.
    for key, value in static_stats.items():
        if key == "raw_size":
            vector["office_raw_size"] = float(value)
        else:
            vector[f"office_{key}"] = float(value)

    # Derived ratios.
    embedded_count = embedded_stats.get(
        "embedded_object_count",
        0,
    )

    vector["office_embedded_pe_ratio"] = _safe_ratio(
        embedded_stats.get("embedded_pe_count", 0),
        embedded_count,
    )

    vector["office_embedded_script_ratio"] = _safe_ratio(
        embedded_stats.get("embedded_script_count", 0),
        embedded_count,
    )

    vector["office_external_relationship_ratio"] = _safe_ratio(
        rel_stats.get("external_relationship_count", 0),
        rel_stats.get("relationship_count", 0),
    )

    vector["office_network_relationship_ratio"] = _safe_ratio(
        rel_stats.get("network_relationship_count", 0),
        rel_stats.get("relationship_count", 0),
    )

    vector["office_xlm_suspicious_formula_ratio"] = _safe_ratio(
        xlm_stats.get("xlm_suspicious_formula_count", 0),
        xlm_stats.get("xlm_formula_count", 0),
    )

    vector["office_xlm_hidden_ratio"] = _safe_ratio(
        (
            xlm_stats.get("xlm_hidden_macrosheet_count", 0)
            + xlm_stats.get("xlm_very_hidden_macrosheet_count", 0)
        ),
        xlm_stats.get("xlm_macrosheet_count", 0),
    )

    # Combination features.
    vector["office_vba_external_combination"] = float(
        has_vba and has_external_relationships
    )

    vector["office_activex_external_combination"] = float(
        has_activex and has_external_relationships
    )

    vector["office_embedded_pe_active_content_combination"] = float(
        embedded_stats.get("embedded_pe_count", 0) > 0
        and (has_vba or has_xlm or has_activex)
    )

    vector["office_xlm_execution_network_combination"] = float(
        has_xlm
        and xlm_stats.get("xlm_execution_indicator_count", 0) > 0
        and (
            xlm_stats.get("xlm_network_indicator_count", 0) > 0
            or xlm_stats.get("xlm_download_indicator_count", 0) > 0
        )
    )

    vector["office_execution_network_combination"] = float(
        static_stats.get("static_execution_indicator_count", 0) > 0
        and static_stats.get("static_network_indicator_count", 0) > 0
    )

    vector["office_download_obfuscation_combination"] = float(
        static_stats.get("static_download_indicator_count", 0) > 0
        and static_stats.get("static_obfuscation_indicator_count", 0) > 0
    )

    # Keep all values finite.
    for key, value in list(vector.items()):
        if not math.isfinite(value):
            vector[key] = 0.0

    return vector


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze_office(
    source: Union[str, Path, bytes, bytearray, memoryview, BinaryIO],
    *,
    max_size: Optional[int] = 250 * 1024 * 1024,
    analyze_relationship_layer: bool = True,
    analyze_embedded_layer: bool = True,
    analyze_ole_layer: bool = True,
    analyze_xlm_layer: bool = True,
) -> OfficeAnalysis:
    """
    Perform complete static Office feature extraction.

    Args:
        source:
            Path, bytes-like object, or binary file object.

        max_size:
            Maximum accepted input size.

        analyze_relationship_layer:
            Enable OOXML relationship analysis.

        analyze_embedded_layer:
            Enable embedded-object analysis.

        analyze_ole_layer:
            Enable OLE analysis.

        analyze_xlm_layer:
            Enable XLM analysis.

    Returns:
        OfficeAnalysis
    """

    data, file_name = _read_input(
        source,
        max_size=max_size,
    )

    extension = _extension(file_name)

    is_ooxml = _detect_ooxml(data)
    is_legacy_ole = _detect_legacy_ole(data)

    family = _document_family(
        extension,
        data,
    )

    macro_enabled_extension = extension in MACRO_ENABLED_EXTENSIONS

    # ---------------------------------------------------------------
    # Package structure.
    # ---------------------------------------------------------------

    parts, part_stats = _analyse_ooxml_parts(data)

    total_uncompressed = int(
        part_stats.get(
            "total_uncompressed_size",
            0,
        )
    )

    total_compressed = int(
        part_stats.get(
            "total_compressed_size",
            0,
        )
    )

    part_stats = dict(part_stats)
    part_stats["compression_ratio"] = _safe_ratio(
        total_uncompressed,
        total_compressed,
    )

    # ---------------------------------------------------------------
    # Specialized analyzers.
    # ---------------------------------------------------------------

    relationship_analysis: Optional[Any] = None
    embedded_analysis: Optional[Any] = None
    ole_analysis: Optional[Any] = None
    xlm_analysis: Optional[Any] = None

    if is_ooxml and analyze_relationship_layer:
        try:
            relationship_analysis = analyze_relationships(data)
        except Exception:
            # Aggregation should not turn a malformed document into
            # an application-level crash.
            relationship_analysis = None

    if is_ooxml and analyze_embedded_layer:
        try:
            embedded_analysis = analyze_embedded_objects(data)
        except Exception:
            embedded_analysis = None

    if is_legacy_ole and analyze_ole_layer:
        try:
            ole_analysis = analyze_ole(data)
        except Exception:
            ole_analysis = None

    if is_ooxml and analyze_xlm_layer and family == "excel":
        try:
            xlm_analysis = analyze_xlm(data)
        except Exception:
            xlm_analysis = None

    # ---------------------------------------------------------------
    # Relationship statistics.
    # ---------------------------------------------------------------

    rel_stats = _relationship_statistics(relationship_analysis)

    # ---------------------------------------------------------------
    # Embedded-object statistics.
    # ---------------------------------------------------------------

    embedded_stats = _embedded_statistics(embedded_analysis)

    # ---------------------------------------------------------------
    # OLE statistics.
    # ---------------------------------------------------------------

    ole_stats = _ole_statistics(ole_analysis)

    # ---------------------------------------------------------------
    # XLM statistics.
    # ---------------------------------------------------------------

    xlm_stats = _xlm_statistics(xlm_analysis)

    # ---------------------------------------------------------------
    # Bounded XML corpus.
    # ---------------------------------------------------------------

    corpus = _read_relevant_ooxml_content(data) if is_ooxml else b""

    static_stats = _static_content_statistics(
        data,
        corpus,
    )

    # ---------------------------------------------------------------
    # Determine high-level active-content flags.
    # ---------------------------------------------------------------

    has_vba = bool(
        part_stats.get("macro_related_part_count", 0) > 0
        or ole_stats.get("ole_vba_stream_count", 0) > 0
        or b"vbaproject.bin" in data.lower()
    )

    has_xlm = bool(
        xlm_stats.get("xlm_macrosheet_count", 0) > 0
        or xlm_stats.get("xlm_formula_count", 0) > 0
        or xlm_stats.get("xlm_suspicious_formula_count", 0) > 0
    )

    has_embedded = bool(
        part_stats.get("embedding_part_count", 0) > 0
        or embedded_stats.get("embedded_object_count", 0) > 0
    )

    has_activex = bool(
        part_stats.get("activex_part_count", 0) > 0
        or embedded_stats.get("embedded_activex_count", 0) > 0
        or rel_stats.get("control_relationship_count", 0) > 0
    )

    has_external_relationships = bool(
        rel_stats.get("external_relationship_count", 0) > 0
    )

    has_external_targets = bool(
        rel_stats.get("network_relationship_count", 0) > 0
        or static_stats.get("static_external_target_count", 0) > 0
        or static_stats.get("static_url_count", 0) > 0
    )

    has_hyperlinks = bool(rel_stats.get("hyperlink_relationship_count", 0) > 0)

    # ---------------------------------------------------------------
    # Semantic indicators.
    # ---------------------------------------------------------------

    indicators = _generate_indicators(
        extension=extension,
        family=family,
        macro_enabled_extension=macro_enabled_extension,
        has_vba=has_vba,
        has_xlm=has_xlm,
        has_embedded=has_embedded,
        has_activex=has_activex,
        has_external_relationships=has_external_relationships,
        has_external_targets=has_external_targets,
        has_hyperlinks=has_hyperlinks,
        rel_stats=rel_stats,
        embedded_stats=embedded_stats,
        ole_stats=ole_stats,
        xlm_stats=xlm_stats,
        static_stats=static_stats,
    )

    # ---------------------------------------------------------------
    # ML vector.
    # ---------------------------------------------------------------

    feature_vector = _build_feature_vector(
        extension=extension,
        family=family,
        is_ooxml=is_ooxml,
        is_macro_enabled_extension=macro_enabled_extension,
        is_legacy_ole=is_legacy_ole,
        has_vba=has_vba,
        has_xlm=has_xlm,
        has_embedded=has_embedded,
        has_activex=has_activex,
        has_external_relationships=has_external_relationships,
        has_external_targets=has_external_targets,
        has_hyperlinks=has_hyperlinks,
        part_stats=part_stats,
        rel_stats=rel_stats,
        embedded_stats=embedded_stats,
        ole_stats=ole_stats,
        xlm_stats=xlm_stats,
        static_stats=static_stats,
    )

    # ---------------------------------------------------------------
    # Human/JSON-friendly feature representation.
    # ---------------------------------------------------------------

    features: Dict[str, Any] = {
        **feature_vector,
        "office_extension": extension,
        "office_document_family": family,
        "office_indicators": list(indicators),
    }

    return OfficeAnalysis(
        file_name=file_name,
        extension=extension,
        document_family=family,
        is_ooxml=is_ooxml,
        is_macro_enabled_extension=macro_enabled_extension,
        is_zip_based=data.startswith(b"PK"),
        is_legacy_ole=is_legacy_ole,
        has_vba_project=has_vba,
        has_xlm=has_xlm,
        has_embedded_objects=has_embedded,
        has_activex=has_activex,
        has_external_relationships=has_external_relationships,
        has_external_targets=has_external_targets,
        has_hyperlinks=has_hyperlinks,
        part_count=int(part_stats.get("part_count", 0)),
        xml_part_count=int(part_stats.get("xml_part_count", 0)),
        relationship_part_count=int(
            part_stats.get(
                "relationship_part_count",
                0,
            )
        ),
        macro_related_part_count=int(
            part_stats.get(
                "macro_related_part_count",
                0,
            )
        ),
        embedding_part_count=int(
            part_stats.get(
                "embedding_part_count",
                0,
            )
        ),
        activex_part_count=int(
            part_stats.get(
                "activex_part_count",
                0,
            )
        ),
        total_uncompressed_size=total_uncompressed,
        total_compressed_size=total_compressed,
        compression_ratio=_safe_ratio(
            total_uncompressed,
            total_compressed,
        ),
        relationship_analysis=relationship_analysis,
        embedded_analysis=embedded_analysis,
        ole_analysis=ole_analysis,
        xlm_analysis=xlm_analysis,
        parts=parts,
        indicators=indicators,
        feature_vector=feature_vector,
        features=features,
    )


def analyze_office_file(
    path: Union[str, Path],
    **kwargs: Any,
) -> OfficeAnalysis:
    """
    Convenience wrapper around analyze_office().
    """

    return analyze_office(
        path,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Feature extraction API
# ---------------------------------------------------------------------------


def extract_office_features(
    source: Union[str, Path, bytes, bytearray, memoryview, BinaryIO],
    *,
    include_metadata: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Extract Office features.

    By default only the feature dictionary is returned.

    If include_metadata=True, document identity and indicators are also
    included.
    """

    analysis = analyze_office(
        source,
        **kwargs,
    )

    result = dict(analysis.feature_vector)

    if include_metadata:
        result.update(
            {
                "office_extension": analysis.extension,
                "office_document_family": analysis.document_family,
                "office_indicators": list(analysis.indicators),
                "office_file_name": analysis.file_name,
            }
        )

    return result


def extract_office_feature_vector(
    source: Union[str, Path, bytes, bytearray, memoryview, BinaryIO],
    **kwargs: Any,
) -> Dict[str, float]:
    """
    Return only numeric ML features.
    """

    analysis = analyze_office(
        source,
        **kwargs,
    )

    return dict(analysis.feature_vector)


# ---------------------------------------------------------------------------
# Stable feature schema
# ---------------------------------------------------------------------------


def office_feature_names() -> Tuple[str, ...]:
    """
    Return the canonical feature names generated by the Office extractor.

    The list is generated from a minimal empty document-like input so that
    callers do not have to maintain a second manually synchronized schema.
    """

    # Build a deterministic vector from neutral values rather than trying
    # to manufacture a valid Office document.
    vector = _build_feature_vector(
        extension="",
        family="unknown",
        is_ooxml=False,
        is_macro_enabled_extension=False,
        is_legacy_ole=False,
        has_vba=False,
        has_xlm=False,
        has_embedded=False,
        has_activex=False,
        has_external_relationships=False,
        has_external_targets=False,
        has_hyperlinks=False,
        part_stats={
            "part_count": 0,
            "xml_part_count": 0,
            "relationship_part_count": 0,
            "macro_related_part_count": 0,
            "embedding_part_count": 0,
            "activex_part_count": 0,
            "total_uncompressed_size": 0,
            "total_compressed_size": 0,
            "compression_ratio": 0.0,
        },
        rel_stats={
            "relationship_count": 0,
            "external_relationship_count": 0,
            "hyperlink_relationship_count": 0,
            "ole_relationship_count": 0,
            "control_relationship_count": 0,
            "network_relationship_count": 0,
            "path_relationship_count": 0,
        },
        embedded_stats={
            "embedded_object_count": 0,
            "embedded_ole_count": 0,
            "embedded_pe_count": 0,
            "embedded_pdf_count": 0,
            "embedded_script_count": 0,
            "embedded_archive_count": 0,
            "embedded_extension_mismatch_count": 0,
            "embedded_activex_count": 0,
        },
        ole_stats={
            "ole_stream_count": 0,
            "ole_storage_count": 0,
            "ole_vba_stream_count": 0,
            "ole_macro_indicator_count": 0,
            "ole_suspicious_stream_count": 0,
            "ole_external_link_count": 0,
        },
        xlm_stats={
            "xlm_formula_count": 0,
            "xlm_suspicious_formula_count": 0,
            "xlm_macrosheet_count": 0,
            "xlm_hidden_macrosheet_count": 0,
            "xlm_very_hidden_macrosheet_count": 0,
            "xlm_defined_name_count": 0,
            "xlm_suspicious_defined_name_count": 0,
            "xlm_execution_indicator_count": 0,
            "xlm_network_indicator_count": 0,
            "xlm_download_indicator_count": 0,
            "xlm_obfuscation_indicator_count": 0,
            "xlm_dynamic_reference_indicator_count": 0,
        },
        static_stats={
            "static_url_count": 0,
            "static_ipv4_count": 0,
            "static_windows_path_count": 0,
            "static_execution_indicator_count": 0,
            "static_download_indicator_count": 0,
            "static_persistence_indicator_count": 0,
            "static_credential_indicator_count": 0,
            "static_obfuscation_indicator_count": 0,
            "static_network_indicator_count": 0,
            "static_dynamic_reference_indicator_count": 0,
            "static_external_target_count": 0,
            "static_unique_keyword_count": 0,
            "static_corpus_size": 0,
            "raw_size": 0,
        },
    )

    return tuple(sorted(vector.keys()))


def build_feature_schema() -> Dict[str, Any]:
    """
    Build a machine-readable feature schema.

    This can be serialized to models/metadata/feature_schema.json.
    """

    names = office_feature_names()

    return {
        "schema_version": "1.0.0",
        "extractor": "office_features",
        "feature_count": len(names),
        "features": [
            {
                "name": name,
                "type": "float",
            }
            for name in names
        ],
    }


# ---------------------------------------------------------------------------
# Feature vector ordering
# ---------------------------------------------------------------------------


def vectorize_features(
    features: Mapping[str, Any],
    feature_names: Optional[Sequence[str]] = None,
) -> List[float]:
    """
    Convert a feature mapping to a deterministic ordered vector.

    Missing values become 0.0.

    This is useful for sklearn pipelines that require a fixed column order.
    """

    names = (
        tuple(feature_names) if feature_names is not None else office_feature_names()
    )

    vector: List[float] = []

    for name in names:
        value = features.get(name, 0.0)

        try:
            numeric = float(value)

            if not math.isfinite(numeric):
                numeric = 0.0

        except (TypeError, ValueError):
            numeric = 0.0

        vector.append(numeric)

    return vector


def extract_ordered_office_feature_vector(
    source: Union[str, Path, bytes, bytearray, memoryview, BinaryIO],
    feature_names: Optional[Sequence[str]] = None,
    **kwargs: Any,
) -> List[float]:
    """
    Extract and order Office features for ML inference.
    """

    features = extract_office_feature_vector(
        source,
        **kwargs,
    )

    return vectorize_features(
        features,
        feature_names=feature_names,
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def analysis_to_dict(
    analysis: OfficeAnalysis,
    *,
    include_parts: bool = True,
    include_lower_level_analysis: bool = False,
) -> Dict[str, Any]:
    """
    Convert OfficeAnalysis to a JSON-serializable dictionary.

    Lower-level analyzer objects are excluded by default because they can
    contain large evidence structures.
    """

    result: Dict[str, Any] = {
        "file_name": analysis.file_name,
        "extension": analysis.extension,
        "document_family": analysis.document_family,
        "is_ooxml": analysis.is_ooxml,
        "is_macro_enabled_extension": (analysis.is_macro_enabled_extension),
        "is_zip_based": analysis.is_zip_based,
        "is_legacy_ole": analysis.is_legacy_ole,
        "has_vba_project": analysis.has_vba_project,
        "has_xlm": analysis.has_xlm,
        "has_embedded_objects": analysis.has_embedded_objects,
        "has_activex": analysis.has_activex,
        "has_external_relationships": (analysis.has_external_relationships),
        "has_external_targets": (analysis.has_external_targets),
        "has_hyperlinks": analysis.has_hyperlinks,
        "part_count": analysis.part_count,
        "xml_part_count": analysis.xml_part_count,
        "relationship_part_count": (analysis.relationship_part_count),
        "macro_related_part_count": (analysis.macro_related_part_count),
        "embedding_part_count": (analysis.embedding_part_count),
        "activex_part_count": (analysis.activex_part_count),
        "total_uncompressed_size": (analysis.total_uncompressed_size),
        "total_compressed_size": (analysis.total_compressed_size),
        "compression_ratio": analysis.compression_ratio,
        "indicators": list(analysis.indicators),
        "feature_vector": dict(analysis.feature_vector),
        "features": dict(analysis.features),
    }

    if include_parts:
        result["parts"] = [asdict(part) for part in analysis.parts]

    if include_lower_level_analysis:
        result["relationship_analysis"] = _serialize_object(
            analysis.relationship_analysis
        )

        result["embedded_analysis"] = _serialize_object(analysis.embedded_analysis)

        result["ole_analysis"] = _serialize_object(analysis.ole_analysis)

        result["xlm_analysis"] = _serialize_object(analysis.xlm_analysis)

    return result


def _serialize_object(value: Any) -> Any:
    if value is None:
        return None

    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)

    if isinstance(value, Mapping):
        return {str(key): _serialize_object(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return [_serialize_object(item) for item in value]

    if isinstance(value, (str, int, float, bool)):
        return value

    return str(value)


# ---------------------------------------------------------------------------
# Utility queries
# ---------------------------------------------------------------------------


def find_office_indicators(
    analysis: OfficeAnalysis,
    *,
    prefix: Optional[str] = None,
) -> Tuple[str, ...]:
    """
    Return semantic indicators, optionally filtered by prefix.
    """

    indicators = analysis.indicators

    if prefix is None:
        return indicators

    prefix = prefix.lower()

    return tuple(item for item in indicators if item.lower().startswith(prefix))


def is_active_office_document(
    analysis: OfficeAnalysis,
) -> bool:
    """
    Determine whether the document contains any static active-content
    mechanism.

    This is NOT a maliciousness verdict.
    """

    return bool(
        analysis.has_vba_project
        or analysis.has_xlm
        or analysis.has_embedded_objects
        or analysis.has_activex
    )


def has_external_content(
    analysis: OfficeAnalysis,
) -> bool:
    """
    Return whether static analysis found externally referenced content.
    """

    return bool(analysis.has_external_relationships or analysis.has_external_targets)


def suspicious_indicator_count(
    analysis: OfficeAnalysis,
) -> int:
    """
    Count semantic indicators.

    This is intentionally only an evidence count, not a malware score.
    """

    return len(analysis.indicators)


# ---------------------------------------------------------------------------
# File hashing helper
# ---------------------------------------------------------------------------


def sha256_digest(
    source: Union[str, Path, bytes, bytearray, memoryview, BinaryIO],
    *,
    chunk_size: int = 1024 * 1024,
) -> str:
    """
    Calculate SHA-256 for an Office input.

    No parsing or execution occurs.
    """

    digest = hashlib.sha256()

    if isinstance(source, (str, Path)):
        with Path(source).open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)

                if not chunk:
                    break

                digest.update(chunk)

        return digest.hexdigest()

    data, _ = _read_input(source)

    digest.update(data)

    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------


def iter_office_features(
    paths: Iterable[Union[str, Path]],
    *,
    continue_on_error: bool = True,
    **kwargs: Any,
) -> Iterator[Tuple[Path, Optional[OfficeAnalysis], Optional[Exception]]]:
    """
    Analyze multiple Office files.

    Yields:
        (path, analysis, error)

    If continue_on_error=True, one malformed file does not stop the batch.
    """

    for item in paths:
        path = Path(item)

        try:
            analysis = analyze_office(
                path,
                **kwargs,
            )

            yield path, analysis, None

        except Exception as exc:
            if not continue_on_error:
                raise

            yield path, None, exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "OfficePartRecord",
    "OfficeAnalysis",
    "analyze_office",
    "analyze_office_file",
    "extract_office_features",
    "extract_office_feature_vector",
    "extract_ordered_office_feature_vector",
    "office_feature_names",
    "build_feature_schema",
    "vectorize_features",
    "analysis_to_dict",
    "find_office_indicators",
    "is_active_office_document",
    "has_external_content",
    "suspicious_indicator_count",
    "sha256_digest",
    "iter_office_features",
]
