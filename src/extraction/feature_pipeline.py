"""
Pharos CDR - Unified Feature Extraction Pipeline.

Central orchestration layer for static feature extraction.

Design goals
------------
* One public pipeline for dataset extraction and later scanning.
* Deterministic, numeric feature vectors suitable for ML.
* Safe handling of untrusted documents and scripts.
* No macro/script/OLE/XLM execution.
* No network access.
* No external relationship fetching.
* Graceful degradation when an optional extractor cannot process a file.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import io
import math
import mimetypes
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping, Optional
import logging

logger = logging.getLogger(__name__)
from xml.etree import ElementTree as ET

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_HASH_CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_READ_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_ZIP_ENTRIES = 10_000
DEFAULT_MAX_XML_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_TEXT_BYTES = 16 * 1024 * 1024

SUPPORTED_OOXML_EXTENSIONS = {
    ".docx", ".docm", ".dotx", ".dotm",
    ".xlsx", ".xlsm", ".xltx", ".xltm",
    ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
}

MACRO_ENABLED_EXTENSIONS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".ppsm",
}

OOXML_MACRO_CONTENT_TYPES = {
    "application/vnd.ms-word.document.macroEnabled.main+xml",
    "application/vnd.ms-word.template.macroEnabledTemplate.main+xml",
    "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
    "application/vnd.ms-excel.template.macroEnabled.main+xml",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml",
    "application/vnd.ms-powerpoint.template.macroEnabled.main+xml",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml",
}

VBA_MARKERS = (b"vbaProject.bin", b"vbaData.xml", b"VBA")
OLE_MARKERS = (b"Compound File", b"Microsoft Office")

SUSPICIOUS_FILE_PART_NAMES = (
    "vbaproject.bin", "vbaData.xml", "oleObject", "embeddings/",
    "activex/", "customxml/", "externalLink", "attachedTemplate",
)

SUSPICIOUS_TEXT_PATTERNS: dict[str, re.Pattern[str]] = {
    "powershell": re.compile(r"\bpowershell(?:\.exe)?\b", re.I),
    "cmd": re.compile(r"\bcmd(?:\.exe)?\b", re.I),
    "wscript": re.compile(r"\bwscript(?:\.exe)?\b", re.I),
    "cscript": re.compile(r"\bcscript(?:\.exe)?\b", re.I),
    "mshta": re.compile(r"\bmshta(?:\.exe)?\b", re.I),
    "rundll32": re.compile(r"\brundll32(?:\.exe)?\b", re.I),
    "regsvr32": re.compile(r"\bregsvr32(?:\.exe)?\b", re.I),
    "certutil": re.compile(r"\bcertutil(?:\.exe)?\b", re.I),
    "bitsadmin": re.compile(r"\bbitsadmin(?:\.exe)?\b", re.I),
    "wmi": re.compile(r"\b(?:wmic|win32_process|winmgmts)\b", re.I),
    "download": re.compile(r"\b(?:download|urlmon|urldownloadtofile|bitsadmin)\b", re.I),
    "encoded_command": re.compile(r"(?:-enc(?:odedcommand)?\b|encodedcommand\b)", re.I),
    "base64": re.compile(r"\b(?:frombase64string|base64|atob)\b", re.I),
    "auto_open": re.compile(r"\b(?:auto_open|autoopen|document_open|workbook_open)\b", re.I),
    "shell_execute": re.compile(r"\b(?:shell|shell_execute|createprocess|winexec)\b", re.I),
}

URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[^\s<>'\"`]+", re.I)
IP_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class FeatureAnalysis:
    """Result returned by FeaturePipeline."""
    source: Any
    source_size: int
    source_hash: str
    analyses: dict[str, dict[str, Any]]
    feature_vector: dict[str, float]
    feature_names: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def analysis_count(self) -> int:
        return len(self.analyses)

    @property
    def feature_count(self) -> int:
        return len(self.feature_vector)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": str(self.source),
            "source_size": self.source_size,
            "source_hash": self.source_hash,
            "analyses": self.analyses,
            "feature_vector": self.feature_vector,
            "feature_names": self.feature_names,
            "metadata": self.metadata,
            "analysis_count": self.analysis_count,
            "feature_count": self.feature_count,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_path(value: Any) -> Optional[Path]:
    if isinstance(value, Path):
        return value
    if isinstance(value, str):
        try:
            return Path(value)
        except (TypeError, ValueError, OSError):
            return None
    return None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except (TypeError, ValueError, OverflowError):
        return default


def _sanitize_feature_name(value: Any) -> str:
    text = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value).strip().lower()).replace("-", "_")
    text = re.sub(r"_+", "_", text)
    return text.strip("_") or "feature"


def _flatten_numeric_mapping(value: Any, prefix: str = "") -> dict[str, float]:
    """Flatten nested mappings/sequences into numeric features."""
    output: dict[str, float] = {}

    if isinstance(value, Mapping):
        for key, child in value.items():
            child_prefix = f"{prefix}.{_sanitize_feature_name(key)}" if prefix else _sanitize_feature_name(key)
            output.update(_flatten_numeric_mapping(child, prefix=child_prefix))
        return output

    if isinstance(value, bool):
        if prefix:
            output[prefix] = 1.0 if value else 0.0
        return output

    if isinstance(value, (int, float)):
        if prefix:
            number = _safe_float(value)
            if math.isfinite(number):
                output[prefix] = number
        return output

    if isinstance(value, (list, tuple, set, frozenset)):
        if prefix:
            output[f"{prefix}.count"] = float(len(value))
        for index, child in enumerate(value):
            child_prefix = f"{prefix}.{index}" if prefix else str(index)
            output.update(_flatten_numeric_mapping(child, prefix=child_prefix))
        return output

    return output


def _merge_feature_values(dest: MutableMapping[str, float], source: Mapping[str, Any], prefix: str = "") -> None:
    for name, value in _flatten_numeric_mapping(source, prefix=prefix).items():
        dest[name] = _safe_float(value)


def _read_limited(path: Path, max_bytes: int) -> bytes:
    with path.open("rb") as f:
        return f.read(max_bytes)


def _sha256_file(path: Path, chunk_size: int = DEFAULT_HASH_CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _source_hash(source: Any, *, chunk_size: int = DEFAULT_HASH_CHUNK_SIZE) -> str:
    path = _coerce_path(source)
    if path is not None and path.is_file():
        return _sha256_file(path, chunk_size=chunk_size)
    if isinstance(source, (bytes, bytearray)):
        return hashlib.sha256(bytes(source)).hexdigest()
    if isinstance(source, memoryview):
        return hashlib.sha256(source.tobytes()).hexdigest()
    if isinstance(source, str):
        return hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()
    return hashlib.sha256(repr(source).encode("utf-8", errors="replace")).hexdigest()


def _source_size(source: Any) -> int:
    path = _coerce_path(source)
    if path is not None and path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    if isinstance(source, (bytes, bytearray)):
        return len(source)
    if isinstance(source, memoryview):
        return source.nbytes
    if isinstance(source, str):
        return len(source.encode("utf-8", errors="replace"))
    return 0


def _read_source_bytes(source: Any, *, max_bytes: int = DEFAULT_MAX_READ_BYTES) -> bytes:
    path = _coerce_path(source)
    if path is not None and path.is_file():
        return _read_limited(path, max_bytes)
    if isinstance(source, bytes):
        return source[:max_bytes]
    if isinstance(source, bytearray):
        return bytes(source[:max_bytes])
    if isinstance(source, memoryview):
        return source.tobytes()[:max_bytes]
    if isinstance(source, str):
        return source.encode("utf-8", errors="replace")[:max_bytes]
    return b""


def _decode_text(data: bytes, *, max_bytes: int = DEFAULT_MAX_TEXT_BYTES) -> str:
    data = data[:max_bytes]
    if not data:
        return ""
    for enc in ("utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            return data.decode(enc, errors="replace")
        except (LookupError, UnicodeError):
            continue
    return ""


def _xml_root(data: bytes) -> Optional[ET.Element]:
    if not data:
        return None
    try:
        return ET.fromstring(data[:DEFAULT_MAX_XML_BYTES])
    except (ET.ParseError, ValueError, TypeError):
        return None


def _local_name(tag: Any) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts if c > 0
    )


# ---------------------------------------------------------------------------
# Built-in analysis functions
# ---------------------------------------------------------------------------


def _inspect_file(path: Path, data: bytes) -> dict[str, Any]:
    ext = path.suffix.lower()
    return {
        "size": _safe_int(path.stat().st_size if path.exists() else len(data)),
        "extension_known": float(ext in SUPPORTED_OOXML_EXTENSIONS or ext in MACRO_ENABLED_EXTENSIONS),
        "extension_macro_enabled": float(ext in MACRO_ENABLED_EXTENSIONS),
        "extension_length": float(len(ext)),
        "filename_length": float(len(path.name)),
        "filename_has_multiple_extensions": float(len(path.name.split(".")) > 2),
        "mime_type_known": float(bool(mimetypes.guess_type(path.name)[0])),
        "is_ooxml_extension": float(ext in SUPPORTED_OOXML_EXTENSIONS),
        "is_macro_enabled_extension": float(ext in MACRO_ENABLED_EXTENSIONS),
    }


def _inspect_entropy(data: bytes) -> dict[str, Any]:
    if not data:
        return {"entropy": 0.0, "high_entropy": 0.0, "very_high_entropy": 0.0}
    v = _entropy(data)
    return {"entropy": v, "high_entropy": float(v >= 7.0), "very_high_entropy": float(v >= 7.5)}


def _inspect_strings(data: bytes) -> dict[str, Any]:
    text = _decode_text(data)
    ascii_strings = re.findall(rb"[\x20-\x7e]{4,}", data)
    unicode_strings = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data)
    return {
        "text_length": float(len(text)),
        "ascii_string_count": float(len(ascii_strings)),
        "unicode_string_count": float(len(unicode_strings)),
        "url_count": float(len(URL_PATTERN.findall(text))),
        "ip_count": float(len(IP_PATTERN.findall(text))),
        "printable_ratio": float(sum(32 <= b < 127 for b in data) / len(data)) if data else 0.0,
    }


def _inspect_raw_source_text(data: bytes) -> dict[str, Any]:
    text = _decode_text(data)
    result: dict[str, Any] = {
        "text_length": float(len(text)),
        "url_count": float(len(URL_PATTERN.findall(text))),
        "ip_count": float(len(IP_PATTERN.findall(text))),
    }
    suspicious_total = 0
    for name, pattern in SUSPICIOUS_TEXT_PATTERNS.items():
        count = len(pattern.findall(text))
        result[f"suspicious_{name}"] = float(count)
        suspicious_total += count
    result["suspicious_string_count"] = float(suspicious_total)
    return result


def _inspect_metadata(path: Path, data: bytes) -> dict[str, Any]:
    ext = path.suffix.lower()
    return {
        "extension_length": float(len(ext)),
        "filename_length": float(len(path.name)),
        "filename_has_space": float(" " in path.name),
        "filename_has_multiple_extensions": float(len(path.name.split(".")) > 2),
        "source_size": float(len(data)),
        "mime_type_known": float(bool(mimetypes.guess_type(path.name)[0])),
    }


# ---------------------------------------------------------------------------
# OOXML analysis
# ---------------------------------------------------------------------------


def _inspect_relationships(entries: Mapping[str, bytes]) -> dict[str, Any]:
    total = external = hyperlinks = ole_objects = attached_templates = 0
    for name, data in entries.items():
        if not name.lower().endswith(".rels"):
            continue
        root = _xml_root(data)
        if root is None:
            continue
        for el in root.iter():
            if _local_name(el.tag) != "Relationship":
                continue
            total += 1
            target = el.attrib.get("Target", "")
            target_mode = el.attrib.get("TargetMode", "").lower()
            rel_type = el.attrib.get("Type", "").lower()
            if target_mode == "external" or any(m in rel_type for m in ("hyperlink", "oleobject", "externallink", "attachedtemplate")):
                external += 1
            if "hyperlink" in rel_type:
                hyperlinks += 1
            if "oleobject" in rel_type:
                ole_objects += 1
            if "attachedtemplate" in rel_type:
                attached_templates += 1
    return {
        "relationships_total": float(total),
        "relationships_external": float(external),
        "relationships_hyperlinks": float(hyperlinks),
        "relationships_ole_objects": float(ole_objects),
        "relationships_attached_templates": float(attached_templates),
    }


def _inspect_content_types(entries: Mapping[str, bytes]) -> dict[str, Any]:
    data = entries.get("[Content_Types].xml")
    if data is None:
        return {"content_types_present": 0.0, "content_types_macro_enabled": 0.0, "content_types_override_count": 0.0}
    root = _xml_root(data)
    macro_enabled = override_count = 0
    for el in (root.iter() if root is not None else ()):
        if _local_name(el.tag) == "Override":
            override_count += 1
        if el.attrib.get("ContentType", "") in OOXML_MACRO_CONTENT_TYPES:
            macro_enabled += 1
    return {
        "content_types_present": 1.0,
        "content_types_macro_enabled": float(macro_enabled > 0),
        "content_types_macro_override_count": float(macro_enabled),
        "content_types_override_count": float(override_count),
    }


def _inspect_document_xml(entries: Mapping[str, bytes]) -> dict[str, Any]:
    doc_name = next((n for n in ("word/document.xml", "xl/workbook.xml", "ppt/presentation.xml") if n in entries), None)
    if doc_name is None:
        return {"document_xml_present": 0.0, "document_paragraphs": 0.0, "document_text_characters": 0.0}
    root = _xml_root(entries[doc_name])
    paragraphs = text_chars = 0
    for el in (root.iter() if root is not None else ()):
        local = _local_name(el.tag)
        if local in {"p", "row", "sheet", "slide"}:
            paragraphs += 1
        if local in {"t", "text", "v"} and el.text:
            text_chars += len(el.text)
    return {"document_xml_present": 1.0, "document_paragraphs": float(paragraphs), "document_text_characters": float(text_chars)}


def _inspect_zip_structure(data: bytes, *, max_entries: int = DEFAULT_MAX_ZIP_ENTRIES) -> dict[str, Any]:
    result: dict[str, Any] = {
        "zip_present": 0.0, "zip_entries": 0.0, "zip_uncompressed_size": 0.0,
        "zip_compressed_size": 0.0, "zip_compression_ratio": 0.0,
        "zip_xml_parts": 0.0, "zip_binary_parts": 0.0,
        "zip_macro_parts": 0.0, "zip_suspicious_parts": 0.0, "zip_error": 0.0,
    }
    if not data.startswith(b"PK"):
        return result

    entries: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            result["zip_present"] = 1.0
            infos = archive.infolist()[:max_entries]
            total_uc = total_c = xml_count = bin_count = macro_count = susp_count = 0

            for info in infos:
                lowered = info.filename.lower()
                total_uc += _safe_int(info.file_size)
                total_c += _safe_int(info.compress_size)

                if lowered.endswith(".xml") or lowered.endswith(".rels"):
                    xml_count += 1
                else:
                    bin_count += 1

                if lowered.endswith("vbaproject.bin") or "vba" in lowered or lowered.endswith(".bin"):
                    macro_count += 1

                if any(m in lowered for m in SUSPICIOUS_FILE_PART_NAMES):
                    susp_count += 1

                if lowered.endswith((".xml", ".rels")) or "content_types" in lowered:
                    try:
                        entries[info.filename] = archive.read(info)[:DEFAULT_MAX_XML_BYTES]
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        continue

            result.update({
                "zip_entries": float(len(infos)), "zip_uncompressed_size": float(total_uc),
                "zip_compressed_size": float(total_c), "zip_xml_parts": float(xml_count),
                "zip_binary_parts": float(bin_count), "zip_macro_parts": float(macro_count),
                "zip_suspicious_parts": float(susp_count),
            })
            if total_c:
                result["zip_compression_ratio"] = total_uc / total_c

            result.update({f"ooxml_{k}": v for k, v in _inspect_content_types(entries).items()})
            result.update({f"ooxml_{k}": v for k, v in _inspect_relationships(entries).items()})
            result.update({f"ooxml_{k}": v for k, v in _inspect_document_xml(entries).items()})

    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
        result["zip_error"] = 1.0

    return result


# ---------------------------------------------------------------------------
# Provider discovery
# ---------------------------------------------------------------------------

EXTRACTOR_MODULES: tuple[str, ...] = (
    "src.extraction.common.file_features",
    "src.extraction.common.entropy",
    "src.extraction.common.strings",
    "src.extraction.common.metadata",
    "src.extraction.office.relationships",
    "src.extraction.office.embedded_objects",
    "src.extraction.office.templates",
    "src.extraction.office.ole",
    "src.extraction.office.xlm",
    "src.extraction.office.office_features",
    "src.extraction.vba.parser",
    "src.extraction.vba.capabilities",
    "src.extraction.vba.execution",
    "src.extraction.vba.api_features",
    "src.extraction.vba.obfuscation",
    "src.extraction.script.parser",
    "src.extraction.script.javascript",
    "src.extraction.script.vbscript",
    "src.extraction.script.powershell",
    "src.extraction.behavior.process",
    "src.extraction.behavior.filesystem",
    "src.extraction.behavior.registry",
    "src.extraction.behavior.network",
    "src.extraction.behavior.persistence",
    "src.extraction.behavior.environment",
    "src.extraction.behavior.credentials",
    "src.extraction.behavior.collection",
    "src.extraction.behavior.evasion",
    "src.extraction.urls.url_features",
    "src.extraction.capabilities.dynamic_execution",
    "src.extraction.capabilities.payload",
    "src.extraction.capabilities.communication",
    "src.extraction.capabilities.derived",
)

PROVIDER_FUNCTION_NAMES = (
    "extract_features", "analyze_features", "analyze", "extract",
    "collect_features", "get_features",
)

PROVIDER_CLASS_NAMES = ("FeatureExtractor", "Extractor", "Analyzer", "FeatureAnalyzer")


def _result_to_mapping(value: Any) -> Optional[Mapping[str, Any]]:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return value
    if isinstance(value, FeatureAnalysis):
        return value.feature_vector
    for attr in ("feature_vector", "features"):
        candidate = getattr(value, attr, None)
        if isinstance(candidate, Mapping):
            return candidate
    if hasattr(value, "to_dict"):
        try:
            candidate = value.to_dict()
        except Exception:
            return None
        if isinstance(candidate, Mapping):
            for key in ("features", "feature_vector"):
                if isinstance(candidate.get(key), Mapping):
                    return candidate[key]
            return candidate
    return None


def _build_provider_arguments(
    callable_object: Callable[..., Any], *,
    source: Any, path: Optional[Path], data: bytes,
    analyses: Mapping[str, Any], metadata: Mapping[str, Any],
) -> Optional[dict[str, Any]]:
    """Build arguments matching the provider's declared parameter names."""
    try:
        sig = inspect.signature(callable_object)
    except (TypeError, ValueError):
        return None

    aliases: dict[str, Any] = {
        "source": source, "file": source, "path": path, "file_path": path,
        "filepath": path, "data": data, "raw": data, "raw_bytes": data,
        "content": data, "bytes_data": data, "analyses": analyses,
        "analysis": analyses, "metadata": metadata, "context": metadata,
    }

    arguments: dict[str, Any] = {}
    for pname, param in sig.parameters.items():
        if pname in {"self", "cls"}:
            continue
        if param.kind in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}:
            continue
        if pname in aliases:
            val = aliases[pname]
            if val is None and param.default is not inspect.Parameter.empty:
                continue
            arguments[pname] = val
        elif param.default is not inspect.Parameter.empty:
            arguments[pname] = param.default
        else:
            arguments[pname] = None

    return arguments


def _invoke_provider(
    provider: Callable[..., Any], *,
    source: Any, path: Optional[Path], data: bytes,
    analyses: Mapping[str, Any], metadata: Mapping[str, Any],
) -> Optional[Mapping[str, Any]]:
    arguments = _build_provider_arguments(
        provider, source=source, path=path, data=data,
        analyses=analyses, metadata=metadata,
    )
    if arguments is None:
        return None
    try:
        result = provider(**arguments)
    except Exception:
        return None
    return _result_to_mapping(result)


def _discover_provider(module: Any) -> Optional[Callable[..., Any]]:
    for name in PROVIDER_FUNCTION_NAMES:
        candidate = getattr(module, name, None)
        if callable(candidate):
            return candidate
    for cls_name in PROVIDER_CLASS_NAMES:
        cls = getattr(module, cls_name, None)
        if cls is None:
            continue
        try:
            instance = cls()
        except Exception:
            continue
        for name in PROVIDER_FUNCTION_NAMES:
            candidate = getattr(instance, name, None)
            if callable(candidate):
                return candidate
    for attr_name in dir(module):
        if attr_name.startswith("_"):
            continue
        if attr_name.startswith("extract_"):
            candidate = getattr(module, attr_name)
            if callable(candidate):
                return candidate
    return None


def _module_feature_namespace(module_name: str) -> str:
    parts = module_name.split("src.extraction.", 1)
    value = parts[1] if len(parts) == 2 else module_name
    return _sanitize_feature_name(value.replace(".", "_"))


# ---------------------------------------------------------------------------
# FeaturePipeline
# ---------------------------------------------------------------------------


class FeaturePipeline:
    """Unified static feature extraction pipeline."""

    def __init__(
        self, *,
        max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
        max_zip_entries: int = DEFAULT_MAX_ZIP_ENTRIES,
        include_paths: bool = False,
        enable_specialized_extractors: bool = True,
    ) -> None:
        self.max_read_bytes = max(1, _safe_int(max_read_bytes, DEFAULT_MAX_READ_BYTES))
        self.max_zip_entries = max(1, _safe_int(max_zip_entries, DEFAULT_MAX_ZIP_ENTRIES))
        self.include_paths = bool(include_paths)
        self.enable_specialized_extractors = bool(enable_specialized_extractors)
        self._providers: Optional[list[tuple[str, Callable[..., Any]]]] = None

    def _load_providers(self) -> list[tuple[str, Callable[..., Any]]]:
        if self._providers is not None:
            return self._providers
        providers: list[tuple[str, Callable[..., Any]]] = []
        if not self.enable_specialized_extractors:
            self._providers = providers
            return providers
        for module_name in EXTRACTOR_MODULES:
            try:
                module = importlib.import_module(module_name)
            except Exception:
                continue
            provider = _discover_provider(module)
            if provider is not None:
                providers.append((module_name, provider))
        self._providers = providers
        return providers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self, source: Any, *,
        analyses: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> FeatureAnalysis:
        """Normalize supplied analyses and return a FeatureAnalysis object."""
        sz = _source_size(source)
        sh = _source_hash(source)

        normalized: dict[str, dict[str, Any]] = {}
        if analyses:
            for name, value in analyses.items():
                key = _sanitize_feature_name(name)
                normalized[key] = dict(value) if isinstance(value, Mapping) else {"value": value}

        fv: dict[str, float] = {
            "pipeline_source_size": float(sz),
            "pipeline_analysis_count": float(len(normalized)),
            "pipeline_feature_sources": float(len(normalized)),
            "pipeline_source_is_path": float(_coerce_path(source) is not None),
            "pipeline_source_is_bytes": float(isinstance(source, (bytes, bytearray, memoryview))),
        }

        for aname, aval in normalized.items():
            _merge_feature_values(fv, aval, prefix=aname)

        nonzero = sum(1 for v in fv.values() if _safe_float(v) != 0.0)
        fv["pipeline_nonzero_feature_count"] = float(nonzero)
        fv["pipeline_total_feature_count"] = float(len(fv) + 1)

        final_meta: dict[str, Any] = {
            "source_hash": sh, "source_size": sz,
            "static_analysis": True, "execution_performed": False,
            "network_access_performed": False, "external_relationships_fetched": False,
        }
        if self.include_paths:
            final_meta["source_path"] = str(source)
        if metadata:
            final_meta.update(dict(metadata))

        return FeatureAnalysis(
            source=source, source_size=sz, source_hash=sh,
            analyses=normalized,
            feature_vector=dict(sorted(fv.items())),
            feature_names=sorted(fv),
            metadata=final_meta,
        )

    def analyze_file(self, path: str | Path, **kwargs: Any) -> FeatureAnalysis:
        """Perform the complete static analysis pipeline on a filesystem file."""
        file_path = _coerce_path(path)
        if file_path is None:
            raise TypeError("path must be a filesystem path")
        if not file_path.exists():
            raise FileNotFoundError(f"File does not exist: {file_path}")
        if not file_path.is_file():
            raise ValueError(f"Path is not a regular file: {file_path}")

        data = _read_source_bytes(file_path, max_bytes=self.max_read_bytes)
        actual_size = _source_size(file_path)
        actual_hash = _source_hash(file_path)
        extension = file_path.suffix.lower()
        text = _decode_text(data)

        analyses: dict[str, dict[str, Any]] = {}

        # Common
        analyses["file"] = _inspect_file(file_path, data)
        analyses["entropy"] = _inspect_entropy(data)
        analyses["strings"] = _inspect_strings(data)
        analyses["metadata"] = _inspect_metadata(file_path, data)
        analyses["raw_text"] = _inspect_raw_source_text(data)

        # OOXML
        analyses["ooxml"] = _inspect_zip_structure(data, max_entries=self.max_zip_entries)
        analyses["office"] = {
            "is_ooxml": float(extension in SUPPORTED_OOXML_EXTENSIONS and data.startswith(b"PK")),
            "macro_enabled_extension": float(extension in MACRO_ENABLED_EXTENSIONS),
            "vba_marker_present": float(any(m in data for m in VBA_MARKERS)),
            "ole_marker_present": float(any(m in data for m in OLE_MARKERS)),
        }

        # Script indicators
        analyses["script"] = {
            "javascript_indicator": float(bool(re.search(r"\b(?:javascript|eval|document\.write)\b", text, re.I))),
            "vbscript_indicator": float(bool(re.search(r"\b(?:vbscript|createobject|wscript\.shell)\b", text, re.I))),
            "powershell_indicator": float(bool(re.search(r"\bpowershell(?:\.exe)?\b", text, re.I))),
        }

        # URLs
        urls = URL_PATTERN.findall(text)
        analyses["urls"] = {
            "url_count": float(len(urls)),
            "unique_url_count": float(len(set(urls))),
            "http_url_count": float(sum(u.lower().startswith("http://") for u in urls)),
            "https_url_count": float(sum(u.lower().startswith("https://") for u in urls)),
            "ftp_url_count": float(sum(u.lower().startswith("ftp://") for u in urls)),
            "ip_literal_count": float(len(IP_PATTERN.findall(text))),
        }

        # Capabilities
        raw = analyses["raw_text"]
        analyses["capabilities"] = {
            "dynamic_execution_indicator": float(any(
                raw.get(f"suspicious_{k}", 0) > 0
                for k in ("powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "shell_execute")
            )),
            "payload_indicator": float(raw.get("suspicious_base64", 0) > 0 or raw.get("suspicious_encoded_command", 0) > 0),
            "communication_indicator": float(analyses["urls"].get("url_count", 0) > 0),
        }

        # Specialized extractors
        specialized_successes: list[str] = []
        provider_context = {"source_hash": actual_hash, "source_size": actual_size, "extension": extension}

        for module_name, provider in self._load_providers():
            namespace = _module_feature_namespace(module_name)
            result = _invoke_provider(
                provider, source=file_path, path=file_path, data=data,
                analyses=analyses, metadata=provider_context,
            )
            if result is None:
                continue
            try:
                numeric = _flatten_numeric_mapping(result)
            except Exception:
                continue
            if numeric:
                analyses[namespace] = dict(numeric)
                specialized_successes.append(module_name)

        # Derived features
        analyses["derived"] = self._derive_features(analyses, extension=extension, data=data)

        # Final metadata
        pipeline_metadata = {
            "file_extension": extension, "file_name": file_path.name,
            "is_ooxml_zip": bool(data.startswith(b"PK") and extension in SUPPORTED_OOXML_EXTENSIONS),
            "specialized_extractors_enabled": self.enable_specialized_extractors,
            "specialized_extractor_count": float(len(self._load_providers())),
            "specialized_extractors_used": specialized_successes,
            "execution_performed": False, "network_access_performed": False,
            "macro_execution_performed": False, "script_execution_performed": False,
            "ole_execution_performed": False, "external_relationships_fetched": False,
            "source_size_actual": actual_size, "source_size_read": len(data),
            "source_hash": actual_hash,
        }
        pipeline_metadata.update(kwargs.pop("metadata", {}))

        return self.analyze(file_path, analyses=analyses, metadata=pipeline_metadata)

    # ------------------------------------------------------------------
    # Derived features
    # ------------------------------------------------------------------

    def _derive_features(
        self, analyses: Mapping[str, Mapping[str, Any]], *,
        extension: str, data: bytes,
    ) -> dict[str, float]:
        raw = analyses.get("raw_text", {})
        ooxml = analyses.get("ooxml", {})
        office = analyses.get("office", {})
        entropy = analyses.get("entropy", {})
        strings = analyses.get("strings", {})
        urls = analyses.get("urls", {})
        capabilities = analyses.get("capabilities", {})

        suspicious_total = _safe_float(raw.get("suspicious_string_count", 0))
        ext_rels = _safe_float(ooxml.get("ooxml_relationships_external", 0))
        macro_parts = _safe_float(ooxml.get("zip_macro_parts", 0))
        susp_parts = _safe_float(ooxml.get("zip_suspicious_parts", 0))
        url_count = _safe_float(urls.get("url_count", 0))
        high_ent = _safe_float(entropy.get("high_entropy", 0))

        macro_present = (
            office.get("macro_enabled_extension", 0) > 0
            or office.get("vba_marker_present", 0) > 0
            or macro_parts > 0
            or ooxml.get("ooxml_content_types_macro_enabled", 0) > 0
        )

        return {
            "macro_present": float(macro_present),
            "external_reference_present": float(ext_rels > 0),
            "suspicious_content_present": float(suspicious_total > 0 or susp_parts > 0),
            "script_capability_present": float(capabilities.get("dynamic_execution_indicator", 0) > 0),
            "payload_capability_present": float(capabilities.get("payload_indicator", 0) > 0),
            "communication_capability_present": float(capabilities.get("communication_indicator", 0) > 0),
            "url_present": float(url_count > 0),
            "high_entropy_present": high_ent,
            "macro_and_suspicious_content": float(
                (office.get("macro_enabled_extension", 0) > 0 or macro_parts > 0)
                and (suspicious_total > 0 or susp_parts > 0)
            ),
            "external_reference_and_url": float(ext_rels > 0 and url_count > 0),
            "packed_or_encoded_indicator": float(
                high_ent > 0
                and (raw.get("suspicious_base64", 0) > 0 or raw.get("suspicious_encoded_command", 0) > 0)
            ),
            "large_compression_ratio_indicator": float(_safe_float(ooxml.get("zip_compression_ratio", 0)) >= 10.0),
            "extension_macro_consistency": float(
                (extension in MACRO_ENABLED_EXTENSIONS and (macro_parts > 0 or office.get("vba_marker_present", 0) > 0))
                or (extension not in MACRO_ENABLED_EXTENSIONS and macro_parts == 0)
            ),
            "string_density": _safe_float(strings.get("ascii_string_count", 0)) / max(1.0, float(len(data))),
        }

    # ------------------------------------------------------------------
    # Compatibility methods
    # ------------------------------------------------------------------

    def extract_features(self, source: Any, **kwargs: Any) -> FeatureAnalysis:
        return self.analyze(source, **kwargs)

    def analyze_features(self, source: Any, **kwargs: Any) -> FeatureAnalysis:
        return self.analyze(source, **kwargs)


# ---------------------------------------------------------------------------
# Module-level compatibility API
# ---------------------------------------------------------------------------

_INIT_KEYS = {"max_read_bytes", "max_zip_entries", "include_paths", "enable_specialized_extractors"}


def analyze_file(path: str | Path, **kwargs: Any) -> FeatureAnalysis:
    init_kw = {k: kwargs.pop(k) for k in _INIT_KEYS if k in kwargs}
    return FeaturePipeline(**init_kw).analyze_file(path, **kwargs)


def analyze_features(
    source: Any, *,
    analyses: Optional[Mapping[str, Any]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> FeatureAnalysis:
    init_kw = {k: kwargs.pop(k) for k in _INIT_KEYS if k in kwargs}
    return FeaturePipeline(**init_kw).analyze(source, analyses=analyses, metadata=metadata)


def extract_features(source: Any, **kwargs: Any) -> FeatureAnalysis:
    return analyze_features(source, **kwargs)


# Historical aliases
FeatureExtractorPipeline = FeaturePipeline
PipelineAnalysis = FeatureAnalysis


__all__ = [
    "FeatureAnalysis", "FeaturePipeline",
    "FeatureExtractorPipeline", "PipelineAnalysis",
    "analyze_file", "analyze_features", "extract_features",
    "DEFAULT_HASH_CHUNK_SIZE", "DEFAULT_MAX_READ_BYTES",
    "DEFAULT_MAX_ZIP_ENTRIES", "DEFAULT_MAX_XML_BYTES", "DEFAULT_MAX_TEXT_BYTES",
]
