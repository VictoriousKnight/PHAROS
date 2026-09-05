"""
Pharos CDR Flask routes.

This module exposes the HTTP/web interface for the Pharos CDR application.

Security model
--------------
The web layer is intentionally thin. Uploaded documents are passed to the
existing static analysis pipeline in ``src.pipeline.scanner``. This module
does not execute documents, macros, scripts, subprocesses, or network
connections.

The route layer is responsible for:

* HTTP request validation
* bounded multipart uploads
* safe filename handling
* invoking the scanner
* rendering HTML pages
* serializing scan results
* returning sanitized content when available
* health/readiness endpoints
* consistent error responses

Expected Flask application layout:

    pharos-cdr/
    ├── src/
    │   └── api/
    │       ├── app.py
    │       ├── routes.py
    │       └── schemas.py
    │
    └── web/
        ├── templates/
        │   ├── index.html
        │   ├── scan.html
        │   └── result.html
        └── static/
            ├── css/
            │   └── app.css
            └── js/
                └── app.js

The application factory in ``app.py`` should call:

    register_routes(app)

No uploaded document is persisted by this module unless the scanner or
application layer explicitly does so through a controlled API.
"""

from __future__ import annotations

import io
import json
import logging
import mimetypes
import os
import re
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

try:
    from ..pipeline import report as report_pipeline
    from ..pipeline import scanner as scanner_pipeline
except ImportError:  # pragma: no cover - supports direct module execution
    from src.pipeline import report as report_pipeline
    from src.pipeline import scanner as scanner_pipeline


LOGGER = logging.getLogger(__name__)


MODULE_NAME = "pharos_cdr.api.routes"
ROUTES_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Request limits
# ---------------------------------------------------------------------------

DEFAULT_MAX_UPLOAD_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_REQUEST_BYTES = 110 * 1024 * 1024

MAX_FILENAME_LENGTH = 255
MAX_CONTENT_TYPE_LENGTH = 150
MAX_ERROR_LENGTH = 1000

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


# ---------------------------------------------------------------------------
# Allowed / known document types
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = frozenset(
    {
        # Microsoft Office / OOXML
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

        # Legacy Office / OLE
        ".doc",
        ".xls",
        ".ppt",
        ".dot",
        ".xlt",
        ".pot",
        ".pps",

        # Documents
        ".pdf",
        ".rtf",

        # Scripts
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".psm1",
        ".psd1",
        ".bat",
        ".cmd",
        ".sh",
        ".bash",

        # Text / source formats that can be statically inspected
        ".txt",
        ".csv",
        ".xml",
        ".html",
        ".htm",
        ".json",
    }
)


ALLOWED_MIME_TYPES = frozenset(
    {
        "application/octet-stream",

        "application/pdf",
        "application/rtf",
        "text/rtf",

        "text/plain",
        "text/csv",
        "text/xml",
        "application/xml",
        "application/json",

        "text/html",

        # OOXML
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
        "application/vnd.ms-word.document.macroenabled.12",
        "application/vnd.ms-word.template.macroenabled.12",

        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/vnd.ms-excel.template.macroenabled.12",

        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.presentationml.template",
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
        "application/vnd.ms-powerpoint.presentation.macroenabled.12",
        "application/vnd.ms-powerpoint.template.macroenabled.12",
        "application/vnd.ms-powerpoint.slideshow.macroenabled.12",

        # Legacy Office
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",

        # Common script types
        "application/javascript",
        "text/javascript",
        "application/x-javascript",

        "text/vbscript",
        "application/x-vbscript",

        "text/x-powershell",
        "application/x-powershell",

        "application/x-bat",
        "application/x-sh",
    }
)


# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

api = Blueprint(
    "pharos_cdr_api",
    __name__,
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class APIError(Exception):
    """Base exception for route-level failures."""

    status_code = 500
    error_code = "api_error"

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        error_code: Optional[str] = None,
    ) -> None:
        super().__init__(message)

        self.message = str(message)

        if status_code is not None:
            self.status_code = int(status_code)

        if error_code is not None:
            self.error_code = str(error_code)


class RequestValidationError(APIError):
    """Raised when an HTTP request fails validation."""

    status_code = 400
    error_code = "invalid_request"


class UploadValidationError(APIError):
    """Raised when an uploaded file fails validation."""

    status_code = 400
    error_code = "invalid_upload"


class UploadTooLargeError(APIError):
    """Raised when an uploaded document exceeds the configured limit."""

    status_code = 413
    error_code = "upload_too_large"


class ScanExecutionError(APIError):
    """Raised when the static scanning pipeline cannot complete."""

    status_code = 500
    error_code = "scan_failed"


class ReportGenerationError(APIError):
    """Raised when a scan result cannot be rendered."""

    status_code = 500
    error_code = "report_failed"


class SanitizedContentUnavailableError(APIError):
    """Raised when sanitized output was requested but is unavailable."""

    status_code = 404
    error_code = "sanitized_content_unavailable"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_text(
    value: Any,
    *,
    default: str = "",
    maximum: int = MAX_ERROR_LENGTH,
) -> str:
    """Convert an arbitrary value into bounded text."""

    if value is None:
        return default

    try:
        text = str(value)
    except Exception:
        return default

    text = text.replace("\x00", "")

    if maximum > 0:
        return text[:maximum]

    return text


def _safe_filename(filename: Any) -> str:
    """
    Return a filesystem-safe display filename.

    The route layer never trusts the filename supplied by the browser.
    Directory traversal components are discarded and control characters are
    removed.
    """

    name = _safe_text(
        filename,
        default="uploaded_document",
        maximum=MAX_FILENAME_LENGTH,
    )

    name = name.replace("\\", "/")

    # Keep only the final path component.
    name = name.rsplit("/", 1)[-1]

    # Remove control characters.
    name = "".join(
        character
        for character in name
        if ord(character) >= 32
        and ord(character) != 127
    )

    # Avoid hidden/path-like names.
    name = name.strip().strip(".")

    if not name:
        name = "uploaded_document"

    # Avoid special Windows device names in generated response filenames.
    stem = Path(name).stem.upper()

    if stem in {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }:
        name = "uploaded_document"

    return name[:MAX_FILENAME_LENGTH]


def _extension(filename: str) -> str:
    """Return a normalized lowercase file extension."""

    return Path(filename).suffix.lower()


def _configured_max_upload_bytes() -> int:
    """Read the upload limit from Flask configuration."""

    configured = current_app.config.get(
        "PHAROS_MAX_UPLOAD_BYTES",
        DEFAULT_MAX_UPLOAD_BYTES,
    )

    try:
        value = int(configured)
    except (TypeError, ValueError):
        value = DEFAULT_MAX_UPLOAD_BYTES

    return max(1, value)


def _configured_request_limit() -> int:
    """Read the maximum Flask request size."""

    configured = current_app.config.get(
        "MAX_CONTENT_LENGTH",
        DEFAULT_MAX_REQUEST_BYTES,
    )

    try:
        value = int(configured)
    except (TypeError, ValueError):
        value = DEFAULT_MAX_REQUEST_BYTES

    return max(1, value)


def _is_json_request() -> bool:
    """Determine whether the client requested a JSON response."""

    if request.is_json:
        return True

    accepted = request.accept_mimetypes

    return accepted.best == "application/json"


def _json_error(
    error: APIError,
) -> Response:
    """Create a consistent JSON API error response."""

    payload = {
        "ok": False,
        "error": {
            "code": error.error_code,
            "message": _safe_text(error.message),
        },
        "module": MODULE_NAME,
        "version": ROUTES_VERSION,
    }

    return jsonify(payload), error.status_code


def _dataclass_to_dict(value: Any) -> Any:
    """Convert dataclasses and nested values into JSON-compatible objects."""

    if is_dataclass(value) and not isinstance(value, type):
        try:
            return {
                key: _dataclass_to_dict(item)
                for key, item in asdict(value).items()
            }
        except Exception:
            pass

    if isinstance(value, Mapping):
        return {
            str(key): _dataclass_to_dict(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            _dataclass_to_dict(item)
            for item in value
        ]

    if isinstance(value, set):
        return [
            _dataclass_to_dict(item)
            for item in sorted(
                value,
                key=lambda item: str(item),
            )
        ]

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return _safe_text(value)


def _result_to_dict(result: Any) -> dict[str, Any]:
    """
    Normalize a scanner result into a JSON-compatible dictionary.
    """

    if result is None:
        return {}

    if hasattr(scanner_pipeline, "result_to_dict"):
        try:
            normalized = scanner_pipeline.result_to_dict(result)

            if isinstance(normalized, Mapping):
                return dict(
                    _dataclass_to_dict(normalized)
                )
        except Exception:
            LOGGER.debug(
                "scanner.result_to_dict failed; falling back",
                exc_info=True,
            )

    normalized = _dataclass_to_dict(result)

    if isinstance(normalized, Mapping):
        return dict(normalized)

    return {
        "result": normalized,
    }


def _result_to_json(
    result: Any,
    *,
    pretty: bool = False,
) -> str:
    """Serialize a scan result deterministically where possible."""

    if hasattr(scanner_pipeline, "result_to_json"):
        try:
            return str(
                scanner_pipeline.result_to_json(
                    result,
                    pretty=pretty,
                )
            )
        except TypeError:
            try:
                return str(
                    scanner_pipeline.result_to_json(result)
                )
            except Exception:
                LOGGER.debug(
                    "scanner.result_to_json failed",
                    exc_info=True,
                )
        except Exception:
            LOGGER.debug(
                "scanner.result_to_json failed",
                exc_info=True,
            )

    data = _result_to_dict(result)

    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
    )


def _get_result_value(
    result: Any,
    *names: str,
    default: Any = None,
) -> Any:
    """
    Retrieve a value from a dataclass/object/mapping using several possible
    field names.
    """

    if result is None:
        return default

    for name in names:
        if isinstance(result, Mapping) and name in result:
            return result[name]

        try:
            value = getattr(result, name)
        except Exception:
            continue

        if value is not None:
            return value

    return default


def _read_upload_bytes(
    storage: Any,
) -> bytes:
    """Read an uploaded file with an explicit memory bound."""

    if storage is None:
        raise UploadValidationError(
            "No uploaded file was supplied."
        )

    stream = getattr(storage, "stream", None)

    if stream is None:
        raise UploadValidationError(
            "The uploaded file has no readable stream."
        )

    maximum = _configured_max_upload_bytes()

    chunks: list[bytes] = []
    total = 0

    while True:
        chunk = stream.read(
            min(1024 * 1024, maximum - total + 1)
        )

        if not chunk:
            break

        if not isinstance(chunk, bytes):
            chunk = bytes(chunk)

        total += len(chunk)

        if total > maximum:
            raise UploadTooLargeError(
                "The uploaded document exceeds the configured "
                f"maximum size of {maximum} bytes."
            )

        chunks.append(chunk)

    data = b"".join(chunks)

    if not data:
        raise UploadValidationError(
            "The uploaded document is empty."
        )

    return data


def _validate_upload_metadata(
    filename: str,
    content_type: Optional[str],
) -> None:
    """Validate filename and content type without trusting either."""

    extension = _extension(filename)

    if not extension:
        raise UploadValidationError(
            "The uploaded document must have a file extension."
        )

    if extension not in ALLOWED_EXTENSIONS:
        raise UploadValidationError(
            f"Unsupported file extension: {extension}"
        )

    if content_type:
        content_type = content_type.lower().split(";", 1)[0].strip()

        if (
            len(content_type) > MAX_CONTENT_TYPE_LENGTH
        ):
            raise UploadValidationError(
                "The supplied content type is invalid."
            )
 
        #  Content-Type is advisory only. Browsers and reverse proxies can
        #  provide generic application/octet-stream, and valid documents can
        #  be mislabeled. The authoritative content validation is performed
        #  by the ingestion/scanner pipeline.
        
        if (
            content_type not in ALLOWED_MIME_TYPES
            and not content_type.startswith("text/")
            and not content_type.startswith("application/")
        ):
            raise UploadValidationError(
                f"Unsupported content type: {content_type}"
            )


def _validate_upload(
    storage: Any,
) -> tuple[str, str, bytes]:
    """Validate and read a Flask uploaded file."""

    filename = _safe_filename(
        getattr(storage, "filename", None)
    )

    content_type = _safe_text(
        getattr(storage, "content_type", None),
        maximum=MAX_CONTENT_TYPE_LENGTH,
    )

    _validate_upload_metadata(
        filename,
        content_type,
    )

    data = _read_upload_bytes(storage)

    return filename, content_type, data


def _scanner_config_from_request() -> Any:
    """
    Build a scanner configuration from safe request parameters.

    The default configuration remains authoritative. Only explicitly
    supported boolean options are accepted.
    """

    mode = request.form.get(
        "mode",
        request.args.get("mode", ""),
    ).strip().lower()

    if mode == "strict":
        if hasattr(scanner_pipeline, "strict_config"):
            return scanner_pipeline.strict_config()

    if mode in {"minimal", "fast"}:
        if hasattr(scanner_pipeline, "minimal_config"):
            return scanner_pipeline.minimal_config()

    if mode in {"analysis", "analysis_only"}:
        if hasattr(scanner_pipeline, "analysis_config"):
            return scanner_pipeline.analysis_config()

    if hasattr(scanner_pipeline, "default_config"):
        return scanner_pipeline.default_config()

    return None


def _scan_bytes(
    data: bytes,
    filename: str,
    *,
    config: Any = None,
) -> Any:
    """Invoke the existing scanner using bytes."""

    try:
        if hasattr(scanner_pipeline, "scan_bytes"):
            if config is not None:
                return scanner_pipeline.scan_bytes(
                    data,
                    filename=filename,
                    config=config,
                )

            return scanner_pipeline.scan_bytes(
                data,
                filename=filename,
            )

        if hasattr(scanner_pipeline, "scan"):
            if config is not None:
                return scanner_pipeline.scan(
                    data,
                    filename=filename,
                    config=config,
                )

            return scanner_pipeline.scan(
                data,
                filename=filename,
            )

    except (
        scanner_pipeline.ScanError,
        scanner_pipeline.ScanInputError,
        scanner_pipeline.ScanLimitError,
        scanner_pipeline.ScanStageError,
    ) as exc:
        raise ScanExecutionError(
            _safe_text(exc)
        ) from exc

    except Exception as exc:
        LOGGER.exception(
            "Unexpected scanner failure"
        )

        raise ScanExecutionError(
            "The static analysis pipeline could not "
            "complete the requested scan."
        ) from exc

    raise ScanExecutionError(
        "The scanner implementation is unavailable."
    )


def _build_report(
    result: Any,
    *,
    report_format: str,
) -> str:
    """Render a scanner result using the existing report pipeline."""

    report_format = report_format.lower().strip()

    try:
        if report_format == "json":
            return report_pipeline.report_to_json(
                result
            )

        if report_format == "html":
            return report_pipeline.report_to_html(
                result
            )

        if report_format in {"text", "txt"}:
            return report_pipeline.report_to_text(
                result
            )

        if report_format in {"jsonl", "ndjson"}:
            return report_pipeline.report_to_jsonl(
                result
            )

    except Exception as exc:
        LOGGER.exception(
            "Report rendering failed"
        )

        raise ReportGenerationError(
            "The scan completed, but the report could not "
            "be generated."
        ) from exc

    raise ReportGenerationError(
        f"Unsupported report format: {report_format}"
    )


def _scan_context(
    result: Any,
) -> dict[str, Any]:
    """Prepare a bounded context for HTML result templates."""

    data = _result_to_dict(result)

    probability = _get_result_value(
        result,
        "model_probability",
        "probability",
        "malicious_probability",
        "score",
    )

    verdict = _get_result_value(
        result,
        "verdict",
        "scan_verdict",
        "disposition",
    )

    status = _get_result_value(
        result,
        "status",
        "scan_status",
    )

    filename = _get_result_value(
        result,
        "filename",
        "file_name",
        "name",
    )

    sha256 = _get_result_value(
        result,
        "sha256",
        "file_sha256",
        "input_sha256",
    )

    return {
        "result": result,
        "data": data,
        "filename": _safe_text(
            filename,
            default="uploaded_document",
            maximum=MAX_FILENAME_LENGTH,
        ),
        "verdict": _safe_text(
            verdict,
            default="unknown",
            maximum=100,
        ),
        "status": _safe_text(
            status,
            default="completed",
            maximum=100,
        ),
        "probability": probability,
        "sha256": _safe_text(
            sha256,
            maximum=128,
        ),
    }


def _report_data_for_result(
    result: Any,
) -> dict[str, Any]:
    """Build report data for APIs that need structured report content."""

    if hasattr(report_pipeline, "build_report_data"):
        try:
            data = report_pipeline.build_report_data(
                result
            )

            if isinstance(data, Mapping):
                return dict(
                    _dataclass_to_dict(data)
                )
        except Exception:
            LOGGER.debug(
                "build_report_data failed",
                exc_info=True,
            )

    return _result_to_dict(result)


def _sanitized_bytes(
    result: Any,
) -> tuple[bytes, str]:
    """
    Extract sanitized bytes from a scan result.

    The scanner remains the owner of sanitization. This route never performs
    sanitization itself.
    """

    candidate = _get_result_value(
        result,
        "sanitized_content",
        "sanitized_bytes",
        "sanitized_data",
        "sanitized",
    )

    if candidate is None:
        raise SanitizedContentUnavailableError(
            "No sanitized document is available for this scan."
        )

    if isinstance(candidate, bytes):
        data = candidate

    elif isinstance(candidate, bytearray):
        data = bytes(candidate)

    elif isinstance(candidate, memoryview):
        data = candidate.tobytes()

    elif isinstance(candidate, Mapping):
        nested = candidate.get("content")

        if nested is None:
            nested = candidate.get("data")

        if isinstance(nested, bytes):
            data = nested
        elif isinstance(nested, bytearray):
            data = bytes(nested)
        else:
            raise SanitizedContentUnavailableError(
                "The scan result does not contain downloadable "
                "sanitized document bytes."
            )

    else:
        raise SanitizedContentUnavailableError(
            "The scan result does not contain downloadable "
            "sanitized document bytes."
        )

    if not data:
        raise SanitizedContentUnavailableError(
            "The sanitized document is empty."
        )

    if len(data) > _configured_max_upload_bytes():
        raise SanitizedContentUnavailableError(
            "The sanitized document exceeds the configured "
            "download limit."
        )

    filename = _get_result_value(
        result,
        "filename",
        "file_name",
        "name",
        default="document",
    )

    filename = _safe_filename(filename)

    suffix = Path(filename).suffix

    if suffix:
        output_name = (
            Path(filename).stem
            + "_sanitized"
            + suffix
        )
    else:
        output_name = filename + "_sanitized"

    return data, output_name


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------


@api.errorhandler(APIError)
def handle_api_error(error: APIError):
    """Handle application-specific API errors."""

    if _is_json_request():
        return _json_error(error)

    return render_template(
        "error.html",
        error=error,
        status_code=error.status_code,
    ), error.status_code


@api.errorhandler(413)
def handle_request_too_large(error):
    """Handle Flask/reverse-proxy request-size violations."""

    api_error = UploadTooLargeError(
        "The request exceeds the maximum permitted upload size."
    )

    if _is_json_request():
        return _json_error(api_error)

    return render_template(
        "error.html",
        error=api_error,
        status_code=413,
    ), 413


@api.errorhandler(404)
def handle_not_found(error):
    """Return a consistent 404 response."""

    if _is_json_request():
        return jsonify(
            {
                "ok": False,
                "error": {
                    "code": "not_found",
                    "message": "The requested resource was not found.",
                },
            }
        ), 404

    return render_template(
        "error.html",
        error=APIError(
            "The requested resource was not found.",
            status_code=404,
            error_code="not_found",
        ),
        status_code=404,
    ), 404


@api.errorhandler(Exception)
def handle_unexpected_error(error: Exception):
    """Prevent internal exception details from leaking to clients."""

    LOGGER.exception(
        "Unhandled API exception",
        exc_info=error,
    )

    api_error = APIError(
        "An unexpected server error occurred.",
        status_code=500,
        error_code="internal_server_error",
    )

    if _is_json_request():
        return _json_error(api_error)

    return render_template(
        "error.html",
        error=api_error,
        status_code=500,
    ), 500


# ---------------------------------------------------------------------------
# HTML routes
# ---------------------------------------------------------------------------


@api.get("/")
def index():
    """Render the Pharos CDR landing page."""

    return render_template(
        "index.html",
        module=MODULE_NAME,
        version=ROUTES_VERSION,
        max_upload_bytes=_configured_max_upload_bytes(),
        supported_extensions=sorted(
            ALLOWED_EXTENSIONS
        ),
    )


@api.get("/scan")
def scan_page():
    """Render the document upload/scan page."""

    return render_template(
        "scan.html",
        module=MODULE_NAME,
        version=ROUTES_VERSION,
        max_upload_bytes=_configured_max_upload_bytes(),
        supported_extensions=sorted(
            ALLOWED_EXTENSIONS
        ),
    )


@api.post("/scan")
def scan_upload():
    """
    Receive a browser multipart upload and run the static scanner.

    On success this route renders the browser result page. Clients requesting
    JSON receive the same result as structured JSON instead.
    """

    storage = request.files.get("file")

    if storage is None:
        raise RequestValidationError(
            "The request must contain a file field named 'file'."
        )

    filename, content_type, data = _validate_upload(
        storage
    )

    config = _scanner_config_from_request()

    result = _scan_bytes(
        data,
        filename,
        config=config,
    )

    if _is_json_request():
        return jsonify(
            {
                "ok": True,
                "result": _result_to_dict(result),
            }
        )

    context = _scan_context(result)

    context.update(
        {
            "filename": filename,
            "content_type": content_type,
            "input_size": len(data),
        }
    )

    return render_template(
        "result.html",
        **context,
    )


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------


@api.post("/api/scan")
def api_scan():
    """
    JSON-compatible document scanning endpoint.

    The preferred request format is multipart/form-data:

        POST /api/scan
        file=<document>

    Optional form field:

        mode=strict|balanced|analysis|minimal

    A JSON request body may also contain:

        {
            "content": "...",
            "filename": "document.txt"
        }

    The JSON-content form is intended for bounded textual/static inputs.
    Binary documents should use multipart upload.
    """

    if request.files:
        storage = request.files.get("file")

        if storage is None:
            raise RequestValidationError(
                "A multipart request must contain a "
                "'file' field."
            )

        filename, content_type, data = _validate_upload(
            storage
        )

    elif request.is_json:
        payload = request.get_json(
            silent=True
        )

        if not isinstance(payload, Mapping):
            raise RequestValidationError(
                "The JSON request body must be an object."
            )

        filename = _safe_filename(
            payload.get(
                "filename",
                "uploaded_document.txt",
            )
        )

        content = payload.get("content")

        if not isinstance(content, str):
            raise RequestValidationError(
                "JSON scanning requires a string "
                "'content' field."
            )

        encoded = content.encode(
            "utf-8",
            errors="strict",
        )

        if len(encoded) > _configured_max_upload_bytes():
            raise UploadTooLargeError(
                "The supplied JSON content exceeds "
                "the configured maximum size."
            )

        data = encoded
        content_type = "text/plain"

        _validate_upload_metadata(
            filename,
            content_type,
        )

    else:
        raise RequestValidationError(
            "Expected multipart/form-data or application/json."
        )

    config = _scanner_config_from_request()

    if request.is_json:
        mode = request.json.get("mode")

        if mode:
            with current_app.test_request_context(
                query_string={"mode": str(mode)}
            ):
                config = _scanner_config_from_request()

    result = _scan_bytes(
        data,
        filename,
        config=config,
    )

    return jsonify(
        {
            "ok": True,
            "result": _result_to_dict(result),
        }
    )


@api.get("/api/scan/<scan_id>")
def api_scan_by_id(scan_id: str):
    """
    Retrieve a previously stored scan result.

    Persistence is deliberately application-owned. This endpoint looks for
    an optional application-provided scan-result store callable:

        current_app.extensions["pharos_scan_store"]

    The callable must accept the scan ID and return a scanner result.

    If no result store is configured, a 501 response is returned rather than
    pretending that scans are persisted.
    """

    scan_id = _safe_text(
        scan_id,
        maximum=128,
    ).strip()

    if not scan_id:
        raise RequestValidationError(
            "A scan ID is required."
        )

    if not re.fullmatch(
        r"[A-Za-z0-9._:-]{1,128}",
        scan_id,
    ):
        raise RequestValidationError(
            "The supplied scan ID contains invalid characters."
        )

    store = current_app.extensions.get(
        "pharos_scan_store"
    )

    if store is None:
        raise APIError(
            "Persistent scan-result storage is not configured.",
            status_code=501,
            error_code="scan_store_unavailable",
        )

    try:
        result = store(scan_id)
    except Exception as exc:
        LOGGER.exception(
            "Scan-result store failed"
        )

        raise ScanExecutionError(
            "The scan-result store could not be queried."
        ) from exc

    if result is None:
        raise APIError(
            "The requested scan result was not found.",
            status_code=404,
            error_code="scan_not_found",
        )

    return jsonify(
        {
            "ok": True,
            "scan_id": scan_id,
            "result": _result_to_dict(result),
        }
    )


# ---------------------------------------------------------------------------
# Report endpoints
# ---------------------------------------------------------------------------


@api.post("/api/report")
def api_report():
    """
    Scan an uploaded document and return a rendered report.

    Supported query/form parameter:

        format=json
        format=jsonl
        format=html
        format=text
    """

    storage = request.files.get("file")

    if storage is None:
        raise RequestValidationError(
            "The request must contain a file field named 'file'."
        )

    filename, _, data = _validate_upload(storage)

    requested_format = (
        request.form.get(
            "format",
            request.args.get(
                "format",
                "json",
            ),
        )
        .strip()
        .lower()
    )

    if requested_format not in {
        "json",
        "jsonl",
        "html",
        "text",
        "txt",
    }:
        raise RequestValidationError(
            "Unsupported report format. "
            "Use json, jsonl, html, or text."
        )

    result = _scan_bytes(
        data,
        filename,
        config=_scanner_config_from_request(),
    )

    report_format = (
        "text"
        if requested_format == "txt"
        else requested_format
    )

    rendered = _build_report(
        result,
        report_format=report_format,
    )

    if report_format == "json":
        return Response(
            rendered,
            status=200,
            mimetype="application/json",
        )

    if report_format == "jsonl":
        return Response(
            rendered,
            status=200,
            mimetype="application/x-ndjson",
        )

    if report_format == "html":
        return Response(
            rendered,
            status=200,
            mimetype="text/html",
        )

    return Response(
        rendered,
        status=200,
        mimetype="text/plain",
    )


@api.get("/api/report/<scan_id>")
def api_report_by_id(scan_id: str):
    """
    Render a report from a persisted scan result.

    Requires the same optional ``pharos_scan_store`` extension used by
    ``api_scan_by_id``.
    """

    scan_id = _safe_text(
        scan_id,
        maximum=128,
    ).strip()

    if not re.fullmatch(
        r"[A-Za-z0-9._:-]{1,128}",
        scan_id,
    ):
        raise RequestValidationError(
            "The supplied scan ID contains invalid characters."
        )

    store = current_app.extensions.get(
        "pharos_scan_store"
    )

    if store is None:
        raise APIError(
            "Persistent scan-result storage is not configured.",
            status_code=501,
            error_code="scan_store_unavailable",
        )

    try:
        result = store(scan_id)
    except Exception as exc:
        LOGGER.exception(
            "Scan-result store failed"
        )

        raise ScanExecutionError(
            "The scan-result store could not be queried."
        ) from exc

    if result is None:
        raise APIError(
            "The requested scan result was not found.",
            status_code=404,
            error_code="scan_not_found",
        )

    requested_format = request.args.get(
        "format",
        "json",
    ).strip().lower()

    if requested_format not in {
        "json",
        "jsonl",
        "html",
        "text",
    }:
        raise RequestValidationError(
            "Unsupported report format."
        )

    rendered = _build_report(
        result,
        report_format=requested_format,
    )

    mimetypes_by_format = {
        "json": "application/json",
        "jsonl": "application/x-ndjson",
        "html": "text/html",
        "text": "text/plain",
    }

    return Response(
        rendered,
        status=200,
        mimetype=mimetypes_by_format[
            requested_format
        ],
    )


@api.post("/api/report/html")
def api_html_report():
    """Scan a document and return a self-contained HTML report."""

    storage = request.files.get("file")

    if storage is None:
        raise RequestValidationError(
            "The request must contain a file field named 'file'."
        )

    filename, _, data = _validate_upload(storage)

    result = _scan_bytes(
        data,
        filename,
        config=_scanner_config_from_request(),
    )

    rendered = _build_report(
        result,
        report_format="html",
    )

    return Response(
        rendered,
        status=200,
        mimetype="text/html",
    )


# ---------------------------------------------------------------------------
# Sanitized-document endpoint
# ---------------------------------------------------------------------------


@api.post("/api/sanitize")
def api_sanitize():
    """
    Scan and return the sanitized document when sanitization succeeds.

    The scanner/CDR layers remain responsible for deciding whether
    sanitization is appropriate and for constructing the sanitized content.
    """

    storage = request.files.get("file")

    if storage is None:
        raise RequestValidationError(
            "The request must contain a file field named 'file'."
        )

    filename, _, data = _validate_upload(storage)

    config = _scanner_config_from_request()

    result = _scan_bytes(
        data,
        filename,
        config=config,
    )

    sanitized, output_name = _sanitized_bytes(
        result
    )

    mimetype = (
        mimetypes.guess_type(output_name)[0]
        or "application/octet-stream"
    )

    return send_file(
        io.BytesIO(sanitized),
        mimetype=mimetype,
        as_attachment=True,
        download_name=output_name,
        max_age=0,
    )


@api.post("/api/sanitized")
def api_sanitized():
    """
    Alias for the sanitized-document endpoint.

    Kept separate from ``/api/sanitize`` so frontend clients can use the
    semantically clearer resource name.
    """

    return api_sanitize()


# ---------------------------------------------------------------------------
# Health / readiness
# ---------------------------------------------------------------------------


@api.get("/health")
def health():
    """Return a lightweight liveness response."""

    return jsonify(
        {
            "ok": True,
            "status": "healthy",
            "module": MODULE_NAME,
            "version": ROUTES_VERSION,
        }
    )


@api.get("/api/health")
def api_health():
    """JSON API alias for the health endpoint."""

    return health()


@api.get("/ready")
def readiness():
    """
    Return service readiness.

    This intentionally checks imports/configuration rather than running a
    malware scan as part of a health check.
    """

    checks: dict[str, bool] = {
        "scanner": hasattr(
            scanner_pipeline,
            "scan_bytes",
        )
        or hasattr(
            scanner_pipeline,
            "scan",
        ),
        "reporter": (
            hasattr(
                report_pipeline,
                "report_to_json",
            )
            and hasattr(
                report_pipeline,
                "report_to_html",
            )
        ),
    }

    ready = all(checks.values())

    payload = {
        "ok": ready,
        "status": (
            "ready"
            if ready
            else "not_ready"
        ),
        "checks": checks,
        "module": MODULE_NAME,
        "version": ROUTES_VERSION,
    }

    return jsonify(payload), (
        200 if ready else 503
    )


@api.get("/api/ready")
def api_readiness():
    """JSON API alias for readiness."""

    return readiness()


# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------


@api.get("/api/info")
def api_info():
    """Return non-sensitive API/application capability information."""

    return jsonify(
        {
            "ok": True,
            "application": "Pharos CDR",
            "module": MODULE_NAME,
            "version": ROUTES_VERSION,
            "analysis": {
                "static_only": True,
                "executes_documents": False,
                "executes_macros": False,
                "executes_scripts": False,
                "contacts_uploaded_urls": False,
                "starts_processes": False,
            },
            "upload": {
                "max_bytes": _configured_max_upload_bytes(),
                "allowed_extensions": sorted(
                    ALLOWED_EXTENSIONS
                ),
            },
            "reports": [
                "json",
                "jsonl",
                "html",
                "text",
            ],
            "endpoints": {
                "web": [
                    "/",
                    "/scan",
                ],
                "api": [
                    "/api/scan",
                    "/api/report",
                    "/api/report/html",
                    "/api/sanitize",
                    "/api/sanitized",
                    "/api/health",
                    "/api/ready",
                    "/api/info",
                ],
            },
        }
    )


# ---------------------------------------------------------------------------
# Optional API aliases
# ---------------------------------------------------------------------------


@api.post("/analyze")
def analyze_alias():
    """Human-friendly alias for the scan upload endpoint."""

    return scan_upload()


@api.post("/api/analyze")
def api_analyze_alias():
    """API alias for ``/api/scan``."""

    return api_scan()


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------


def register_routes(
    app: Any,
    *,
    url_prefix: str = "",
) -> Blueprint:
    """
    Register the Pharos CDR blueprint with a Flask application.

    Parameters
    ----------
    app:
        Flask application instance.

    url_prefix:
        Optional prefix for all routes.

    Returns
    -------
    Blueprint
        The registered Pharos CDR blueprint.

    Example
    -------
    ::

        from flask import Flask
        from .routes import register_routes

        app = Flask(__name__)
        register_routes(app)

    """

    if app is None:
        raise ValueError(
            "A Flask application instance is required."
        )

    # Configure the Flask-level request bound if the application has not
    # already configured one.
    if not app.config.get("MAX_CONTENT_LENGTH"):
        app.config["MAX_CONTENT_LENGTH"] = (
            DEFAULT_MAX_REQUEST_BYTES
        )

    if "PHAROS_MAX_UPLOAD_BYTES" not in app.config:
        app.config[
            "PHAROS_MAX_UPLOAD_BYTES"
        ] = DEFAULT_MAX_UPLOAD_BYTES

    if "PHAROS_CDR_VERSION" not in app.config:
        app.config[
            "PHAROS_CDR_VERSION"
        ] = ROUTES_VERSION

    app.register_blueprint(
        api,
        url_prefix=url_prefix,
    )

    return api


# ---------------------------------------------------------------------------
# Route inspection helpers
# ---------------------------------------------------------------------------


def route_summary(
    app: Any,
) -> list[dict[str, Any]]:
    """
    Return a deterministic summary of registered Flask routes.

    This is intended for diagnostics and tests.
    """

    if app is None:
        return []

    entries: list[dict[str, Any]] = []

    for rule in app.url_map.iter_rules():
        methods = sorted(
            method
            for method in rule.methods
            if method not in {
                "HEAD",
                "OPTIONS",
            }
        )

        entries.append(
            {
                "endpoint": rule.endpoint,
                "path": str(rule),
                "methods": methods,
            }
        )

    entries.sort(
        key=lambda item: (
            item["path"],
            item["endpoint"],
        )
    )

    return entries


def route_names(
    app: Any,
) -> list[str]:
    """Return sorted registered endpoint names."""

    return sorted(
        {
            rule.endpoint
            for rule in app.url_map.iter_rules()
        }
    )


# ---------------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------------

__all__ = [
    "api",
    "register_routes",
    "APIError",
    "RequestValidationError",
    "UploadValidationError",
    "UploadTooLargeError",
    "ScanExecutionError",
    "ReportGenerationError",
    "SanitizedContentUnavailableError",
    "route_summary",
    "route_names",
    "MODULE_NAME",
    "ROUTES_VERSION",
    "DEFAULT_MAX_UPLOAD_BYTES",
    "DEFAULT_MAX_REQUEST_BYTES",
    "ALLOWED_EXTENSIONS",
    "ALLOWED_MIME_TYPES",
]