"""
pharos-cdr.api.errors
=====================

Centralized error handling for the Pharos CDR Flask/API layer.

Responsibilities
----------------
- Define API-specific exception types.
- Normalize service/scanner/report failures into HTTP-safe errors.
- Produce consistent JSON error envelopes.
- Produce safe HTML error pages without requiring an additional template.
- Prevent accidental disclosure of internal exception details.
- Provide Flask error-handler registration helpers.

Security properties
-------------------
- No exception traceback is returned to API clients by default.
- Internal exception messages are only exposed when explicitly enabled.
- Error responses do not contain uploaded document bytes.
- Error responses do not execute or inspect submitted documents.
- Error payloads are bounded.
"""

from __future__ import annotations

import html
import logging
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from flask import (
    Flask,
    Response,
    current_app,
    jsonify,
    render_template,
    request,
)
from werkzeug.exceptions import HTTPException
from werkzeug.wrappers import Response as WerkzeugResponse

MODULE_NAME = "pharos_cdr.api.errors"
ERRORS_VERSION = "1.0.0"

LOGGER = logging.getLogger(MODULE_NAME)

MAX_ERROR_CODE_LENGTH = 128
MAX_MESSAGE_LENGTH = 2_000
MAX_DETAILS_ITEMS = 64
MAX_DETAIL_VALUE_LENGTH = 2_000
MAX_REQUEST_ID_LENGTH = 128
MAX_PATH_LENGTH = 1_024

DEFAULT_INTERNAL_MESSAGE = "The server could not complete the requested operation."

DEFAULT_NOT_FOUND_MESSAGE = "The requested resource was not found."

DEFAULT_METHOD_NOT_ALLOWED_MESSAGE = "The HTTP method is not allowed for this resource."

DEFAULT_REQUEST_TOO_LARGE_MESSAGE = (
    "The uploaded request exceeds the configured size limit."
)

DEFAULT_INTERNAL_ERROR_MESSAGE = "An unexpected server error occurred."


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_text(
    value: Any,
    maximum: int,
    default: str = "",
) -> str:
    if value is None:
        return default

    if isinstance(value, bytes):
        value = value.decode(
            "utf-8",
            errors="replace",
        )

    text = str(value).strip()

    if not text:
        return default

    return text[:maximum]


def _safe_bool(
    value: Any,
    default: bool = False,
) -> bool:
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return bool(value)

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {
            "true",
            "1",
            "yes",
            "on",
        }:
            return True

        if normalized in {
            "false",
            "0",
            "no",
            "off",
            "",
        }:
            return False

    return default


def _safe_details(
    value: Optional[Mapping[str, Any]],
) -> dict[str, Any]:
    if not value:
        return {}

    if not isinstance(value, Mapping):
        return {}

    result: dict[str, Any] = {}

    for index, (key, item) in enumerate(value.items()):
        if index >= MAX_DETAILS_ITEMS:
            break

        key_text = _safe_text(
            key,
            MAX_ERROR_CODE_LENGTH,
        )

        if not key_text:
            continue

        if (
            isinstance(
                item,
                (str, int, float, bool),
            )
            or item is None
        ):
            result[key_text] = (
                _safe_text(
                    item,
                    MAX_DETAIL_VALUE_LENGTH,
                )
                if isinstance(item, str)
                else item
            )
        elif isinstance(item, (list, tuple)):
            result[key_text] = [
                _safe_text(
                    child,
                    MAX_DETAIL_VALUE_LENGTH,
                )
                for child in list(item)[:32]
            ]
        else:
            result[key_text] = _safe_text(
                item,
                MAX_DETAIL_VALUE_LENGTH,
            )

    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _request_id() -> str:
    """
    Generate a non-sensitive correlation identifier.
    """

    return uuid.uuid4().hex


def _configured_bool(
    name: str,
    default: bool = False,
) -> bool:
    try:
        value = current_app.config.get(
            name,
            default,
        )
    except RuntimeError:
        return default

    return _safe_bool(
        value,
        default=default,
    )


def _configured_int(
    name: str,
    default: int,
) -> int:
    try:
        value = current_app.config.get(
            name,
            default,
        )
    except RuntimeError:
        return default

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _request_path() -> str:
    try:
        return _safe_text(
            request.path,
            MAX_PATH_LENGTH,
            "/",
        )
    except RuntimeError:
        return "/"


def _request_method() -> str:
    try:
        return _safe_text(
            request.method,
            16,
            "UNKNOWN",
        ).upper()
    except RuntimeError:
        return "UNKNOWN"


def _wants_json() -> bool:
    """
    Decide whether an error should use the JSON API envelope.
    """

    try:
        if request.path.startswith("/api/"):
            return True

        if request.is_json:
            return True

        accepted = request.accept_mimetypes

        if accepted:
            json_quality = accepted["application/json"]
            html_quality = accepted["text/html"]

            return json_quality > html_quality

    except Exception:
        pass

    return False


def _request_id_from_headers() -> Optional[str]:
    try:
        value = request.headers.get("X-Request-ID")
    except Exception:
        return None

    if not value:
        return None

    normalized = _safe_text(
        value,
        MAX_REQUEST_ID_LENGTH,
    )

    return normalized or None


def _debug_enabled() -> bool:
    return _configured_bool(
        "PHAROS_API_DEBUG_ERRORS",
        default=False,
    )


def _expose_internal_errors() -> bool:
    return _configured_bool(
        "PHAROS_API_EXPOSE_INTERNAL_ERRORS",
        default=False,
    )


def _should_log_traceback() -> bool:
    return _configured_bool(
        "PHAROS_API_LOG_TRACEBACKS",
        default=True,
    )


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------


@dataclass
class APIException(Exception):
    """
    Base application exception with an HTTP-safe public representation.
    """

    message: str
    status_code: int = 400
    code: str = "api_error"
    details: Optional[Mapping[str, Any]] = None
    public_message: Optional[str] = None
    log_level: int = logging.WARNING
    expose_details: bool = True

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)

        self.message = _safe_text(
            self.message,
            MAX_MESSAGE_LENGTH,
            DEFAULT_INTERNAL_MESSAGE,
        )

        self.code = _safe_text(
            self.code,
            MAX_ERROR_CODE_LENGTH,
            "api_error",
        ).lower()

        try:
            self.status_code = int(self.status_code)
        except (TypeError, ValueError):
            self.status_code = 400

        self.status_code = max(
            400,
            min(
                self.status_code,
                599,
            ),
        )

        if self.public_message is not None:
            self.public_message = _safe_text(
                self.public_message,
                MAX_MESSAGE_LENGTH,
            )

        self.details = _safe_details(self.details)

    def client_message(self) -> str:
        if self.public_message:
            return self.public_message

        if self.expose_details:
            return self.message

        return DEFAULT_INTERNAL_MESSAGE

    def to_dict(
        self,
        *,
        request_id: Optional[str] = None,
    ) -> dict[str, Any]:
        payload = {
            "error": self.code,
            "message": self.client_message(),
            "status_code": self.status_code,
            "request_id": request_id,
            "timestamp": _utc_now(),
        }

        if self.details and (self.expose_details or _expose_internal_errors()):
            payload["details"] = dict(self.details)

        return payload


class ValidationAPIError(APIException):
    """Invalid API input."""

    def __init__(
        self,
        message: str,
        *,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=400,
            code="validation_error",
            details=details,
            log_level=logging.INFO,
        )


class AuthenticationAPIError(APIException):
    """Authentication failure."""

    def __init__(
        self,
        message: str = "Authentication is required.",
        *,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=401,
            code="authentication_required",
            details=details,
            public_message="Authentication is required.",
            log_level=logging.INFO,
        )


class AuthorizationAPIError(APIException):
    """Authorization failure."""

    def __init__(
        self,
        message: str = "You are not authorized to perform this operation.",
        *,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=403,
            code="forbidden",
            details=details,
            public_message=("You are not authorized to perform this operation."),
            log_level=logging.INFO,
        )


class ResourceNotFoundAPIError(APIException):
    """Requested API resource does not exist."""

    def __init__(
        self,
        message: str = DEFAULT_NOT_FOUND_MESSAGE,
        *,
        resource: Optional[str] = None,
    ) -> None:
        details = {}

        if resource:
            details["resource"] = _safe_text(
                resource,
                256,
            )

        super().__init__(
            message=message,
            status_code=404,
            code="not_found",
            details=details,
            public_message=DEFAULT_NOT_FOUND_MESSAGE,
            log_level=logging.INFO,
        )


class MethodNotAllowedAPIError(APIException):
    """HTTP method is not supported."""

    def __init__(
        self,
        message: str = DEFAULT_METHOD_NOT_ALLOWED_MESSAGE,
        *,
        allowed_methods: Optional[list[str]] = None,
    ) -> None:
        details = {}

        if allowed_methods:
            details["allowed_methods"] = [
                _safe_text(
                    method,
                    16,
                ).upper()
                for method in allowed_methods[:32]
            ]

        super().__init__(
            message=message,
            status_code=405,
            code="method_not_allowed",
            details=details,
            public_message=DEFAULT_METHOD_NOT_ALLOWED_MESSAGE,
            log_level=logging.INFO,
        )


class RequestTooLargeAPIError(APIException):
    """Request exceeded the configured body/upload limit."""

    def __init__(
        self,
        message: str = DEFAULT_REQUEST_TOO_LARGE_MESSAGE,
        *,
        maximum_bytes: Optional[int] = None,
    ) -> None:
        details = {}

        if maximum_bytes is not None:
            try:
                details["maximum_bytes"] = max(
                    0,
                    int(maximum_bytes),
                )
            except (TypeError, ValueError):
                pass

        super().__init__(
            message=message,
            status_code=413,
            code="request_too_large",
            details=details,
            public_message=DEFAULT_REQUEST_TOO_LARGE_MESSAGE,
            log_level=logging.INFO,
        )


class UnsupportedMediaTypeAPIError(APIException):
    """Uploaded document type is not supported."""

    def __init__(
        self,
        message: str = "The submitted file type is not supported.",
        *,
        content_type: Optional[str] = None,
    ) -> None:
        details = {}

        if content_type:
            details["content_type"] = _safe_text(
                content_type,
                160,
            )

        super().__init__(
            message=message,
            status_code=415,
            code="unsupported_media_type",
            details=details,
            public_message=("The submitted file type is not supported."),
            log_level=logging.INFO,
        )


class ScanAPIError(APIException):
    """Static analysis failure."""

    def __init__(
        self,
        message: str = "The document scan could not be completed.",
        *,
        details: Optional[Mapping[str, Any]] = None,
        status_code: int = 422,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            code="scan_error",
            details=details,
            public_message=("The document scan could not be completed."),
            expose_details=False,
            log_level=logging.ERROR,
        )


class ScanLimitAPIError(APIException):
    """Scanner resource limit was exceeded."""

    def __init__(
        self,
        message: str = ("The document exceeds a scanner processing limit."),
        *,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=413,
            code="scan_limit_exceeded",
            details=details,
            public_message=("The document exceeds a scanner processing limit."),
            expose_details=False,
            log_level=logging.WARNING,
        )


class ReportAPIError(APIException):
    """Report generation failure."""

    def __init__(
        self,
        message: str = "The report could not be generated.",
        *,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=500,
            code="report_error",
            details=details,
            public_message=("The report could not be generated."),
            expose_details=False,
            log_level=logging.ERROR,
        )


class SanitizationAPIError(APIException):
    """CDR sanitization/output failure."""

    def __init__(
        self,
        message: str = ("A sanitized document is not available."),
        *,
        details: Optional[Mapping[str, Any]] = None,
        status_code: int = 422,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            code="sanitization_error",
            details=details,
            public_message=("A sanitized document is not available."),
            expose_details=False,
            log_level=logging.WARNING,
        )


class StorageAPIError(APIException):
    """Scan/report persistence failure."""

    def __init__(
        self,
        message: str = "The requested resource could not be stored.",
        *,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=500,
            code="storage_error",
            details=details,
            public_message=("The requested resource could not be stored."),
            expose_details=False,
            log_level=logging.ERROR,
        )


class ConfigurationAPIError(APIException):
    """Server-side API configuration failure."""

    def __init__(
        self,
        message: str = ("The API service is not correctly configured."),
        *,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=500,
            code="configuration_error",
            details=details,
            public_message=("The API service is not correctly configured."),
            expose_details=False,
            log_level=logging.ERROR,
        )


# ---------------------------------------------------------------------------
# Exception normalization
# ---------------------------------------------------------------------------


def normalize_exception(
    error: BaseException,
) -> APIException:
    """
    Convert arbitrary application exceptions into APIException.

    Known API exceptions are preserved. Werkzeug HTTP exceptions become
    appropriate API exceptions. Internal exceptions are intentionally hidden
    from clients unless internal exposure is explicitly enabled.
    """

    if isinstance(error, APIException):
        return error

    if isinstance(error, HTTPException):
        status_code = int(error.code or 500)

        if status_code == 400:
            return ValidationAPIError(error.description or "Bad request.")

        if status_code == 401:
            return AuthenticationAPIError()

        if status_code == 403:
            return AuthorizationAPIError()

        if status_code == 404:
            return ResourceNotFoundAPIError()

        if status_code == 405:
            allowed = getattr(
                error,
                "valid_methods",
                None,
            )

            return MethodNotAllowedAPIError(
                allowed_methods=(sorted(allowed) if allowed else None)
            )

        if status_code == 413:
            return RequestTooLargeAPIError()

        if status_code == 415:
            return UnsupportedMediaTypeAPIError()

        return APIException(
            message=_safe_text(
                error.description,
                MAX_MESSAGE_LENGTH,
                DEFAULT_INTERNAL_MESSAGE,
            ),
            status_code=status_code,
            code=(f"http_{status_code}"),
            public_message=(
                _safe_text(
                    error.description,
                    MAX_MESSAGE_LENGTH,
                    DEFAULT_INTERNAL_MESSAGE,
                )
            ),
            expose_details=False,
            log_level=logging.WARNING,
        )

    # Map common built-in failures to safe HTTP errors.
    if isinstance(
        error,
        (ValueError, TypeError),
    ):
        return ValidationAPIError("The supplied request could not be processed.")

    if isinstance(
        error,
        PermissionError,
    ):
        return AuthorizationAPIError()

    if isinstance(
        error,
        (FileNotFoundError,),
    ):
        return ResourceNotFoundAPIError()

    return APIException(
        message=_safe_text(
            error,
            MAX_MESSAGE_LENGTH,
            DEFAULT_INTERNAL_MESSAGE,
        ),
        status_code=500,
        code="internal_error",
        public_message=(
            _safe_text(
                error,
                MAX_MESSAGE_LENGTH,
                DEFAULT_INTERNAL_ERROR_MESSAGE,
            )
            if _expose_internal_errors()
            else DEFAULT_INTERNAL_ERROR_MESSAGE
        ),
        expose_details=False,
        log_level=logging.ERROR,
    )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def log_exception(
    error: BaseException,
    *,
    request_id: Optional[str] = None,
) -> None:
    """
    Log an exception without logging request/document contents.
    """

    normalized = normalize_exception(error)

    extra = {
        "request_id": request_id,
        "status_code": normalized.status_code,
        "error_code": normalized.code,
        "path": _request_path(),
        "method": _request_method(),
    }

    if _should_log_traceback() and normalized.status_code >= 500:
        LOGGER.log(
            normalized.log_level,
            "API request failed: %s",
            normalized.message,
            exc_info=True,
            extra=extra,
        )
    else:
        LOGGER.log(
            normalized.log_level,
            "API request failed: %s",
            normalized.code,
            extra=extra,
        )


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------


def error_payload(
    error: BaseException,
    *,
    request_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Build a stable JSON-compatible API error payload.
    """

    normalized = normalize_exception(error)

    effective_request_id = request_id or _request_id_from_headers() or _request_id()

    return normalized.to_dict(
        request_id=effective_request_id,
    )


def json_error_response(
    error: BaseException,
    *,
    request_id: Optional[str] = None,
) -> Response:
    """
    Build a Flask JSON error response.
    """

    normalized = normalize_exception(error)

    payload = error_payload(
        normalized,
        request_id=request_id,
    )

    response = jsonify(payload)

    response.status_code = normalized.status_code

    _apply_error_headers(
        response,
        request_id=payload.get("request_id"),
    )

    return response


def _render_error_html(
    error: BaseException,
    *,
    request_id: Optional[str],
) -> Response:
    """
    Render a dependency-free safe HTML error page.

    If a dedicated error.html template is present, it is used. Otherwise a
    minimal built-in page is returned.
    """

    normalized = normalize_exception(error)

    payload = error_payload(
        normalized,
        request_id=request_id,
    )

    message = html.escape(str(payload.get("message", "Error")))

    code = html.escape(str(payload.get("error", "api_error")))

    request_identifier = html.escape(
        str(
            payload.get(
                "request_id",
                "",
            )
        )
    )

    status_code = int(
        payload.get(
            "status_code",
            normalized.status_code,
        )
    )

    try:
        templates = current_app.jinja_env.list_templates()

        if "error.html" in templates:
            response = render_template(
                "error.html",
                error=payload,
                status_code=status_code,
                message=payload.get("message"),
                request_id=payload.get("request_id"),
            )

            result = Response(
                response,
                status=status_code,
                mimetype="text/html",
            )

            _apply_error_headers(
                result,
                request_id=payload.get("request_id"),
            )

            return result

    except Exception:
        LOGGER.debug(
            "Unable to render optional error.html template.",
            exc_info=True,
        )

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Pharos CDR — Error {status_code}</title>
<style>
:root {{
    color-scheme: light dark;
    font-family: system-ui,-apple-system,BlinkMacSystemFont,
                 "Segoe UI",sans-serif;
}}
body {{
    margin: 0;
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 2rem;
    box-sizing: border-box;
    background: #f5f7fa;
    color: #172033;
}}
.card {{
    width: min(680px,100%);
    padding: 2rem;
    border: 1px solid #d9dee8;
    border-radius: 14px;
    background: #fff;
    box-shadow: 0 12px 36px rgba(0,0,0,.08);
}}
.status {{
    margin: 0 0 .5rem;
    font-size: 2.5rem;
    line-height: 1;
}}
.code {{
    margin: 0 0 1rem;
    font-family: ui-monospace,SFMono-Regular,Menlo,monospace;
    font-size: .9rem;
    color: #5c6678;
}}
.message {{
    margin: 0;
    font-size: 1.05rem;
    line-height: 1.6;
}}
.request-id {{
    margin-top: 1.5rem;
    padding-top: 1rem;
    border-top: 1px solid #e1e5ec;
    font-family: ui-monospace,SFMono-Regular,Menlo,monospace;
    font-size: .8rem;
    color: #687286;
    overflow-wrap: anywhere;
}}
@media (prefers-color-scheme: dark) {{
    body {{
        background: #10141c;
        color: #edf1f7;
    }}
    .card {{
        background: #181e28;
        border-color: #303847;
        box-shadow: none;
    }}
    .code,
    .request-id {{
        color: #aeb8c9;
    }}
    .request-id {{
        border-color: #303847;
    }}
}}
</style>
</head>
<body>
<main class="card" role="alert">
    <h1 class="status">{status_code}</h1>
    <p class="code">{code}</p>
    <p class="message">{message}</p>
    <p class="request-id">Request ID: {request_identifier}</p>
</main>
</body>
</html>"""

    response = Response(
        document,
        status=status_code,
        mimetype="text/html",
    )

    _apply_error_headers(
        response,
        request_id=payload.get("request_id"),
    )

    return response


def error_response(
    error: BaseException,
    *,
    request_id: Optional[str] = None,
) -> Response:
    """
    Return JSON or HTML based on the current request.
    """

    if _wants_json():
        return json_error_response(
            error,
            request_id=request_id,
        )

    return _render_error_html(
        error,
        request_id=request_id,
    )


def _apply_error_headers(
    response: Response | WerkzeugResponse,
    *,
    request_id: Optional[str],
) -> None:
    """
    Apply security/cache headers to error responses.
    """

    response.headers["Cache-Control"] = "no-store, max-age=0"

    response.headers["Pragma"] = "no-cache"

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "DENY"

    response.headers["Referrer-Policy"] = "no-referrer"

    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "style-src 'unsafe-inline'; "
        "img-src 'none'; "
        "script-src 'none'; "
        "connect-src 'none'; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'"
    )

    if request_id:
        response.headers["X-Request-ID"] = _safe_text(
            request_id,
            MAX_REQUEST_ID_LENGTH,
        )


# ---------------------------------------------------------------------------
# Flask error handlers
# ---------------------------------------------------------------------------


def handle_api_exception(
    error: APIException,
) -> Response:
    request_id = _request_id_from_headers() or _request_id()

    log_exception(
        error,
        request_id=request_id,
    )

    return error_response(
        error,
        request_id=request_id,
    )


def handle_http_exception(
    error: HTTPException,
) -> Response:
    normalized = normalize_exception(error)

    request_id = _request_id_from_headers() or _request_id()

    log_exception(
        normalized,
        request_id=request_id,
    )

    return error_response(
        normalized,
        request_id=request_id,
    )


def handle_generic_exception(
    error: Exception,
) -> Response:
    normalized = normalize_exception(error)

    request_id = _request_id_from_headers() or _request_id()

    log_exception(
        error,
        request_id=request_id,
    )

    return error_response(
        normalized,
        request_id=request_id,
    )


def handle_404(
    error: Exception,
) -> Response:
    normalized = ResourceNotFoundAPIError()

    request_id = _request_id_from_headers() or _request_id()

    log_exception(
        normalized,
        request_id=request_id,
    )

    return error_response(
        normalized,
        request_id=request_id,
    )


def handle_405(
    error: HTTPException,
) -> Response:
    allowed = getattr(
        error,
        "valid_methods",
        None,
    )

    normalized = MethodNotAllowedAPIError(
        allowed_methods=(sorted(allowed) if allowed else None)
    )

    request_id = _request_id_from_headers() or _request_id()

    log_exception(
        normalized,
        request_id=request_id,
    )

    response = error_response(
        normalized,
        request_id=request_id,
    )

    if allowed:
        response.headers["Allow"] = ", ".join(sorted(allowed))

    return response


def handle_413(
    error: Exception,
) -> Response:
    maximum = _configured_int(
        "MAX_CONTENT_LENGTH",
        0,
    )

    normalized = RequestTooLargeAPIError(
        maximum_bytes=(maximum if maximum > 0 else None)
    )

    request_id = _request_id_from_headers() or _request_id()

    log_exception(
        normalized,
        request_id=request_id,
    )

    return error_response(
        normalized,
        request_id=request_id,
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_error_handlers(
    app: Flask,
) -> Flask:
    """
    Register all Pharos CDR Flask error handlers.

    Registration is idempotent from the application's perspective: calling
    this function again simply re-registers the same handlers.
    """

    if not isinstance(app, Flask):
        raise TypeError("register_error_handlers() requires a Flask application.")

    app.register_error_handler(
        APIException,
        handle_api_exception,
    )

    app.register_error_handler(
        HTTPException,
        handle_http_exception,
    )

    app.register_error_handler(
        400,
        lambda error: handle_http_exception(
            error
            if isinstance(
                error,
                HTTPException,
            )
            else HTTPException(description="Bad request.")
        ),
    )

    app.register_error_handler(
        404,
        handle_404,
    )

    app.register_error_handler(
        405,
        handle_405,
    )

    app.register_error_handler(
        413,
        handle_413,
    )

    app.register_error_handler(
        415,
        handle_http_exception,
    )

    app.register_error_handler(
        Exception,
        handle_generic_exception,
    )

    return app


def install_error_handlers(
    app: Flask,
) -> Flask:
    """
    Alias for :func:`register_error_handlers`.
    """

    return register_error_handlers(app)


# ---------------------------------------------------------------------------
# Flask after-request helper
# ---------------------------------------------------------------------------


def apply_security_headers(
    response: Response | WerkzeugResponse,
) -> Response | WerkzeugResponse:
    """
    Apply common security/cache headers to an API response.

    This helper can be registered with Flask via ``after_request``.
    """

    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff",
    )

    response.headers.setdefault(
        "X-Frame-Options",
        "DENY",
    )

    response.headers.setdefault(
        "Referrer-Policy",
        "no-referrer",
    )

    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), " "geolocation=(), payment=()",
    )

    return response


def register_security_headers(
    app: Flask,
) -> Flask:
    """
    Register the common security-header callback.
    """

    if not isinstance(app, Flask):
        raise TypeError("register_security_headers() requires a Flask application.")

    app.after_request(apply_security_headers)

    return app


# ---------------------------------------------------------------------------
# Error metadata
# ---------------------------------------------------------------------------


def error_catalog() -> dict[str, Any]:
    """
    Return machine-readable information about supported API errors.
    """

    return {
        "module": MODULE_NAME,
        "version": ERRORS_VERSION,
        "errors": {
            "validation_error": 400,
            "authentication_required": 401,
            "forbidden": 403,
            "not_found": 404,
            "method_not_allowed": 405,
            "request_too_large": 413,
            "unsupported_media_type": 415,
            "scan_error": 422,
            "scan_limit_exceeded": 413,
            "sanitization_error": 422,
            "report_error": 500,
            "storage_error": 500,
            "configuration_error": 500,
            "internal_error": 500,
        },
        "security": {
            "tracebacks_exposed": _expose_internal_errors(),
            "internal_messages_exposed": _expose_internal_errors(),
            "document_content_logged": False,
        },
    }


def health_check() -> dict[str, Any]:
    """
    Return basic health information for the error subsystem.
    """

    return {
        "module": MODULE_NAME,
        "version": ERRORS_VERSION,
        "status": "ok",
        "handlers": [
            "APIException",
            "HTTPException",
            "404",
            "405",
            "413",
            "415",
            "Exception",
        ],
        "timestamp": _utc_now(),
    }


# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------


register = register_error_handlers
install = register_error_handlers
catalog = error_catalog
health = health_check
normalize = normalize_exception
handle = handle_generic_exception


# ---------------------------------------------------------------------------
# PUBLIC APIs
# ---------------------------------------------------------------------------

__all__ = [
    "MODULE_NAME",
    "ERRORS_VERSION",
    "APIException",
    "ValidationAPIError",
    "AuthenticationAPIError",
    "AuthorizationAPIError",
    "ResourceNotFoundAPIError",
    "MethodNotAllowedAPIError",
    "RequestTooLargeAPIError",
    "UnsupportedMediaTypeAPIError",
    "ScanAPIError",
    "ScanLimitAPIError",
    "ReportAPIError",
    "SanitizationAPIError",
    "StorageAPIError",
    "ConfigurationAPIError",
    "normalize_exception",
    "log_exception",
    "error_payload",
    "json_error_response",
    "error_response",
    "handle_api_exception",
    "handle_http_exception",
    "handle_generic_exception",
    "handle_404",
    "handle_405",
    "handle_413",
    "register_error_handlers",
    "install_error_handlers",
    "apply_security_headers",
    "register_security_headers",
    "error_catalog",
    "health_check",
    "register",
    "install",
    "catalog",
    "health",
    "normalize",
    "handle",
]
