"""
Flask application factory for the Pharos CDR web/API layer.

This module is intentionally responsible for HTTP application setup only.
Document analysis, ML inference, CDR decisions, sanitization, and report
generation remain in the existing application layers.

Application architecture:

    HTTP client / Browser
            |
            v
        Flask app
            |
            +--> src.api.routes
            |       |
            |       v
            |   src.api.services
            |       |
            |       v
            |   pipeline.scanner
            |       |
            |       +--> extraction
            |       +--> ML
            |       +--> CDR
            |       +--> reporting
            |
            v
        HTTP response

Security properties:
    - Debug mode is disabled by default.
    - Maximum request/upload size is enforced.
    - Uploaded content is not executed.
    - Flask does not directly invoke subprocesses or document applications.
    - Server-side paths are not exposed through request parameters.
    - Error responses do not expose tracebacks by default.
    - Security-related HTTP headers are applied to responses.
    - The application can be configured through environment variables.
"""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path
from typing import Any, Mapping

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

MODULE_NAME = "pharos_cdr.api.app"
APP_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Application defaults
# ---------------------------------------------------------------------------

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000

DEFAULT_MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MiB
DEFAULT_MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MiB

DEFAULT_OUTPUT_DIRECTORY = Path("outputs")
DEFAULT_SANITIZED_DIRECTORY = DEFAULT_OUTPUT_DIRECTORY / "sanitized"
DEFAULT_REPORT_DIRECTORY = DEFAULT_OUTPUT_DIRECTORY / "reports"

DEFAULT_ALLOWED_HOSTS = {
    "127.0.0.1",
    "localhost",
    "::1",
}

DEFAULT_JSON_SORT_KEYS = True

# Flask/Werkzeug will reject an incoming request above this size before the
# scanner receives it. The scanner itself has independent limits.
MAX_CONTENT_LENGTH_ENV = "PHAROS_MAX_CONTENT_LENGTH"
MAX_UPLOAD_BYTES_ENV = "PHAROS_MAX_UPLOAD_BYTES"

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


def _safe_bool(value: Any, default: bool = False) -> bool:
    """
    Parse a boolean configuration value safely.

    Accepted true values:
        1, true, yes, y, on

    Accepted false values:
        0, false, no, n, off

    Unknown values return the supplied default.
    """
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    text = str(value).strip().lower()

    if text in {"1", "true", "yes", "y", "on"}:
        return True

    if text in {"0", "false", "no", "n", "off"}:
        return False

    return default


def _safe_int(
    value: Any,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """
    Parse an integer configuration value with optional bounds.
    """
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default

    if minimum is not None and parsed < minimum:
        return default

    if maximum is not None and parsed > maximum:
        return default

    return parsed


def _safe_path(value: Any, default: Path) -> Path:
    """
    Normalize a local configuration path.

    This function does not resolve or access the filesystem. It only converts
    the configured value into a Path object.
    """
    if value is None:
        return default

    text = str(value).strip()

    if not text:
        return default

    return Path(text)


def _environment_config() -> dict[str, Any]:
    """
    Build Flask configuration from environment variables.

    Environment variables are intentionally optional. The application can
    therefore run with safe local-development defaults.
    """
    max_content_length = _safe_int(
        os.getenv(MAX_CONTENT_LENGTH_ENV),
        DEFAULT_MAX_CONTENT_LENGTH,
        minimum=1,
        maximum=1024 * 1024 * 1024,
    )

    max_upload_bytes = _safe_int(
        os.getenv(MAX_UPLOAD_BYTES_ENV),
        DEFAULT_MAX_UPLOAD_BYTES,
        minimum=1,
        maximum=1024 * 1024 * 1024,
    )

    output_directory = _safe_path(
        os.getenv("PHAROS_OUTPUT_DIRECTORY"),
        DEFAULT_OUTPUT_DIRECTORY,
    )

    sanitized_directory = _safe_path(
        os.getenv("PHAROS_SANITIZED_DIRECTORY"),
        output_directory / "sanitized",
    )

    report_directory = _safe_path(
        os.getenv("PHAROS_REPORT_DIRECTORY"),
        output_directory / "reports",
    )

    return {
        "PHAROS_ENV": os.getenv("PHAROS_ENV", "production").strip().lower(),
        "PHAROS_DEBUG": _safe_bool(
            os.getenv("PHAROS_DEBUG"),
            default=False,
        ),
        "PHAROS_TESTING": _safe_bool(
            os.getenv("PHAROS_TESTING"),
            default=False,
        ),
        "PHAROS_MAX_CONTENT_LENGTH": max_content_length,
        "PHAROS_MAX_UPLOAD_BYTES": min(
            max_content_length,
            max_upload_bytes,
        ),
        "PHAROS_OUTPUT_DIRECTORY": output_directory,
        "PHAROS_SANITIZED_DIRECTORY": sanitized_directory,
        "PHAROS_REPORT_DIRECTORY": report_directory,
        "PHAROS_API_PREFIX": (os.getenv("PHAROS_API_PREFIX", "/api").strip() or "/api"),
        "PHAROS_SESSION_COOKIE_SECURE": _safe_bool(
            os.getenv("PHAROS_SESSION_COOKIE_SECURE"),
            default=False,
        ),
        "PHAROS_SESSION_COOKIE_HTTPONLY": True,
        "PHAROS_SESSION_COOKIE_SAMESITE": "Lax",
        "PHAROS_MAX_JSON_BYTES": _safe_int(
            os.getenv("PHAROS_MAX_JSON_BYTES"),
            10 * 1024 * 1024,
            minimum=1024,
            maximum=100 * 1024 * 1024,
        ),
    }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def configure_logging(app: Flask) -> None:
    """
    Configure application logging.

    The function avoids installing duplicate handlers when create_app() is
    called multiple times during tests.
    """
    level_name = os.getenv("PHAROS_LOG_LEVEL", "INFO").upper()

    level = getattr(logging, level_name, logging.INFO)

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    logger = app.logger
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    else:
        for handler in logger.handlers:
            handler.setLevel(level)

    logging.getLogger("werkzeug").setLevel(level)


# ---------------------------------------------------------------------------
# Flask configuration
# ---------------------------------------------------------------------------


def configure_application(app: Flask) -> None:
    """
    Apply secure application defaults.
    """
    app.config.from_mapping(
        MAX_CONTENT_LENGTH=DEFAULT_MAX_CONTENT_LENGTH,
        JSON_SORT_KEYS=DEFAULT_JSON_SORT_KEYS,
        JSONIFY_PRETTYPRINT_REGULAR=False,
        SEND_FILE_MAX_AGE_DEFAULT=0,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_SAMESITE="Lax",
        PROPAGATE_EXCEPTIONS=False,
        TRAP_HTTP_EXCEPTIONS=False,
        PHAROS_ENV="production",
        PHAROS_DEBUG=False,
        PHAROS_TESTING=False,
        PHAROS_MAX_UPLOAD_BYTES=DEFAULT_MAX_UPLOAD_BYTES,
        PHAROS_OUTPUT_DIRECTORY=DEFAULT_OUTPUT_DIRECTORY,
        PHAROS_SANITIZED_DIRECTORY=DEFAULT_SANITIZED_DIRECTORY,
        PHAROS_REPORT_DIRECTORY=DEFAULT_REPORT_DIRECTORY,
        PHAROS_API_PREFIX="/api",
        PHAROS_MAX_JSON_BYTES=10 * 1024 * 1024,
        PHAROS_APP_VERSION=APP_VERSION,
        PHAROS_MODULE_NAME=MODULE_NAME,
    )

    environment_config = _environment_config()
    app.config.update(environment_config)

    app.config["MAX_CONTENT_LENGTH"] = min(
        int(app.config["PHAROS_MAX_CONTENT_LENGTH"]),
        int(app.config["PHAROS_MAX_UPLOAD_BYTES"]),
    )

    # Flask session settings.
    app.config["SESSION_COOKIE_SECURE"] = bool(
        app.config["PHAROS_SESSION_COOKIE_SECURE"]
    )
    app.config["SESSION_COOKIE_HTTPONLY"] = bool(
        app.config["PHAROS_SESSION_COOKIE_HTTPONLY"]
    )
    app.config["SESSION_COOKIE_SAMESITE"] = app.config["PHAROS_SESSION_COOKIE_SAMESITE"]


def validate_application_config(app: Flask) -> None:
    """
    Validate configuration after loading environment settings.

    Raises:
        ValueError: if an unsafe or inconsistent configuration is detected.
    """
    max_content_length = int(app.config["MAX_CONTENT_LENGTH"])
    max_upload_bytes = int(app.config["PHAROS_MAX_UPLOAD_BYTES"])

    if max_content_length <= 0:
        raise ValueError("MAX_CONTENT_LENGTH must be greater than zero.")

    if max_upload_bytes <= 0:
        raise ValueError("PHAROS_MAX_UPLOAD_BYTES must be greater than zero.")

    if max_upload_bytes > max_content_length:
        raise ValueError("PHAROS_MAX_UPLOAD_BYTES cannot exceed MAX_CONTENT_LENGTH.")

    api_prefix = str(app.config["PHAROS_API_PREFIX"]).strip()

    if not api_prefix.startswith("/"):
        api_prefix = "/" + api_prefix

    api_prefix = api_prefix.rstrip("/")

    if not api_prefix:
        api_prefix = "/api"

    app.config["PHAROS_API_PREFIX"] = api_prefix


# ---------------------------------------------------------------------------
# Filesystem initialization
# ---------------------------------------------------------------------------


def initialize_output_directories(app: Flask) -> None:
    """
    Create controlled application output directories.

    These directories contain generated reports and sanitized output. The
    function never creates directories based on a user-supplied request path.
    """
    directories = (
        app.config["PHAROS_OUTPUT_DIRECTORY"],
        app.config["PHAROS_SANITIZED_DIRECTORY"],
        app.config["PHAROS_REPORT_DIRECTORY"],
    )

    for directory in directories:
        path = Path(directory)

        # Refuse obviously dangerous configurations.
        if path == Path("/"):
            raise ValueError("PHAROS output directory cannot be the filesystem root.")

        path.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Request/security helpers
# ---------------------------------------------------------------------------


def _request_id() -> str:
    """
    Generate an opaque request identifier.

    The identifier is not derived from the uploaded filename or filesystem
    path and therefore does not disclose document identity.
    """
    return secrets.token_urlsafe(16)


def _is_json_request() -> bool:
    """
    Return whether the request explicitly asks for a JSON response.
    """
    if request.is_json:
        return True

    best = request.accept_mimetypes.best

    if not best:
        return False

    return best == "application/json"


def _json_error(
    message: str,
    *,
    status_code: int,
    error: str | None = None,
    request_id: str | None = None,
) -> tuple[Any, int]:
    """
    Construct a consistent JSON API error response.
    """
    payload: dict[str, Any] = {
        "success": False,
        "error": error or "request_error",
        "message": message,
        "request_id": request_id or _request_id(),
    }

    return jsonify(payload), status_code


def install_request_context_hooks(app: Flask) -> None:
    """
    Install request/response hooks.

    The hooks add a request identifier and defensive security headers without
    modifying scanner behavior.
    """

    @app.before_request
    def before_request() -> None:
        request.pharos_request_id = _request_id()  # type: ignore[attr-defined]

        # Reject oversized JSON payloads independently of the global request
        # limit when Content-Length is available.
        content_length = request.content_length

        if (
            content_length is not None
            and request.is_json
            and content_length > int(app.config["PHAROS_MAX_JSON_BYTES"])
        ):
            raise RequestEntityTooLarge(
                description="JSON request body exceeds the configured limit."
            )

    @app.after_request
    def after_request(response):
        request_id = getattr(
            request,
            "pharos_request_id",
            None,
        )

        if request_id:
            response.headers["X-Request-ID"] = request_id

        # Defensive headers suitable for a document-analysis UI/API.
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
            "camera=(), microphone=(), geolocation=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            (
                "default-src 'self'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "frame-ancestors 'none'; "
                "object-src 'none'; "
                "img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; "
                "script-src 'self'"
            ),
        )

        # API responses should not be cached. Browser report pages can later
        # override this if desired.
        if request.path.startswith(str(app.config["PHAROS_API_PREFIX"])):
            response.headers.setdefault(
                "Cache-Control",
                "no-store",
            )

        return response


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def install_error_handlers(app: Flask) -> None:
    """
    Install consistent API and browser error handlers.
    """

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(error: RequestEntityTooLarge):
        message = "The uploaded request exceeds the configured maximum size."

        request_id = getattr(
            request,
            "pharos_request_id",
            None,
        )

        if _is_json_request() or request.path.startswith(
            str(app.config["PHAROS_API_PREFIX"])
        ):
            return _json_error(
                message,
                status_code=413,
                error="request_too_large",
                request_id=request_id,
            )

        return (
            jsonify(
                {
                    "success": False,
                    "error": "request_too_large",
                    "message": message,
                    "request_id": request_id,
                }
            ),
            413,
        )

    @app.errorhandler(HTTPException)
    def handle_http_exception(error: HTTPException):
        request_id = getattr(
            request,
            "pharos_request_id",
            None,
        )

        status_code = int(error.code or 500)

        message = error.description or error.name

        if _is_json_request() or request.path.startswith(
            str(app.config["PHAROS_API_PREFIX"])
        ):
            return _json_error(
                str(message),
                status_code=status_code,
                error=error.name.lower().replace(" ", "_"),
                request_id=request_id,
            )

        return (
            jsonify(
                {
                    "success": False,
                    "error": error.name.lower().replace(" ", "_"),
                    "message": str(message),
                    "request_id": request_id,
                }
            ),
            status_code,
        )

    @app.errorhandler(Exception)
    def handle_unexpected_exception(error: Exception):
        request_id = getattr(
            request,
            "pharos_request_id",
            None,
        )

        app.logger.exception(
            "Unhandled application exception request_id=%s",
            request_id,
        )

        # Never expose the exception text or traceback to remote clients.
        if _is_json_request() or request.path.startswith(
            str(app.config["PHAROS_API_PREFIX"])
        ):
            return _json_error(
                "An internal server error occurred.",
                status_code=500,
                error="internal_server_error",
                request_id=request_id,
            )

        return (
            jsonify(
                {
                    "success": False,
                    "error": "internal_server_error",
                    "message": "An internal server error occurred.",
                    "request_id": request_id,
                }
            ),
            500,
        )


# ---------------------------------------------------------------------------
# Blueprint registration
# ---------------------------------------------------------------------------


def register_routes(app: Flask) -> None:
    """
    Register the application's Flask blueprints.

    Routes are imported lazily so that the application factory remains easy
    to import in environments where only configuration or health checks are
    being exercised.

    The expected routes module API is:

        create_blueprint(api_prefix: str) -> flask.Blueprint

    The routes module should delegate document processing to
    ``src.api.services`` and ultimately ``pipeline.scanner``.
    """
    try:
        from .routes import create_blueprint
    except ImportError as exc:
        raise RuntimeError(
            "Unable to import src.api.routes. "
            "Ensure routes.py is present and Flask is installed."
        ) from exc

    blueprint = create_blueprint(api_prefix=str(app.config["PHAROS_API_PREFIX"]))

    app.register_blueprint(blueprint)


# ---------------------------------------------------------------------------
# Built-in health endpoint
# ---------------------------------------------------------------------------


def register_health_endpoint(app: Flask) -> None:
    """
    Register the health/readiness endpoint.

    This endpoint intentionally performs no document analysis and does not
    load arbitrary model artifacts. It verifies that the Flask application
    itself is operational.
    """

    api_prefix = str(app.config["PHAROS_API_PREFIX"])

    endpoint = f"{api_prefix}/health"

    @app.get(endpoint)
    def health():
        return jsonify(
            {
                "success": True,
                "status": "healthy",
                "service": "pharos-cdr",
                "version": APP_VERSION,
                "module": MODULE_NAME,
                "environment": app.config["PHAROS_ENV"],
            }
        )


# ---------------------------------------------------------------------------
# Browser root fallback
# ---------------------------------------------------------------------------


def register_root_endpoint(app: Flask) -> None:
    """
    Register the browser-facing root endpoint.

    The actual dashboard is expected to be implemented by routes.py. This
    endpoint provides a minimal fallback if the UI route is not registered.

    If routes.py defines ``/`` itself, Flask's more-specific route registration
    will need to be coordinated there rather than relying on this fallback.
    """

    @app.get("/")
    def index():
        return jsonify(
            {
                "service": "pharos-cdr",
                "version": APP_VERSION,
                "status": "running",
                "api": {
                    "health": f"{app.config['PHAROS_API_PREFIX']}/health",
                    "scan": f"{app.config['PHAROS_API_PREFIX']}/scan",
                },
                "message": (
                    "Pharos CDR API is running. "
                    "The browser dashboard can be served by the web routes."
                ),
            }
        )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(
    config: Mapping[str, Any] | None = None,
    *,
    register_application_routes: bool = True,
    initialize_directories: bool = True,
) -> Flask:
    """
    Create and configure the Pharos CDR Flask application.

    Args:
        config:
            Optional configuration mapping. Values supplied here override
            environment-derived defaults.

        register_application_routes:
            If True, import and register ``src.api.routes``.

            Tests can set this to False when they only need the application
            shell, health endpoint, and error handling.

        initialize_directories:
            If True, create the configured output/report directories.

    Returns:
        Configured Flask application.

    Example:

        app = create_app()

    The returned Flask object can be served through a WSGI server such as
    Gunicorn or Waitress in production.
    """
    app = Flask(
        __name__,
        static_folder=None,
        template_folder=None,
    )

    configure_application(app)

    if config:
        app.config.update(dict(config))

    validate_application_config(app)

    configure_logging(app)

    if initialize_directories:
        initialize_output_directories(app)

    install_request_context_hooks(app)
    install_error_handlers(app)

    register_health_endpoint(app)

    if register_application_routes:
        register_routes(app)

    return app


# ---------------------------------------------------------------------------
# Development entry point
# ---------------------------------------------------------------------------


def run_development_server(
    app: Flask | None = None,
    *,
    host: str | None = None,
    port: int | None = None,
    debug: bool | None = None,
) -> None:
    """
    Run Flask's development server.

    This function exists only for local development.

    Production deployments should use a dedicated WSGI server and should not
    enable Flask's debugger for untrusted document-analysis workloads.
    """
    application = app or create_app()

    configured_host = host or os.getenv(
        "PHAROS_HOST",
        DEFAULT_HOST,
    )

    configured_port = _safe_int(
        port if port is not None else os.getenv("PHAROS_PORT"),
        DEFAULT_PORT,
        minimum=1,
        maximum=65535,
    )

    if debug is None:
        configured_debug = bool(application.config.get("PHAROS_DEBUG", False))
    else:
        configured_debug = bool(debug)

    application.run(
        host=configured_host,
        port=configured_port,
        debug=configured_debug,
        use_reloader=configured_debug,
    )


# ---------------------------------------------------------------------------
# WSGI application
# ---------------------------------------------------------------------------

# This is the object WSGI servers can import:
#
#     from src.api.app import app
#
# For production, keep PHAROS_DEBUG=false.
app = create_app(
    register_application_routes=True,
    initialize_directories=True,
)


# ---------------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------------


__all__ = [
    "APP_VERSION",
    "MODULE_NAME",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "DEFAULT_MAX_CONTENT_LENGTH",
    "DEFAULT_MAX_UPLOAD_BYTES",
    "DEFAULT_OUTPUT_DIRECTORY",
    "DEFAULT_SANITIZED_DIRECTORY",
    "DEFAULT_REPORT_DIRECTORY",
    "configure_application",
    "configure_logging",
    "create_app",
    "initialize_output_directories",
    "install_error_handlers",
    "install_request_context_hooks",
    "register_health_endpoint",
    "register_routes",
    "run_development_server",
    "validate_application_config",
    "app",
]


if __name__ == "__main__":
    run_development_server(app)
