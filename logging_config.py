"""Unified logging configuration for Sublist3r4m.

Provides a single entry point for creating consistently formatted loggers
across every module in the project.  Replaces the per-module logger classes
(``EnhancedLogger``, ``AdvancedOwnerLogger``, ``ColoredLogger``, and the
bare ANSI-color constants in *sublist3r.py*) with one shared implementation.

Usage::

    from logging_config import get_logger

    logger = get_logger("MyModule")
    logger.info("Ready to enumerate subdomains")

For more control (custom log file, different level, color toggle)::

    from logging_config import setup_logger

    logger = setup_logger(
        name="SubBrute",
        log_file="subbrute.log",
        level=logging.DEBUG,
        colored=True,
    )
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

# ---------------------------------------------------------------------------
# ANSI color codes -- no external dependency required
# ---------------------------------------------------------------------------

_COLORS: dict[str, str] = {
    "DEBUG": "\033[36m",  # Cyan
    "INFO": "\033[32m",  # Green
    "WARNING": "\033[33m",  # Yellow
    "ERROR": "\033[31m",  # Red
    "CRITICAL": "\033[35m",  # Magenta
    "RESET": "\033[0m",
}

# ---------------------------------------------------------------------------
# Format strings
# ---------------------------------------------------------------------------

_CONSOLE_FMT = "[%(levelname)s] %(name)s: %(message)s"
_FILE_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_FILE_DATEFMT = "%Y-%m-%d %H:%M:%S"


# ---------------------------------------------------------------------------
# Colored formatter
# ---------------------------------------------------------------------------


class _ColoredFormatter(logging.Formatter):
    """A ``logging.Formatter`` that wraps the level name in ANSI color codes.

    Falls back to plain text when *colored* is ``False`` or when the stream
    is not a TTY (e.g. piped to a file).
    """

    def __init__(
        self,
        fmt: str = _CONSOLE_FMT,
        datefmt: str | None = None,
        colored: bool = True,
    ) -> None:
        super().__init__(fmt, datefmt=datefmt)
        self._colored = colored

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        if self._colored:
            color = _COLORS.get(record.levelname, "")
            reset = _COLORS["RESET"]
            record = logging.makeLogRecord(record.__dict__)
            record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def setup_logger(
    name: str,
    log_file: str | None = None,
    level: int = logging.INFO,
    colored: bool = True,
) -> logging.Logger:
    """Create (or retrieve) a logger with consistent formatting.

    Parameters
    ----------
    name:
        Logger name -- typically the module or component name
        (e.g. ``"SubBrute"``, ``"JARVIS_Intelligence"``).
    log_file:
        Optional path to a log file.  When provided a
        ``RotatingFileHandler`` is attached (10 MB max, 5 backups).
    level:
        Logging level for the logger itself.  Both the console and
        file handlers inherit this level unless the file handler is
        explicitly set to ``DEBUG``.
    colored:
        If ``True`` **and** *stderr* is a TTY, the console handler
        uses ANSI colors.  Set to ``False`` to force plain output.

    Returns
    -------
    logging.Logger
        A fully configured logger ready for use.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid stacking duplicate handlers when ``setup_logger`` is called
    # more than once for the same *name* (e.g. during tests or re-imports).
    if logger.handlers:
        return logger

    # -- Console handler ---------------------------------------------------
    stream = sys.stderr
    use_color = colored and hasattr(stream, "isatty") and stream.isatty()
    console_handler = logging.StreamHandler(stream)
    console_handler.setLevel(level)
    console_handler.setFormatter(_ColoredFormatter(fmt=_CONSOLE_FMT, colored=use_color))
    logger.addHandler(console_handler)

    # -- File handler (optional) -------------------------------------------
    if log_file is not None:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(fmt=_FILE_FMT, datefmt=_FILE_DATEFMT),
        )
        logger.addHandler(file_handler)

    # Prevent messages from propagating to the root logger when a parent
    # logger has already been configured (avoids duplicate output).
    logger.propagate = False

    return logger


def get_logger(name: str) -> logging.Logger:
    """Shortcut: return a logger configured with sensible defaults.

    Equivalent to ``setup_logger(name)`` -- INFO level, colored console
    output, no file handler.  Call :func:`setup_logger` directly when you
    need finer control.
    """
    return setup_logger(name)
