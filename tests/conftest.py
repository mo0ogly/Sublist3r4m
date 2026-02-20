"""Shared fixtures for sublist3r tests."""

import logging
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def tmp_output_dir(tmp_path):
    """Provide a temporary directory for file-output tests."""
    return tmp_path


@pytest.fixture
def sample_domains():
    """A reusable list of test subdomains."""
    return [
        "mail.example.com",
        "www.example.com",
        "api.example.com",
        "dev.example.com",
        "b.example.com",
        "a.example.com",
    ]


@pytest.fixture(autouse=True)
def mock_dns():
    """Patch dns.resolver.resolve (and the legacy .query) globally so no test
    ever makes a real DNS lookup.  Yields the mock so individual tests can
    customise return values when needed."""
    mock_answer = MagicMock()
    mock_answer.to_text.return_value = "93.184.216.34"
    with patch("dns.resolver.resolve", return_value=[mock_answer]) as m_resolve, \
         patch("dns.resolver.Resolver") as m_resolver_cls:
        # Make Resolver().query also safe
        instance = m_resolver_cls.return_value
        instance.query.return_value = [mock_answer]
        instance.resolve.return_value = [mock_answer]
        yield m_resolve


@pytest.fixture(autouse=True)
def isolate_logging():
    """Ensure every test uses a NullHandler so nothing is written to disk."""
    root = logging.getLogger()
    original_handlers = root.handlers[:]
    root.handlers = [logging.NullHandler()]
    yield
    root.handlers = original_handlers


@pytest.fixture(autouse=True)
def prevent_network(monkeypatch):
    """As a safety net, make socket.create_connection raise immediately so that
    no test can accidentally open a real network connection."""
    import socket as _socket

    _original = _socket.create_connection

    def _blocked(*args, **kwargs):
        raise OSError("Network access is blocked in tests")

    monkeypatch.setattr(_socket, "create_connection", _blocked)
    yield
