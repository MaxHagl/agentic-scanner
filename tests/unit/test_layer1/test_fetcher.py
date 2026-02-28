"""
tests/unit/test_layer1/test_fetcher.py
──────────────────────────────────────
Unit tests for scanner.layer1_static.fetcher.

All tests mock urllib.request.urlopen — no real network calls are made.
"""

from __future__ import annotations

import urllib.error
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.layer1_static.fetcher import _normalize_github_url, fetch_to_tempfile


# ── URL normalisation ─────────────────────────────────────────────────────────


def test_github_blob_url_normalized():
    url = "https://github.com/modelcontextprotocol/servers/blob/main/src/filesystem/README.md"
    expected = "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/filesystem/README.md"
    assert _normalize_github_url(url) == expected


def test_github_repo_root_url_normalized():
    url = "https://github.com/modelcontextprotocol/servers"
    expected = "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md"
    assert _normalize_github_url(url) == expected


def test_raw_url_unchanged():
    url = "https://raw.githubusercontent.com/owner/repo/main/README.md"
    assert _normalize_github_url(url) == url


# ── fetch_to_tempfile ─────────────────────────────────────────────────────────


def _make_mock_response(content: bytes) -> MagicMock:
    """Build a MagicMock that acts like the context-manager returned by urlopen."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = content
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def test_json_ext_preserved():
    url = "https://github.com/owner/repo/blob/main/server.json"
    content = b'{"name": "test"}'
    mock_resp = _make_mock_response(content)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with patch("urllib.request.Request"):
            path = fetch_to_tempfile(url)

    try:
        assert path.suffix == ".json"
        assert path.read_bytes() == content
    finally:
        path.unlink(missing_ok=True)


def test_md_ext_preserved():
    url = "https://github.com/owner/repo/blob/main/src/filesystem/README.md"
    content = b"# Filesystem Server\n\nA safe tool."
    mock_resp = _make_mock_response(content)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with patch("urllib.request.Request"):
            path = fetch_to_tempfile(url)

    try:
        assert path.suffix == ".md"
        assert path.read_bytes() == content
    finally:
        path.unlink(missing_ok=True)


def test_unknown_ext_defaults_to_md():
    url = "https://example.com/somefile"
    content = b"# Some content"
    mock_resp = _make_mock_response(content)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with patch("urllib.request.Request"):
            path = fetch_to_tempfile(url)

    try:
        assert path.suffix == ".md"
    finally:
        path.unlink(missing_ok=True)


def test_content_size_cap_raises():
    url = "https://example.com/huge.md"
    max_bytes = 10_485_760  # 10 MB
    # Return content that is one byte over the limit
    content = b"x" * (max_bytes + 1)
    mock_resp = _make_mock_response(content)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with patch("urllib.request.Request"):
            with pytest.raises(ValueError, match="exceeds"):
                fetch_to_tempfile(url, max_bytes=max_bytes)


def test_network_error_propagates():
    url = "https://example.com/unreachable.md"

    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("connection refused"),
    ):
        with patch("urllib.request.Request"):
            with pytest.raises(urllib.error.URLError):
                fetch_to_tempfile(url)
