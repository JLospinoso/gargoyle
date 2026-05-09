"""Unit tests for user-facing acceptance errors."""

from __future__ import annotations

from gargoyle_acceptance.errors import AcceptanceError


def test_acceptance_error_string_without_hint() -> None:
    """Errors without hints render compactly."""
    assert str(AcceptanceError("Title", "Detail")) == "Title: Detail"
