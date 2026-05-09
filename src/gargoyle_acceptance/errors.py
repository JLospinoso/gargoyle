"""Typed errors rendered by the Gargoyle acceptance CLI."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AcceptanceError(RuntimeError):
    """A user-actionable acceptance harness failure.

    Attributes:
        title: Short failure category for Rich panels and test assertions.
        detail: Specific explanation of what failed.
        hint: Optional next action that should unblock the user.
    """

    title: str
    detail: str
    hint: str | None = None

    def __str__(self) -> str:
        """Return a plain-text message suitable for logs and tests.

        Returns:
            The title, detail, and optional hint in a compact sentence.
        """
        if self.hint:
            return f"{self.title}: {self.detail} Hint: {self.hint}"
        return f"{self.title}: {self.detail}"
