"""Small Win32 window helpers used to close Gargoyle's MessageBox payload."""

from __future__ import annotations

import ctypes
import time
from ctypes import wintypes
from typing import Any

from gargoyle_acceptance.errors import AcceptanceError

WM_CLOSE = 0x0010


class MessageBoxController:
    """Finds and closes MessageBox windows owned by a process."""

    def __init__(self) -> None:
        """Load the Win32 user32 API."""
        self._user32: Any = ctypes.WinDLL("user32", use_last_error=True)

    def wait_for_message_box(
        self,
        *,
        pid: int,
        title: str,
        timeout_seconds: float,
        poll_seconds: float = 0.1,
    ) -> int:
        """Wait for a visible MessageBox window with the expected title.

        Args:
            pid: Process ID that should own the window.
            title: Expected window title.
            timeout_seconds: Maximum time to wait.
            poll_seconds: Delay between polls.

        Returns:
            Native window handle as an integer.

        Raises:
            AcceptanceError: If the window does not appear before the timeout.
        """
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            matches = self.find_message_boxes(pid=pid, title=title)
            if matches:
                return matches[0]
            time.sleep(poll_seconds)
        raise AcceptanceError(
            "MessageBox not found",
            f"No visible {title!r} MessageBox appeared for process {pid}.",
            (
                "The PIC may not have reached the benign payload, or the desktop may be "
                "non-interactive."
            ),
        )

    def find_message_boxes(self, *, pid: int, title: str) -> list[int]:
        """Enumerate visible windows that look like Gargoyle MessageBoxes.

        Args:
            pid: Process ID that should own the window.
            title: Expected window title.

        Returns:
            Matching window handles.
        """
        matches: list[int] = []
        enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        @enum_proc  # type: ignore[untyped-decorator]
        def callback(hwnd: int, _lparam: int) -> bool:
            window_pid = wintypes.DWORD()
            self._user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
            if int(window_pid.value) != pid:
                return True
            if not self._user32.IsWindowVisible(hwnd):
                return True
            text = self._window_text(hwnd)
            if text == title:
                matches.append(hwnd)
            return True

        self._user32.EnumWindows(callback, 0)
        return matches

    def close_window(self, hwnd: int) -> None:
        """Close a window by posting `WM_CLOSE`.

        Args:
            hwnd: Native window handle.

        Raises:
            AcceptanceError: If `PostMessageW` fails.
        """
        if not self._user32.PostMessageW(hwnd, WM_CLOSE, 0, 0):
            error_code = ctypes.get_last_error()
            raise AcceptanceError(
                "MessageBox close failed",
                f"PostMessageW(WM_CLOSE) failed for hwnd {hwnd:#x} with error {error_code}.",
                "Close the MessageBox manually, then rerun the harness.",
            )

    def wait_until_closed(
        self,
        hwnd: int,
        *,
        timeout_seconds: float = 5.0,
        poll_seconds: float = 0.1,
    ) -> None:
        """Wait until a window handle is no longer valid.

        Args:
            hwnd: Native window handle.
            timeout_seconds: Maximum time to wait.
            poll_seconds: Delay between polls.

        Raises:
            AcceptanceError: If the window remains open.
        """
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if not self._user32.IsWindow(hwnd):
                return
            time.sleep(poll_seconds)
        raise AcceptanceError(
            "MessageBox stayed open",
            f"Window {hwnd:#x} did not close within {timeout_seconds:.0f} seconds.",
            "Close the MessageBox manually and check whether another process owns it.",
        )

    def _window_text(self, hwnd: int) -> str:
        """Read the UTF-16 title text for a window.

        Args:
            hwnd: Native window handle.

        Returns:
            Window title text.
        """
        length = int(self._user32.GetWindowTextLengthW(hwnd))
        buffer = ctypes.create_unicode_buffer(length + 1)
        self._user32.GetWindowTextW(hwnd, buffer, length + 1)
        return buffer.value
