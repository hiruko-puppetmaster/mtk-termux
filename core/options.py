"""Shared CLI/TUI options and progress reporting primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol


@dataclass
class AppOptions:
    mode: str = "tui"
    da: Path | None = None
    preloader: Path | None = None
    auth: Path | None = None
    payload: Path | None = None
    profiles_dir: Path | None = None
    exploit: str = "auto"
    prefer_model: str | None = None
    port: int | None = None
    once: bool = False
    wait_timeout: float = 0.0
    dry_run: bool = False
    allow_unsigned_da: bool = False
    no_root_check: bool = False
    json: bool = False
    verbose: bool = False
    no_color: bool = False
    elevate: bool = False
    rpmb_key: bytes | None = None
    rpmb_confirm: bool = False
    extra_asset_dirs: list[Path] = field(default_factory=list)


ProgressCallback = Callable[[str, str, float | None], None]


def null_progress(stage: str, message: str, fraction: float | None = None) -> None:
    """Default no-op progress callback."""


class Logger(Protocol):
    def info(self, message: str) -> None: ...
    def warning(self, message: str) -> None: ...
    def error(self, message: str) -> None: ...
    def debug(self, message: str) -> None: ...
