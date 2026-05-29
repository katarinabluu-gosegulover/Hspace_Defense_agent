"""Minimal HSPACE agent SDK shim used by the team defense agent.

This package also provides a tiny compatibility layer for older agent
implementations that expected ``AgentContext`` and ``AgentSDKError`` to exist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class AgentSDKError(RuntimeError):
    """Compatibility exception used by older defense agent variants."""


@dataclass
class AgentContext:
    """No-op compatibility shim for legacy agent code paths.

    The current defense agent does not use this class, but some earlier builds
    imported it directly. Keeping a permissive implementation prevents those
    builds from crashing at import time if the coordinator starts them.
    """

    values: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.values[key] = value

    def log(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def report(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def emit_event(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def __enter__(self) -> "AgentContext":
        return self

    def __exit__(self, *_exc: Any) -> bool:
        return False
