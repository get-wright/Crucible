"""Model access. One factory so no call site decides live-vs-offline itself."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..config import Settings, get_settings
from .client import (
    Completion,
    EgressDenied,
    FPTClient,
    ProviderError,
    ToolCall,
    Usage,
    extract_json,
)
from .offline import OfflineClient

__all__ = [
    "Completion",
    "EgressDenied",
    "FPTClient",
    "OfflineClient",
    "ProviderError",
    "ToolCall",
    "Usage",
    "extract_json",
    "make_client",
]


def make_client(settings: Settings | None = None, *, agent_policy: str | None = None):
    """Return the live FPT client, or the scripted one when no key is present.

    Falling back on a missing key rather than raising is deliberate: a fresh
    clone should be able to run the whole pipeline and the test suite before
    anyone has been handed credentials.
    """
    s = settings or get_settings()
    if s.is_offline:
        return OfflineClient(s, agent_policy=agent_policy)
    return FPTClient(s)
