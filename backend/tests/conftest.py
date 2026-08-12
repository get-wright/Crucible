from __future__ import annotations

from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent.parent
EXAMPLE = PROJECT / "example-scenario.md"


@pytest.fixture(scope="session")
def example_yaml() -> str:
    return EXAMPLE.read_text()


@pytest.fixture
def tmp_settings(tmp_path, monkeypatch):
    """Settings pointed at a throwaway data dir, forced offline.

    Offline keeps the suite hermetic: tests must not depend on a live
    marketplace, on credentials, or on sampler luck.
    """
    from crucible.config import Settings, get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("CRUCIBLE_OFFLINE", "true")
    monkeypatch.setenv("CRUCIBLE_DATA_DIR", str(tmp_path))
    # Without this the suite writes scenario files into the real library.
    monkeypatch.setenv("CRUCIBLE_LIBRARY_DIR", str(tmp_path / "scenarios"))
    monkeypatch.delenv("FPT_API_KEY", raising=False)
    monkeypatch.delenv("MKP_API_KEY", raising=False)
    s = Settings(offline=True, data_dir=tmp_path, library_dir=tmp_path / "scenarios")
    s.ensure_dirs()
    yield s
    get_settings.cache_clear()
