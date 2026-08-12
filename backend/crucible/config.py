"""Runtime configuration.

Every model call in Crucible goes through the FPT AI Marketplace, an
OpenAI-compatible endpoint. Three distinct model roles exist and they are
configured separately on purpose:

  target    - the model under test (overridable per scenario)
  simulator - seeds the world and serves unbound tool calls
  judge     - grades the run; must differ from the target where numbers are
              published (self-preference bias), enforced in judge.py
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = REPO_ROOT.parent

# The four models the marketplace currently serves. Kept here so the API can
# offer them to the UI without a network round-trip on every page load.
FPT_MODELS = ["GLM-5.2", "DeepSeek-V4-Flash", "Qwen3.6-27B", "gpt-oss-120b"]


def is_available(model: str) -> bool:
    return model in FPT_MODELS


def resolve_model(requested: str, default: str) -> tuple[str, str | None]:
    """Map a requested model onto one this provider actually serves.

    The scenario format is provider-agnostic by design — the example declares
    `claude-opus-5` and `gpt-5.5`, neither of which FPT hosts. Failing the run
    would make every portable scenario unrunnable here; silently substituting
    would make results incomparable without anyone noticing. So: substitute,
    and return a note that the caller records in `run.start` and in the result
    row, next to `scenario_hash`.

    Returns `(model_to_use, note_or_None)`.
    """
    if not requested:
        return default, None
    if is_available(requested):
        return requested, None
    return default, (
        f"scenario requested `{requested}`, which this provider does not serve; "
        f"ran on `{default}` instead"
    )


# A `KEY=VALUE` assignment, as opposed to a bare token that merely contains
# "=". FPT keys are base64 and routinely end in "=" padding, so testing for
# the presence of "=" anywhere misclassifies a real key as an assignment.
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _bare_token_from_dotenv() -> str:
    """Read a key from a `.env` holding just the token, with no `KEY=` prefix.

    The project's `.env` is a single bare line. pydantic-settings only parses
    `KEY=VALUE`, so that file would otherwise be silently ignored and the
    backend would drop to offline mode with a valid key sitting on disk. Both
    the backend dir and the project root are checked, nearest first.
    """
    for candidate in (REPO_ROOT / ".env", PROJECT_ROOT / ".env"):
        try:
            text = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
        if len(lines) == 1 and not _ASSIGNMENT.match(lines[0]):
            return lines[0]
    return ""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CRUCIBLE_", env_file=".env", extra="ignore"
    )

    # --- provider -----------------------------------------------------------
    fpt_base_url: str = "https://mkp-api.fptcloud.com/v1"
    fpt_api_key: str = ""

    target_model: str = "GLM-5.2"
    simulator_model: str = "GLM-5.2"
    judge_model: str = "DeepSeek-V4-Flash"
    generator_model: str = "GLM-5.2"

    # FPT load-balances across vLLM replicas and does not honour `seed`, so
    # temperature 0 is the only sampler-side determinism lever available.
    # Per-replica greedy is deterministic; cross-replica is not.
    temperature: float = 0.0
    request_timeout_s: float = 180.0
    max_retries: int = 3

    # --- egress -------------------------------------------------------------
    # Deny-all except these hosts. A denied outbound attempt from inside a run
    # is itself a finding and is logged as `egress.denied`.
    egress_allowlist: str = "mkp-api.fptcloud.com"

    # --- storage ------------------------------------------------------------
    data_dir: Path = REPO_ROOT / "data"

    # --- offline ------------------------------------------------------------
    # When true (or when no key is present) all model calls are served by the
    # deterministic scripted backend in llm/offline.py. The whole pipeline
    # still runs end to end; only the intelligence is stubbed.
    offline: bool = False

    @property
    def resolved_key(self) -> str:
        """FPT_API_KEY, then MKP_API_KEY, then CRUCIBLE_FPT_API_KEY, then bare `.env`."""
        return (
            os.environ.get("FPT_API_KEY")
            or os.environ.get("MKP_API_KEY")
            or self.fpt_api_key
            or _bare_token_from_dotenv()
        )

    @property
    def is_offline(self) -> bool:
        return self.offline or not self.resolved_key

    @property
    def allowed_hosts(self) -> set[str]:
        return {h.strip() for h in self.egress_allowlist.split(",") if h.strip()}

    @property
    def scenarios_dir(self) -> Path:
        return self.data_dir / "scenarios"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"

    @property
    def worlds_dir(self) -> Path:
        return self.data_dir / "worlds"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "crucible.db"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.scenarios_dir, self.runs_dir, self.worlds_dir):
            d.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
