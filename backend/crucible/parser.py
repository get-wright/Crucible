"""YAML → IR, preserving a line number for every node.

`PLATFORM_PLAN.md` §2.2 calls line-anchored errors the single
highest-leverage UX decision in the product, and they double as the
generator's repair signal. That is only possible if the parse keeps a map
from semantic path (`scenario.inputs.turns[1].attach_files[0]`) to source
line, which is what `LineIndex` is.

ruamel.yaml in round-trip mode attaches `.lc` position data to every mapping
and sequence node. We walk the loaded tree once and flatten that into a plain
dict so nothing downstream has to know about ruamel.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import MarkedYAMLError

from .ir import ScenarioIR


class LineIndex:
    """path -> 1-based source line. Missing paths fall back to the parent."""

    def __init__(self, mapping: dict[str, int] | None = None):
        self._m: dict[str, int] = mapping or {}

    def __contains__(self, path: str) -> bool:
        return path in self._m

    def line(self, path: str, default: int = 1) -> int:
        """Nearest known line for `path`, walking up to its ancestors."""
        if path in self._m:
            return self._m[path]
        parts = path.replace("[", ".[").split(".")
        while parts:
            parts.pop()
            probe = ".".join(parts).replace(".[", "[")
            if probe in self._m:
                return self._m[probe]
        return default

    def as_dict(self) -> dict[str, int]:
        return dict(self._m)


@dataclass(slots=True)
class ParseResult:
    ok: bool
    ir: ScenarioIR | None
    lines: LineIndex
    #: Populated only when the YAML itself is malformed. Schema-level problems
    #: are validate.py's job, so that one bad field does not mask the rest.
    syntax_error: str | None = None
    syntax_line: int | None = None


def _walk(node: Any, prefix: str, out: dict[str, int]) -> None:
    if isinstance(node, dict):
        lc = getattr(node, "lc", None)
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if lc is not None:
                try:
                    # (key_line, key_col, value_line, value_col), 0-based
                    out[path] = lc.data[key][0] + 1
                except (KeyError, AttributeError, TypeError, IndexError):
                    pass
            _walk(value, path, out)
    elif isinstance(node, list):
        lc = getattr(node, "lc", None)
        for i, value in enumerate(node):
            path = f"{prefix}[{i}]"
            if lc is not None:
                try:
                    out[path] = lc.data[i][0] + 1
                except (KeyError, AttributeError, TypeError, IndexError):
                    pass
            _walk(value, path, out)


def _plain(node: Any) -> Any:
    """Strip ruamel's comment/position wrappers to plain Python containers."""
    if isinstance(node, dict):
        return {str(k): _plain(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_plain(v) for v in node]
    return node


def parse(source: str) -> ParseResult:
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    try:
        raw = yaml.load(source)
    except MarkedYAMLError as e:
        line = (e.problem_mark.line + 1) if e.problem_mark else 1
        return ParseResult(False, None, LineIndex(), f"{e.problem}", line)
    except Exception as e:  # ruamel raises a wide family on malformed input
        return ParseResult(False, None, LineIndex(), str(e), 1)

    if raw is None:
        return ParseResult(False, None, LineIndex(), "the file is empty", 1)
    if not isinstance(raw, dict):
        return ParseResult(
            False, None, LineIndex(),
            f"the top level must be a mapping with `scenario:` and `agents:` keys, "
            f"got {type(raw).__name__}",
            1,
        )

    index: dict[str, int] = {}
    _walk(raw, "", index)
    lines = LineIndex(index)
    data = _plain(raw)

    # Build the IR leniently — every field is optional in ir.py precisely so
    # that a missing block becomes a validator finding with a line number,
    # not a construction crash with a stack trace.
    try:
        ir = ScenarioIR.model_validate({
            "scenario": data.get("scenario") or {},
            "agents": data.get("agents") or {},
            "source": source,
        })
    except Exception as e:
        return ParseResult(False, None, lines, f"could not interpret the document: {e}", 1)

    return ParseResult(True, ir, lines)
