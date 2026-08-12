"""Field overrides — change a scenario at the point of running it.

Sweeping a scenario across models, turn limits or prompts otherwise means
editing the file, running, and editing it back. That is fine once and awful
ten times, and it leaves the library full of half-reverted experiments.

An override is applied to the YAML text before validation, not to the parsed
object afterwards. Three things follow from that, all of them wanted:

  * the result is a real scenario file, so line-anchored findings still point
    at real lines;
  * `scenario_hash` changes, so an overridden run is stored as its own thing
    rather than silently colliding with the unmodified scenario's results;
  * the exact text that ran can be written out and kept.

Paths are dotted, with bracket indices for lists:

    scenario.model=GLM-5.2
    scenario.max_turns=8
    scenario.inputs.turns[0].prompt=Just look, do not act.
    agents.target.tools[2].description=Merges a PR. Destructive.
"""

from __future__ import annotations

import io
import re
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

_STEP = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


class OverrideError(ValueError):
    """The path does not address anything in this scenario."""


def _steps(path: str) -> list[str | int]:
    out: list[str | int] = []
    for key, index in _STEP.findall(path):
        out.append(int(index) if index else key)
    if not out:
        raise OverrideError(f"`{path}` is not a field path")
    return out


def _coerce(raw: str) -> Any:
    """Turn the command-line string into the type the field expects.

    `max_turns=8` has to become an integer or validation rejects it for being
    a string, which would be a confusing way to learn about a typo.
    """
    text = raw.strip()
    lowered = text.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered in ("null", "none", "~"):
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return LiteralScalarString(text) if "\n" in text else text


def apply_overrides(yaml_text: str, assignments: list[str]) -> tuple[str, list[str]]:
    """Apply `path=value` assignments to a scenario file.

    Returns the rewritten text and a note per change, so a run can record what
    it was actually given rather than only what the file on disk says.
    """
    if not assignments:
        return yaml_text, []

    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 96
    yaml.indent(mapping=2, sequence=4, offset=2)
    doc = yaml.load(yaml_text)
    notes: list[str] = []

    for raw in assignments:
        if "=" not in raw:
            raise OverrideError(f"`{raw}` is not `path=value`")
        path, _, value = raw.partition("=")
        steps = _steps(path.strip())
        node: Any = doc
        for i, step in enumerate(steps[:-1]):
            try:
                node = node[step]
            except (KeyError, IndexError, TypeError) as e:
                walked = ".".join(str(x) for x in steps[: i + 1])
                raise OverrideError(
                    f"`{path}` does not exist: nothing at `{walked}`"
                ) from e
        last = steps[-1]
        # Refuse to invent a field. A typo that silently adds `scenario.modle`
        # would run the unmodified scenario and report success.
        try:
            before = node[last]
        except (KeyError, IndexError, TypeError) as e:
            raise OverrideError(
                f"`{path}` does not exist in this scenario, so setting it would "
                "have no effect on the run"
            ) from e
        node[last] = _coerce(value)
        notes.append(f"{path.strip()}: {before!r} -> {node[last]!r}")

    buf = io.StringIO()
    yaml.dump(doc, buf)
    return buf.getvalue(), notes
