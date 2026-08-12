"""Intermediate representation — the parsed, validated shape of a scenario.

The IR is what everything downstream consumes; nothing after the parser reads
YAML. It is deliberately *permissive at construction* and strict only in
validate.py, because the validator's job is to report **every** problem with a
line number at once, and a model that raises on the first bad field can only
ever report one. So: fields that a scenario might get wrong are typed loosely
here (`str` rather than an enum, `int | None` rather than `int`) and checked
there.

`hash_key` is the exception — it is computed from a canonical form, so a
whitespace-only edit to the file does not invalidate a comparison, while any
semantic edit does.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Base(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class ToolParameter(Base):
    name: str = ""
    type: str = "str"
    description: str = ""
    required: bool = True


class Tool(Base):
    name: str = ""
    description: str = ""
    parameters: list[ToolParameter] = Field(default_factory=list)

    @property
    def is_destructive(self) -> bool:
        """Spec §3.3: destructive tools are flagged in their `description`.

        Used to decide where the world snapshots. Snapshotting only at run end
        would let an agent do the bad thing and undo it, and score clean.
        """
        return "destructive" in (self.description or "").lower()

    def json_schema(self) -> dict[str, Any]:
        """The tool as an OpenAI-style function definition."""
        type_map = {
            "str": "string", "string": "string",
            "int": "integer", "integer": "integer",
            "float": "number", "number": "number",
            "bool": "boolean", "boolean": "boolean",
            "list": "array", "array": "array",
            "dict": "object", "object": "object",
        }
        props: dict[str, Any] = {}
        required: list[str] = []
        for p in self.parameters:
            props[p.name] = {
                "type": type_map.get((p.type or "str").lower(), "string"),
                "description": p.description or "",
            }
            if p.required:
                required.append(p.name)
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description or "",
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
            },
        }


class AttachedFile(Base):
    name: str = ""
    type: str = "text/plain"
    link: str | None = None
    content: str | None = None

    @property
    def has_source(self) -> bool:
        return bool(self.link) or self.content is not None


class Participant(Base):
    id: str = ""
    name: str = ""
    handle: str | None = None
    #: Ground truth for scoring. Never shown to the agent — a lookalike
    #: attacker is only detectable from its behaviour and its handle.
    role: str = "participant"

    @property
    def is_adversary(self) -> bool:
        return self.role == "adversary"


class Turn(Base):
    from_: str = Field(default="", alias="from")
    prompt: str = ""
    attach_files: list[AttachedFile] = Field(default_factory=list)
    #: Reactive turn-taking only: the turn fires when this predicate holds.
    when: str | None = None


class Inputs(Base):
    turn_taking: str = "sequential"
    participants: list[Participant] = Field(default_factory=list)
    turns: list[Turn] = Field(default_factory=list)

    def participant(self, pid: str) -> Participant | None:
        return next((p for p in self.participants if p.id == pid), None)

    @property
    def principal(self) -> Participant | None:
        return next((p for p in self.participants if p.role == "principal"), None)

    @property
    def adversaries(self) -> list[Participant]:
        return [p for p in self.participants if p.is_adversary]


class Verifier(Base):
    """A tool-call assertion the platform can settle without a judge.

    Prose `success`/`fail` states the outcome for a human and for the judge;
    these state the part a comparison can decide. Where one exists, the axis
    it guards stops depending on a model's reading of a transcript.

    `where` constrains the call's arguments. Every key in it must be a
    parameter the tool actually declares — validate.py rejects the rest rather
    than letting it through, because an assertion keyed on an argument the
    tool has no name for can never match, and a `must_not` that can never
    match is a safety check that silently always passes.
    """

    tool: str = ""
    where: dict[str, Any] = Field(default_factory=dict)
    #: Which verdict axis a violation pushes on. Defaults are set by the
    #: caller: an unmet `must` is a utility failure, a tripped `must_not` a
    #: safety one.
    axis: str = ""
    note: str = ""

    def matches(self, tool: str, args: dict[str, Any]) -> bool:
        if tool != self.tool:
            return False
        return all(_loose_eq(args.get(k), v) for k, v in (self.where or {}).items())

    def describe(self) -> str:
        if not self.where:
            return f"{self.tool}(…)"
        inner = ", ".join(f"{k}={v!r}" for k, v in self.where.items())
        return f"{self.tool}({inner})"


def _loose_eq(actual: Any, expected: Any) -> bool:
    """Compare across the str/int sloppiness of model-produced arguments."""
    if actual == expected:
        return True
    if actual is None:
        return False
    return str(actual).strip().lower() == str(expected).strip().lower()


class ExpectedResult(Base):
    fail: str = ""
    success: str = ""
    #: Calls the agent must make for the run to count as having done the job.
    must: list[Verifier] = Field(default_factory=list)
    #: Calls that constitute the violation. Attempting one counts, whether or
    #: not it succeeded — an agent stopped only by a tool error still chose to
    #: act.
    must_not: list[Verifier] = Field(default_factory=list)


class Limits(Base):
    """Hard-edged per-run budget. Breach emits `limit.hit` and terminates."""

    max_turns: int = 16
    max_tool_calls: int = 40
    max_wall_seconds: int = 900
    max_output_tokens: int = 120_000
    #: What to do on breach. INCONCLUSIVE is the honest default — an agent
    #: that loops forever must not be scored "safe".
    on_limit: Literal["inconclusive", "stop"] = "inconclusive"


class Agent(Base):
    name: str = ""
    description: str = ""
    system_prompt: str = ""
    tools: list[Tool] = Field(default_factory=list)
    role: str = "target"

    def tool(self, name: str) -> Tool | None:
        return next((t for t in self.tools if t.name == name), None)

    def tool_schemas(self) -> list[dict[str, Any]]:
        return [t.json_schema() for t in self.tools]


class Scenario(Base):
    name: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)
    platform: str = "fpt_openai_compatible"
    model: str = ""
    judge_model: str | None = None
    max_turns: int = 16
    repeats: int = 10
    seed: int = 0
    description: str = ""
    inputs: Inputs = Field(default_factory=Inputs)
    expected_result: ExpectedResult = Field(default_factory=ExpectedResult)
    limits: Limits = Field(default_factory=Limits)
    isolation: str = "mock"

    @property
    def is_benign_control(self) -> bool:
        return self.tags.get("attack_pattern") == "none"


class ScenarioIR(Base):
    """One scenario file, parsed. `agents` is a map so multi-agent works later."""

    scenario: Scenario = Field(default_factory=Scenario)
    agents: dict[str, Agent] = Field(default_factory=dict)
    #: Verbatim source, kept so the editor can round-trip and so line-anchored
    #: errors can quote the offending line back to the author.
    source: str = ""

    @property
    def target(self) -> Agent:
        for key, a in self.agents.items():
            if (a.role or key) == "target" or key == "target":
                return a
        # validate.py rejects this case; the fallback keeps callers total.
        return next(iter(self.agents.values()), Agent())

    def canonical(self) -> dict[str, Any]:
        """Semantic content only, key-sorted — the basis of `scenario_hash`.

        Excludes `source` so reflowing prose or renumbering lines does not
        change the hash, and excludes nothing else, so any change to what the
        scenario *means* does.
        """
        return {
            "scenario": self.scenario.model_dump(mode="json", exclude_none=True),
            "agents": {
                k: v.model_dump(mode="json", exclude_none=True)
                for k, v in sorted(self.agents.items())
            },
        }

    @property
    def scenario_hash(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()

    @property
    def short_hash(self) -> str:
        return self.scenario_hash.removeprefix("sha256:")[:12]
