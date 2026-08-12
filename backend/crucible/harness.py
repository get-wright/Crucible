"""Agent loop — the target under test, behind a provider-agnostic interface.

`Harness` is deliberately thin (PLATFORM_PLAN §2.4). One adapter ships:
FPT's OpenAI-compatible route, which covers every model the marketplace
serves. `openai_agents`, `langgraph` and a generic `mcp_client` slot in behind
the same three methods later.

Streaming deltas are preserved rather than collapsed. `reasoning.delta` is
where you actually see the moment an agent gets talked into something, and it
is the thing most eval harnesses throw away.

## Thinking starvation

Measured on this provider: a thinking model given too small a `max_tokens`
spends the entire budget on `reasoning_content` and returns `finish_reason:
"length"` with empty content and no tool calls. The loop would then see a
silent, blameless stall — an agent that did nothing, scored as safe.

`step` detects that exact signature and retries once with thinking disabled,
which converts a stall into an answer. If it still starves, the run ends
INCONCLUSIVE rather than pretending the agent chose to stop.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Protocol

from .config import Settings, get_settings
from .llm import Completion, Usage


@dataclass
class Session:
    """One conversation with the target agent."""

    system_prompt: str
    tools: list[dict[str, Any]] = field(default_factory=list)
    messages: list[dict[str, Any]] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    model: str = ""

    def wire(self) -> list[dict[str, Any]]:
        return [{"role": "system", "content": self.system_prompt}, *self.messages]

    def add_user(self, message: dict[str, Any]) -> None:
        self.messages.append(message)

    def add_assistant(self, c: Completion) -> None:
        """Record the assistant turn in the shape the API expects back.

        `content` must be present even when empty — some routes reject an
        assistant message with tool calls and no content key.
        """
        msg: dict[str, Any] = {"role": "assistant", "content": c.content or ""}
        if c.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": tc.raw_arguments or "{}"},
                }
                for tc in c.tool_calls
            ]
        self.messages.append(msg)

    def add_tool_result(self, call_id: str, name: str, content: str) -> None:
        self.messages.append(
            {"role": "tool", "tool_call_id": call_id, "name": name, "content": content}
        )


class Harness(Protocol):
    def start(
        self, system_prompt: str, tools: list[dict[str, Any]], initial: list[dict[str, Any]]
    ) -> Session: ...

    def step(self, session: Session) -> AsyncIterator[Any]: ...

    def submit_tool_results(self, session: Session, results: list[tuple[str, str, str]]) -> None: ...


class FPTHarness:
    """Adapter for the FPT OpenAI-compatible route."""

    name = "fpt_openai_compatible"

    def __init__(
        self,
        client: Any,
        model: str,
        *,
        settings: Settings | None = None,
        max_tokens: int = 8000,
    ):
        self.client = client
        self.model = model
        self.s = settings or get_settings()
        self.max_tokens = max_tokens

    def start(
        self,
        system_prompt: str,
        tools: list[dict[str, Any]],
        initial: list[dict[str, Any]] | None = None,
    ) -> Session:
        return Session(
            system_prompt=system_prompt,
            tools=tools,
            messages=list(initial or []),
            model=self.model,
        )

    async def step(self, session: Session) -> AsyncIterator[Any]:
        """Stream one assistant turn. Yields deltas, then a final Completion."""
        final: Completion | None = None
        async for ev in self.client.stream(
            model=self.model,
            messages=session.wire(),
            tools=session.tools or None,
            max_tokens=self.max_tokens,
            role="agent",
        ):
            if isinstance(ev, tuple):
                yield ev
            else:
                final = ev

        if final is None:
            final = Completion(finish_reason="error")

        if _starved(final):
            # See module docstring. Retry once with thinking off so the whole
            # budget is available for the answer.
            retry: Completion | None = None
            async for ev in self.client.stream(
                model=self.model,
                messages=session.wire(),
                tools=session.tools or None,
                max_tokens=self.max_tokens,
                thinking=False,
                role="agent",
            ):
                if isinstance(ev, tuple):
                    yield ev
                else:
                    retry = ev
            if retry is not None and not _starved(retry):
                retry.usage = retry.usage + final.usage
                final = retry
            else:
                final.finish_reason = "starved"

        session.usage = session.usage + final.usage
        yield final

    def submit_tool_results(
        self, session: Session, results: list[tuple[str, str, str]]
    ) -> None:
        for call_id, name, content in results:
            session.add_tool_result(call_id, name, content)


def _starved(c: Completion) -> bool:
    """The thinking-starvation signature: budget spent, nothing produced."""
    return (
        c.finish_reason == "length"
        and not c.tool_calls
        and not (c.content or "").strip()
    )
