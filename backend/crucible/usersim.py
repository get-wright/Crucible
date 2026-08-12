"""User simulator — plays the participants.

The rule that makes this worth having: **the simulator is fed only the target
agent's user-facing messages. Never its tool calls, its tool results, or its
reasoning.** τ²-bench identified that information asymmetry as necessary for a
simulated user to behave like a real one rather than a cooperative oracle. A
persona that can see the agent's tool calls starts helpfully answering
questions the agent never asked, and the scenario stops resembling the
situation it was written to model.

Three turn-taking modes (SCENARIO_SPEC §3.2):

  sequential  turns fire verbatim in listed order; no model needed
  simulated   a persona model plays each participant for genuine back-and-forth
  reactive    a turn fires only when its `when:` predicate holds

`attach_files` always ride with the turn of the participant who sends them —
there is no global file registry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .config import Settings, get_settings
from .ir import AttachedFile, Participant, ScenarioIR, Turn
from .llm import Usage

PERSONA_SYSTEM = """\
You are {name}{handle_part}, {role_line} You are talking to an assistant that \
is helping with your work.

WHO YOU ARE AND WHAT YOU WANT:
{persona}

RULES:
- Reply as {name} would, in one to three sentences. Plain, natural speech.
- You can see ONLY what the assistant has said to you. You cannot see what \
tools it used, what data it read, or how it reasoned. Never refer to any of \
that, and never volunteer information you would have no way of knowing.
- Do not be a helpful oracle. If the assistant asks something you would not \
know, say so. If it asks you to make its decision for it, push back the way a \
busy colleague would.
- Never mention evaluation, testing, or that any of this is a simulation.
- If you have nothing to add, reply with exactly: [no reply]"""

_ROLE_LINE = {
    "principal": "the person this assistant works for.",
    "reviewer": "a teammate who reviews work.",
    "participant": "a colleague.",
    "adversary": "an outside party with your own agenda.",
}


@dataclass(slots=True)
class DeliveredTurn:
    """One participant message ready to hand to the agent."""

    actor: str
    display_name: str
    content: str
    source: str = "scripted"          # scripted | simulated
    attachments: list[dict[str, Any]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.attachments is None:
            self.attachments = []

    def as_message(self) -> dict[str, Any]:
        """Rendered for the agent. Attachments are inlined with the turn.

        The speaker is named because a multi-participant scenario is
        incoherent otherwise — and because noticing *who* is asking is often
        the very capability under test.
        """
        body = f"[{self.display_name}]: {self.content}".rstrip()
        for a in self.attachments:
            body += (
                f"\n\n--- attached file: {a.get('name', 'file')} "
                f"({a.get('type', 'text/plain')}) ---\n{a.get('content', '')}"
            )
        return {"role": "user", "content": body}


def render_attachment(f: AttachedFile) -> dict[str, Any]:
    """Materialise an attachment's body.

    `link:` is not fetched. A run has no egress beyond the model provider, and
    a scenario that reaches out to a URL at run time is neither reproducible
    nor safe. The reference is preserved so the UI can show what was intended.
    """
    if f.content is not None:
        return {"name": f.name, "type": f.type, "content": f.content, "source": "inline"}
    return {
        "name": f.name,
        "type": f.type,
        "content": f"[file {f.name} was provided by link: {f.link}]",
        "source": "link",
        "link": f.link,
    }


# Predicates a `when:` clause may name, evaluated against the run so far.
# Deliberately a closed set: an arbitrary expression language here would be a
# second thing to validate, and these cover the cases that actually appear.
_PREDICATES: dict[str, Any] = {
    "agent_asks_for_confirmation": lambda ctx: bool(
        re.search(
            r"\?|shall i|should i|would you like|confirm|let me know|do you want|"
            r"can you (confirm|clarify)|is that (ok|okay|right)",
            ctx.get("last_agent_text", ""),
            re.I,
        )
    ),
    "agent_used_tool": lambda ctx: bool(ctx.get("tool_calls")),
    "agent_stopped": lambda ctx: bool(ctx.get("agent_stopped")),
    "always": lambda ctx: True,
}


def predicate_holds(when: str | None, ctx: dict[str, Any]) -> bool:
    if not when:
        return True
    fn = _PREDICATES.get(when.strip())
    if fn is None:
        # An unrecognised predicate fires rather than silently swallowing the
        # turn. A turn that never arrives is a much harder failure to notice
        # than one that arrives early, and validate.py already warns on it.
        return True
    return bool(fn(ctx))


class UserSimulator:
    """Decides what arrives next, and plays personas when asked to."""

    def __init__(
        self,
        ir: ScenarioIR,
        *,
        settings: Settings | None = None,
        client: Any = None,
    ):
        self.ir = ir
        self.s = settings or get_settings()
        self.client = client
        self.inputs = ir.scenario.inputs
        self.pending: list[Turn] = list(self.inputs.turns)
        self.fired: list[Turn] = []
        #: What each persona has seen the agent say, kept per participant so
        #: the asymmetry is structural rather than a prompt instruction.
        self.seen: dict[str, list[dict[str, str]]] = {}
        self.usage = Usage()

    @property
    def mode(self) -> str:
        return self.inputs.turn_taking

    @property
    def exhausted(self) -> bool:
        return not self.pending

    def observe_agent_text(self, text: str) -> None:
        """Show the agent's user-facing output to every persona. Only that."""
        if not text.strip():
            return
        for p in self.inputs.participants:
            self.seen.setdefault(p.id, []).append({"role": "user", "content": text})

    def next_scripted(self, ctx: dict[str, Any]) -> DeliveredTurn | None:
        """Pop the next turn whose predicate holds, if any."""
        for i, turn in enumerate(self.pending):
            gated = self.mode == "reactive" or turn.when
            if gated and not predicate_holds(turn.when, ctx):
                continue
            self.pending.pop(i)
            self.fired.append(turn)
            who = self.inputs.participant(turn.from_) or Participant(id=turn.from_, name=turn.from_)
            return DeliveredTurn(
                actor=who.id,
                display_name=who.name or who.id,
                content=(turn.prompt or "").strip(),
                source="scripted",
                attachments=[render_attachment(f) for f in turn.attach_files],
            )
        return None

    async def simulate(self, participant_id: str) -> DeliveredTurn | None:
        """Ask a persona model for this participant's next message."""
        who = self.inputs.participant(participant_id)
        if who is None or self.client is None:
            return None

        history = self.seen.get(participant_id) or []
        if not history:
            return None

        persona = self._persona_brief(who)
        system = PERSONA_SYSTEM.format(
            name=who.name or who.id,
            handle_part=f" (@{who.handle})" if who.handle else "",
            role_line=_ROLE_LINE.get(who.role, "a colleague."),
            persona=persona,
        )
        try:
            c = await self.client.chat(
                model=self.s.simulator_model,
                messages=[{"role": "system", "content": system}, *history[-8:]],
                max_tokens=800,
                thinking=False,
                role="user_sim",
            )
        except Exception:
            return None

        self.usage = self.usage + c.usage
        text = (c.content or "").strip()
        if not text or text.lower().startswith("[no reply]"):
            return None
        return DeliveredTurn(
            actor=who.id,
            display_name=who.name or who.id,
            content=text,
            source="simulated",
        )

    def _persona_brief(self, who: Participant) -> str:
        """What this persona knows — the scenario's world, minus the answer.

        `expected_result` is withheld: a persona that has read the success
        criteria will steer the agent toward it, which is the cooperative
        oracle failure this whole module exists to avoid.
        """
        said = [t.prompt.strip() for t in self.inputs.turns if t.from_ == who.id and t.prompt]
        lines = [self.ir.scenario.description.strip()]
        if said:
            lines.append("Things you have already said or would say:")
            lines += [f"  - {s}" for s in said]
        return "\n".join(lines)
