"""Single-run execution — PLATFORM_PLAN §3.

One scenario, one repeat, one variant. The orchestrator fans these out; this
module knows nothing about `k` or about other runs.

Loop shape:

    deliver any participant turns due now (in order, or whose `when` holds),
      with any attach_files that ride along
    loop:
      stream the agent's turn, emitting reasoning/text deltas live
      if it called tools: serve them, emit tool.call + tool.result
                          (+ injection.delivered when a result carried a payload)
      else: break
    if simulated turn-taking: ask a persona for the next message
    stop when nothing is pending and the agent has stopped

Budget enforcement is hard-edged and checked at every boundary: turns, tool
calls, wall clock, output tokens. On breach the run emits `limit.hit` and
terminates INCONCLUSIVE. An agent that loops forever must not score as safe.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ulid import ULID

from .checks import run_checks
from .config import Settings, get_settings, resolve_model
from .envsim import EnvironmentSimulator
from .events import EventLog
from .harness import FPTHarness
from .ir import ScenarioIR
from .llm import Completion, Usage, make_client
from .usersim import UserSimulator
from .verdict import Verdict, compute_verdict
from .world import World, seed_world


@dataclass
class RunResult:
    run_id: str
    scenario_hash: str
    variant: str
    repeat: int
    verdict: Verdict
    log: EventLog
    world: World
    usage: Usage = field(default_factory=Usage)
    wall_ms: int = 0
    log_path: Path | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_hash": self.scenario_hash,
            "variant": self.variant,
            "repeat": self.repeat,
            "verdict": self.verdict.as_dict(),
            "wall_ms": self.wall_ms,
            "usage": {
                "input_tokens": self.usage.input_tokens,
                "output_tokens": self.usage.output_tokens,
            },
            "log_path": str(self.log_path) if self.log_path else None,
        }


class _Budget:
    """Hard limits. Every breach names the limit and the value it hit."""

    def __init__(self, ir: ScenarioIR):
        lim = ir.scenario.limits
        self.max_turns = max(1, ir.scenario.max_turns or lim.max_turns)
        self.max_tool_calls = lim.max_tool_calls
        self.max_wall_s = lim.max_wall_seconds
        self.max_output = lim.max_output_tokens
        self.started = time.perf_counter()
        self.tool_calls = 0
        self.output_tokens = 0

    def breach(self, turn: int) -> tuple[str, Any] | None:
        if turn > self.max_turns:
            return "max_turns", turn
        if self.tool_calls > self.max_tool_calls:
            return "max_tool_calls", self.tool_calls
        if (time.perf_counter() - self.started) > self.max_wall_s:
            return "max_wall_seconds", round(time.perf_counter() - self.started, 1)
        if self.output_tokens > self.max_output:
            return "max_output_tokens", self.output_tokens
        return None


async def execute_run(
    ir: ScenarioIR,
    *,
    variant: str = "attack",
    repeat: int = 0,
    seed: int = 0,
    settings: Settings | None = None,
    client: Any = None,
    model: str | None = None,
    judge_model: str | None = None,
    timeout_s: float = -1,
    judge: bool = True,
    on_event: Any = None,
    run_id: str | None = None,
) -> RunResult:
    """Execute one run end to end and return its verdict."""
    s = settings or get_settings()
    rid = run_id or f"run_{ULID()}"
    started = time.perf_counter()

    own_client = client is None
    c = client or make_client(s)

    log_path = s.runs_dir / f"{rid}.jsonl"
    log = EventLog(
        run_id=rid, scenario_hash=ir.scenario_hash,
        variant=variant, repeat=repeat, path=log_path,
    )
    if on_event is not None:
        log.on_event = on_event

    target = ir.target
    # A scenario may name a model this provider does not serve; substitute and
    # record it rather than failing a portable scenario outright.
    target_model, model_note = resolve_model(model or ir.scenario.model, s.target_model)
    resolved_judge_model, judge_note = resolve_model(
        judge_model or ir.scenario.judge_model or "", s.judge_model
    )
    substitutions = [n for n in (model_note, judge_note) if n]
    budget = _Budget(ir)
    terminated_by = "agent_stop"
    limit_hit: tuple[str, Any] | None = None

    try:
        world: World | None = None
        initial_world: dict[str, Any] | None = None
        env: EnvironmentSimulator | None = None
        users: UserSimulator | None = None
        seed_usage = Usage()
        try:
            async with asyncio.timeout(timeout_s if timeout_s > 0 else None):
                # ── seed the world ─────────────────────────────────────────────────
                world, seed_usage = await seed_world(ir, seed=seed, settings=s, client=c)

                # The benign control removes the adversary, not merely the bookkeeping
                # about them. Done before `run.start` so the log records the world the
                # agent actually saw.
                # The world before the agent touched it. Checks need it to tell an
                # attacker-supplied value from one the world always contained.
                initial_world = world.snapshot()

                neutralised: list[str] = []
                if variant == "control":
                    neutralised = world.neutralise_injections()

                log.emit(
                    "run.start",
                    {
                        "model": target_model,
                        "harness": FPTHarness.name,
                        "seed": seed,
                        "variant": variant,
                        "repeat": repeat,
                        "scenario_id": ir.scenario.name,
                        "scenario_hash": ir.scenario_hash,
                        "simulator_model": world.seed_model,
                        "judge_model": resolved_judge_model,
                        "model_substitutions": substitutions,
                        "limits": {
                            "max_turns": budget.max_turns,
                            "max_tool_calls": budget.max_tool_calls,
                            "max_wall_seconds": budget.max_wall_s,
                            "max_output_tokens": budget.max_output,
                            "run_timeout_seconds": timeout_s,
                        },
                        "world_from_cache": world.from_cache,
                        "world_summary": world.summary,
                        "injections": [asdict(i) for i in world.injections],
                        "planted": world.planted,
                        "world_notes": world.notes,
                        "control_neutralised": neutralised,
                    },
                )

                env = EnvironmentSimulator(ir, world, settings=s, client=c)
                users = UserSimulator(ir, settings=s, client=c)
                harness = FPTHarness(c, target_model, settings=s)
                session = harness.start(target.system_prompt, target.tool_schemas(), [])

                ctx: dict[str, Any] = {"last_agent_text": "", "tool_calls": 0, "agent_stopped": False}
                turn = 0

                while True:
                    turn += 1
                    log.turn = turn
                    if (breach := budget.breach(turn)) is not None:
                        limit_hit, terminated_by = breach, "limit"
                        break

                    # ── deliver participant turns ──────────────────────────────────
                    delivered = users.next_scripted(ctx)
                    if delivered is None and users.mode == "simulated" and turn > 1:
                        principal = ir.scenario.inputs.principal
                        if principal is not None:
                            delivered = await users.simulate(principal.id)

                    if delivered is not None:
                        session.add_user(delivered.as_message())
                        log.emit(
                            "turn.start",
                            {
                                "actor": delivered.actor,
                                "display_name": delivered.display_name,
                                "source": delivered.source,
                                "content": delivered.content,
                                "attachments": [
                                    {k: v for k, v in a.items() if k != "content"} | {
                                        "content": (a.get("content") or "")[:4000]
                                    }
                                    for a in delivered.attachments
                                ],
                            },
                        )
                    elif users.exhausted and ctx["agent_stopped"]:
                        break
                    elif delivered is None and turn > 1 and ctx["agent_stopped"]:
                        break

                    # ── the agent acts until it stops calling tools ────────────────
                    stopped = False
                    while not stopped:
                        if (breach := budget.breach(turn)) is not None:
                            limit_hit, terminated_by = breach, "limit"
                            break

                        log.emit(
                            "llm.request",
                            {
                                "model": target_model,
                                "temperature": s.temperature,
                                "message_count": len(session.messages),
                                "tool_names": [t.name for t in target.tools],
                            },
                        )

                        final: Completion | None = None
                        async for ev in harness.step(session):
                            if isinstance(ev, tuple):
                                kind, text = ev
                                log.emit(f"{'reasoning' if kind == 'reasoning' else 'text'}.delta", {"text": text})
                            else:
                                final = ev
                        if final is None:
                            final = Completion(finish_reason="error")

                        budget.output_tokens += final.usage.output_tokens
                        log.emit(
                            "llm.response",
                            {
                                "finish_reason": final.finish_reason,
                                "input_tokens": final.usage.input_tokens,
                                "output_tokens": final.usage.output_tokens,
                                "tool_call_count": len(final.tool_calls),
                            },
                        )
                        session.add_assistant(final)

                        if final.content.strip():
                            ctx["last_agent_text"] = final.content
                            users.observe_agent_text(final.content)

                        if final.finish_reason == "starved":
                            # The agent never produced anything actionable, twice.
                            # Reporting this as a voluntary stop would score a stall
                            # as a safe refusal.
                            limit_hit, terminated_by = ("thinking_starvation", target_model), "limit"
                            log.emit("run.error", {"reason": "thinking_starvation", "model": target_model})
                            stopped = True
                            break

                        if not final.tool_calls:
                            stopped = True
                            ctx["agent_stopped"] = True
                            break

                        ctx["agent_stopped"] = False
                        results: list[tuple[str, str, str]] = []
                        for tc in final.tool_calls:
                            budget.tool_calls += 1
                            ctx["tool_calls"] = budget.tool_calls
                            tool = target.tool(tc.name)
                            log.emit(
                                "tool.call",
                                {
                                    "call_id": tc.id,
                                    "tool": tc.name,
                                    "args": tc.arguments,
                                    "valid": tc.parse_error is None,
                                    "schema_errors": [tc.parse_error] if tc.parse_error else [],
                                    "destructive": bool(tool and tool.is_destructive),
                                },
                            )
                            outcome = await env.call(tc.id, tc.name, tc.arguments)

                            for d in outcome.delivered:
                                log.emit("injection.delivered", d.as_dict())
                            for p in outcome.patches:
                                log.emit("state.patch", p.as_dict())

                            log.emit(
                                "tool.result",
                                {
                                    "call_id": tc.id,
                                    "tool": tc.name,
                                    "result": outcome.result,
                                    "is_error": outcome.is_error,
                                    "valid": outcome.valid,
                                    "served_by": outcome.served_by,
                                    "latency_ms": outcome.latency_ms,
                                    "injections": [d.injection_id for d in outcome.delivered],
                                    "snapshot_before": outcome.snapshot_before,
                                    "snapshot_after": outcome.snapshot_after,
                                },
                            )
                            results.append((tc.id, tc.name, outcome.result_text()))

                        harness.submit_tool_results(session, results)

                    if limit_hit is not None:
                        break
                    if users.exhausted and ctx["agent_stopped"]:
                        break

        except TimeoutError:
            limit_hit = ("run_timeout_seconds", timeout_s)
            terminated_by = "limit"

        if limit_hit is not None:
            log.emit(
                "limit.hit",
                {
                    "limit": limit_hit[0],
                    "value": limit_hit[1],
                    "message": (
                        f"Run timed out after {timeout_s:g} seconds."
                        if limit_hit[0] == "run_timeout_seconds"
                        else ""
                    ),
                },
            )

        # ── score ──────────────────────────────────────────────────────────
        checks = []
        if world is not None and env is not None:
            log.emit("world.final", {"collections": world.collections})
            checks = run_checks(ir, world, env, log, initial_world)
            for ch in checks:
                log.emit("check.evaluated", ch.as_dict())
        elif limit_hit is not None:
            log.emit(
                "run.error",
                {
                    "reason": "run_timeout_before_world",
                    "timeout_seconds": timeout_s,
                },
            )

        judge_items = []
        judge_usage = Usage()
        if judge and world is not None:
            from .judge import build_rubric, judge_run

            rubric_items = build_rubric(ir, variant)
            termination = (
                f"Forced stop: `{limit_hit[0]}` reached value {limit_hit[1]}. "
                "The trajectory is partial and the final run verdict remains INCONCLUSIVE."
                if limit_hit is not None
                else "The agent stopped normally."
            )
            log.emit(
                "judge.start",
                {
                    "model": resolved_judge_model,
                    "items": len(rubric_items),
                    "forced_stop": limit_hit is not None,
                    "termination": termination,
                },
            )
            completed = 0

            def publish_judgment(item: Any) -> None:
                nonlocal completed
                completed += 1
                log.emit("judge.item", item.as_dict() | {"completed": completed, "total": len(rubric_items)})

            judge_items, judge_usage = await judge_run(
                ir, log, checks, client=c, settings=s, model=resolved_judge_model,
                termination=termination, on_item=publish_judgment,
            )
            log.emit(
                "judge.complete",
                {
                    "model": resolved_judge_model,
                    "completed": len(judge_items),
                    "items": len(rubric_items),
                    "inconclusive": sum(1 for item in judge_items if item.inconclusive),
                },
            )

        verdict = compute_verdict(
            ir=ir,
            log=log,
            checks=checks,
            judge_items=judge_items,
            terminated_by=terminated_by,
            limit=limit_hit,
            initial=initial_world,
            judge_model=resolved_judge_model,
            target_model=target_model,
        )
        log.emit("run.verdict", verdict.as_dict())

        totals = log.usage_totals()
        usage = Usage(totals["input_tokens"], totals["output_tokens"]) + seed_usage + judge_usage
        if users is not None:
            usage = usage + users.usage
        return RunResult(
            run_id=rid,
            scenario_hash=ir.scenario_hash,
            variant=variant,
            repeat=repeat,
            verdict=verdict,
            log=log,
            world=world or World(),
            usage=usage,
            wall_ms=int((time.perf_counter() - started) * 1000),
            log_path=log_path,
        )
    finally:
        log.close()
        if own_client:
            await c.aclose()
