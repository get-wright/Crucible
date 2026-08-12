"""Orchestrator — PLATFORM_PLAN §2.3.

Expands one scenario into `repeats` runs (× 2 when a benign control variant is
requested), fans them out, collects results. Runs are independent, so this is
embarrassingly parallel and is the reason a whole suite finishes in minutes
rather than serially.

Concurrency is bounded rather than unbounded: the provider rate-limits, and
twenty simultaneous runs mostly produce twenty retries. One shared client
across the fan-out reuses connections, which matters more than it sounds when
each run opens dozens.

A failed run becomes an INCONCLUSIVE result rather than an exception. One bad
run out of ten should cost one data point, not the suite.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from ulid import ULID

from .config import Settings, get_settings, resolve_model
from .events import EventLog
from .ir import ScenarioIR
from .llm import make_client
from .metrics import Metrics, compute_metrics
from .runner import RunResult, execute_run
from .store import Store
from .verdict import INCONCLUSIVE, Verdict


@dataclass
class SuiteResult:
    suite_id: str
    scenario_hash: str
    model: str
    runs: list[RunResult] = field(default_factory=list)
    metrics: Metrics = field(default_factory=Metrics)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "scenario_hash": self.scenario_hash,
            "model": self.model,
            "runs": [r.as_dict() for r in self.runs],
            "metrics": self.metrics.as_dict(),
            "errors": self.errors,
        }


def _failed_result(
    ir: ScenarioIR, variant: str, repeat: int, error: str
) -> RunResult:
    """A run that could not execute, expressed as a normal INCONCLUSIVE row."""
    rid = f"run_{ULID()}"
    log = EventLog(run_id=rid, scenario_hash=ir.scenario_hash, variant=variant, repeat=repeat)
    log.emit("run.error", {"error": error[:500]})
    from .world import World  # local import: only needed on this path

    return RunResult(
        run_id=rid,
        scenario_hash=ir.scenario_hash,
        variant=variant,
        repeat=repeat,
        verdict=Verdict(
            run_id=rid,
            verdict=INCONCLUSIVE,
            terminated_by="error",
            rationale=f"The run failed to execute: {error[:300]}",
        ),
        log=log,
        world=World(),
    )


async def run_suite(
    ir: ScenarioIR,
    *,
    repeats: int | None = None,
    control: bool = False,
    seed: int = 0,
    model: str | None = None,
    settings: Settings | None = None,
    concurrency: int = 4,
    judge: bool = True,
    store: Store | None = None,
    scenario_id: str = "",
    suite_id: str | None = None,
    on_run_complete: Any = None,
    on_event: Any = None,
) -> SuiteResult:
    """Run `k` repeats (and optionally a control variant) and aggregate."""
    s = settings or get_settings()
    k = repeats if repeats is not None else ir.scenario.repeats
    k = max(1, k)
    sid = suite_id or f"suite_{ULID()}"
    target_model, _ = resolve_model(model or ir.scenario.model, s.target_model)
    judge_model, _ = resolve_model(ir.scenario.judge_model or "", s.judge_model)

    variants = ["attack"] + (["control"] if control else [])
    jobs = [(v, i) for v in variants for i in range(k)]

    if store is not None:
        store.create_suite(
            suite_id=sid, scenario_id=scenario_id, scenario_hash=ir.scenario_hash,
            model=target_model, judge_model=judge_model, repeats=k, control=control,
        )
        store.update_suite(sid, status="running")

    result = SuiteResult(suite_id=sid, scenario_hash=ir.scenario_hash, model=target_model)
    sem = asyncio.Semaphore(max(1, concurrency))
    client = make_client(s)

    async def one(variant: str, repeat: int) -> RunResult:
        async with sem:
            try:
                # Every repeat shares the same world seed on purpose: the
                # world is fixed and only the agent varies, which is what
                # makes pass^k a measurement of the agent rather than of the
                # environment generator.
                r = await execute_run(
                    ir, variant=variant, repeat=repeat, seed=seed,
                    settings=s, client=client, model=target_model,
                    judge=judge, on_event=on_event,
                )
            except Exception as e:
                r = _failed_result(ir, variant, repeat, f"{type(e).__name__}: {e}")
                result.errors.append(f"{variant}#{repeat}: {type(e).__name__}: {e}")

            if store is not None:
                try:
                    store.save_run(
                        r, suite_id=sid, scenario_id=scenario_id, model=target_model,
                        judge_model=judge_model,
                        simulator_model=r.world.seed_model, seed=seed,
                    )
                except Exception as e:  # persistence must not sink a suite
                    result.errors.append(f"store: {type(e).__name__}: {e}")
            if on_run_complete is not None:
                try:
                    on_run_complete(r)
                except Exception:
                    pass
            return r

    try:
        result.runs = list(await asyncio.gather(*(one(v, i) for v, i in jobs)))
    finally:
        await client.aclose()

    result.metrics = compute_metrics(
        [(r.variant, r.verdict) for r in result.runs],
        scenario_hash=ir.scenario_hash,
        model=target_model,
    )
    if store is not None:
        store.update_suite(
            sid,
            status="completed",
            metrics=result.metrics.as_dict(),
            error="; ".join(result.errors[:5]) if result.errors else None,
        )
    return result
