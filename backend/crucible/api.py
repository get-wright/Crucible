"""HTTP API — FastAPI, backing the three screens in the mockup.

    New     POST /taxonomy-driven dropdowns, generate, validate-as-you-type
    Run     POST /suites then GET /suites/{id}/stream for live trajectory
    Result  GET  /suites/{id} — verdict, judge items, k-run reliability strip

Two decisions:

**Validation is its own endpoint.** The editor calls `POST /scenarios/validate`
on every pause and renders findings inline against line numbers. Both
authoring paths — generated and hand-written — share it, which is what makes
them genuinely equal rather than one being the real path.

**Runs stream over SSE, and the stream survives reconnection** because events
are also buffered per suite. A trajectory that only exists in a live socket is
lost on a page refresh, which is exactly when a user most wants it back.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from ulid import ULID

from .config import FPT_MODELS, get_settings
from .events import Event, read_log
from .generate import generate_scenario
from .orchestrator import run_suite
from .overrides import OverrideError, apply_overrides
from .store import Store
from .patterns import catalog as pattern_catalog
from .taxonomy import VOCABULARIES, ui_schema
from .validate import validate_source

settings = get_settings()
store = Store(settings)

#: suite_id -> live event buffer + subscriber queues.
_streams: dict[str, "_Stream"] = {}


class _Stream:
    """Per-suite fan-out with replay.

    Buffering as well as broadcasting is what lets a reconnecting client catch
    up instead of joining mid-trajectory with no context.
    """

    def __init__(self, limit: int = 20000):
        self.buffer: list[dict[str, Any]] = []
        self.limit = limit
        self.subscribers: set[asyncio.Queue] = set()
        self.done = False

    def publish(self, payload: dict[str, Any]) -> None:
        self.buffer.append(payload)
        if len(self.buffer) > self.limit:
            del self.buffer[: len(self.buffer) - self.limit]
        for q in list(self.subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    def finish(self) -> None:
        self.done = True
        self.publish({"type": "suite.done"})


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_dirs()
    yield


app = FastAPI(
    title="Crucible",
    version="0.1.0",
    description="Adversarial agent scenario benchmark",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── models ─────────────────────────────────────────────────────────────────


class GenerateRequest(BaseModel):
    tags: dict[str, Any]
    brief: str = Field(min_length=1)
    model: str | None = None
    judge_model: str | None = None
    repeats: int = 10
    max_turns: int = 16
    variation_seed: str | None = None
    pattern: str | None = None
    critique: bool = True
    save: bool = True


class ValidateRequest(BaseModel):
    yaml: str


class SaveScenarioRequest(BaseModel):
    yaml: str
    name: str | None = None
    origin: str = "authored"
    brief: str = ""


class RunRequest(BaseModel):
    scenario_id: str | None = None
    yaml: str | None = None
    model: str | None = None
    repeats: int | None = None
    control: bool = False
    seed: int = 0
    concurrency: int = 4
    judge: bool = True
    #: `path=value` assignments applied before validation, e.g.
    #: ["scenario.model=GLM-5.2"]. Changes the scenario hash.
    overrides: list[str] = Field(default_factory=list)


# ── meta ───────────────────────────────────────────────────────────────────


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "offline": settings.is_offline,
        "provider": settings.fpt_base_url,
        "models": {
            "target": settings.target_model,
            "judge": settings.judge_model,
            "simulator": settings.simulator_model,
            "generator": settings.generator_model,
        },
    }


@app.get("/taxonomy")
def taxonomy() -> dict[str, Any]:
    """Everything the authoring screen needs to build its dropdowns."""
    return {
        "fields": ui_schema(),
        "models": FPT_MODELS,
        "vocabularies": VOCABULARIES,
        "attack_patterns": pattern_catalog(),
    }


@app.get("/rubric")
def rubric_catalog() -> dict[str, Any]:
    """Every criterion the judge can ask, for the authoring screen."""
    from .rubric import load_dimensions

    dims = load_dimensions()
    return {
        "dimensions": [
            {
                "id": d.id, "axis": d.axis, "want": d.want, "weight": d.weight,
                "applies_to": d.applies_to, "requires": d.requires,
                "category": d.category, "version": d.version, "source": d.source,
                "question": d.question,
            }
            for d in sorted(dims.values(), key=lambda d: (d.axis, d.id))
        ]
    }


@app.post("/scenarios/rubric")
def rubric_for(req: ValidateRequest) -> dict[str, Any]:
    """The criteria a given scenario would actually be graded on."""
    from .judge import rubric_version
    from .rubric import resolve

    result = validate_source(req.yaml)
    if result.ir is None:
        raise HTTPException(422, {"validation": result.as_dict()})
    out: dict[str, Any] = {}
    for variant in ("attack", "control"):
        dims, notes = resolve(result.ir, variant=variant)
        out[variant] = {
            "version": rubric_version(result.ir, variant),
            "criteria": [
                {"id": d.id, "axis": d.axis, "want": d.want, "weight": d.weight,
                 "source": d.source}
                for d in dims
            ],
            "notes": notes,
        }
    return out


# ── authoring ──────────────────────────────────────────────────────────────


@app.post("/scenarios/validate")
def validate(req: ValidateRequest) -> dict[str, Any]:
    """Parse + validate. Every finding carries a line number."""
    return validate_source(req.yaml).as_dict()


@app.post("/scenarios/generate")
async def generate(req: GenerateRequest) -> dict[str, Any]:
    unknown = {
        f: v for f, v in req.tags.items()
        if f in VOCABULARIES and v not in VOCABULARIES[f]
    }
    if unknown:
        raise HTTPException(422, f"tag values outside their vocabulary: {unknown}")

    try:
        result = await generate_scenario(
            tags=req.tags, brief=req.brief, settings=settings,
            model=req.model, judge_model=req.judge_model,
            repeats=req.repeats, max_turns=req.max_turns,
            variation_seed=req.variation_seed, pattern=req.pattern, critique=req.critique,
        )
    except Exception as e:
        raise HTTPException(502, f"generation failed: {type(e).__name__}: {e}") from e

    payload = result.as_dict()
    # A draft with findings is still saved. The user is meant to edit it, and
    # an unsaved draft that vanishes on a failed validation is worse than a
    # saved one with a visible problem list.
    if req.save and result.ir is not None:
        sid = f"scn_{ULID()}"
        store.save_scenario(
            scenario_id=sid,
            scenario_hash=result.validation.scenario_hash,
            name=result.ir.scenario.name or "Untitled",
            yaml_text=result.yaml,
            tags=result.ir.scenario.tags,
            model=result.ir.scenario.model,
            judge_model=result.ir.scenario.judge_model or "",
            origin="generated",
            brief=req.brief,
            valid=result.validation.ok,
            findings=[f.as_dict() for f in result.validation.findings],
        )
        payload["scenario_id"] = sid
    return payload


@app.post("/scenarios")
def save_scenario(req: SaveScenarioRequest) -> dict[str, Any]:
    result = validate_source(req.yaml)
    if result.ir is None:
        raise HTTPException(422, {"validation": result.as_dict()})
    sid = f"scn_{ULID()}"
    row = store.save_scenario(
        scenario_id=sid,
        scenario_hash=result.scenario_hash,
        name=req.name or result.ir.scenario.name or "Untitled",
        yaml_text=req.yaml,
        tags=result.ir.scenario.tags,
        model=result.ir.scenario.model,
        judge_model=result.ir.scenario.judge_model or "",
        origin=req.origin,
        brief=req.brief,
        valid=result.ok,
        findings=[f.as_dict() for f in result.findings],
    )
    return {"scenario": row, "validation": result.as_dict()}


@app.get("/scenarios")
def list_scenarios(
    limit: int = 100,
    industry: str | None = None,
    domain: str | None = None,
    attack_pattern: str | None = None,
    attacker_goal: str | None = None,
    violation_type: str | None = None,
    owasp_llm: str | None = None,
    owasp_agentic: str | None = None,
    testing_platform: str | None = None,
) -> dict[str, Any]:
    """The scenario library, filterable by taxonomy facet.

    Filters are declared one by one rather than swept up with `**kwargs`:
    FastAPI derives the query schema from the signature, so a catch-all
    produces a route with no documented parameters that silently ignores
    every filter it is given.
    """
    filters = {
        k: v
        for k, v in {
            "industry": industry, "domain": domain,
            "attack_pattern": attack_pattern, "attacker_goal": attacker_goal,
            "violation_type": violation_type, "owasp_llm": owasp_llm,
            "owasp_agentic": owasp_agentic, "testing_platform": testing_platform,
        }.items()
        if v
    }
    return {"scenarios": store.list_scenarios(tag_filters=filters, limit=limit)}


@app.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str) -> dict[str, Any]:
    row = store.get_scenario(scenario_id)
    if row is None:
        raise HTTPException(404, "no such scenario")
    return row


@app.put("/scenarios/{scenario_id}")
def update_scenario(scenario_id: str, req: SaveScenarioRequest) -> dict[str, Any]:
    existing = store.get_scenario(scenario_id)
    if existing is None:
        raise HTTPException(404, "no such scenario")
    result = validate_source(req.yaml)
    if result.ir is None:
        raise HTTPException(422, {"validation": result.as_dict()})
    row = store.save_scenario(
        scenario_id=scenario_id,
        scenario_hash=result.scenario_hash,
        name=req.name or result.ir.scenario.name or existing["name"],
        yaml_text=req.yaml,
        tags=result.ir.scenario.tags,
        model=result.ir.scenario.model,
        judge_model=result.ir.scenario.judge_model or "",
        origin=existing["origin"],
        brief=existing.get("brief") or "",
        valid=result.ok,
        findings=[f.as_dict() for f in result.findings],
    )
    return {"scenario": row, "validation": result.as_dict()}


@app.delete("/scenarios/{scenario_id}")
def delete_scenario(scenario_id: str) -> dict[str, Any]:
    if not store.delete_scenario(scenario_id):
        raise HTTPException(404, "no such scenario")
    return {"deleted": scenario_id}


# ── running ────────────────────────────────────────────────────────────────


@app.post("/suites")
async def start_suite(req: RunRequest, background: BackgroundTasks) -> dict[str, Any]:
    """Queue a suite. Returns immediately; watch it via the stream endpoint."""
    if req.yaml:
        text, scenario_id = req.yaml, ""
    elif req.scenario_id:
        row = store.get_scenario(req.scenario_id)
        if row is None:
            raise HTTPException(404, "no such scenario")
        text, scenario_id = row["yaml"], req.scenario_id
    else:
        raise HTTPException(422, "provide either `scenario_id` or `yaml`")

    try:
        text, _ = apply_overrides(text, req.overrides)
    except OverrideError as e:
        raise HTTPException(422, f"bad override: {e}") from e
    result = validate_source(text)

    if not result.ok or result.ir is None:
        raise HTTPException(422, {"validation": result.as_dict()})

    ir = result.ir
    suite_id = f"suite_{ULID()}"
    stream = _Stream()
    _streams[suite_id] = stream

    def publish_event(ev: Event) -> None:
        stream.publish({"type": "event", "event": ev.as_dict()})

    def publish_run(r: Any) -> None:
        stream.publish({"type": "run.complete", "run": r.as_dict()})

    async def go() -> None:
        try:
            suite = await run_suite(
                ir,
                repeats=req.repeats,
                control=req.control,
                seed=req.seed,
                model=req.model,
                settings=settings,
                concurrency=req.concurrency,
                judge=req.judge,
                store=store,
                scenario_id=scenario_id,
                suite_id=suite_id,
                on_run_complete=publish_run,
                on_event=publish_event,
            )
            stream.publish({"type": "metrics", "metrics": suite.metrics.as_dict()})
        except Exception as e:
            store.update_suite(suite_id, status="failed", error=f"{type(e).__name__}: {e}")
            stream.publish({"type": "error", "message": f"{type(e).__name__}: {e}"})
        finally:
            stream.finish()

    background.add_task(go)
    return {
        "suite_id": suite_id,
        "scenario_hash": ir.scenario_hash,
        "scenario_name": ir.scenario.name,
        "model": req.model or ir.scenario.model or settings.target_model,
        "repeats": req.repeats if req.repeats is not None else ir.scenario.repeats,
        "control": req.control,
        "stream": f"/suites/{suite_id}/stream",
    }


@app.get("/suites")
def list_suites(scenario_id: str | None = None, limit: int = 50) -> dict[str, Any]:
    return {"suites": store.list_suites(scenario_id=scenario_id, limit=limit)}


@app.get("/suites/{suite_id}")
def get_suite(suite_id: str) -> dict[str, Any]:
    row = store.get_suite(suite_id)
    if row is None:
        raise HTTPException(404, "no such suite")
    row["live"] = suite_id in _streams and not _streams[suite_id].done
    return row


@app.get("/suites/{suite_id}/stream")
async def stream_suite(suite_id: str, replay: bool = True) -> StreamingResponse:
    """Server-sent events for a running suite, with replay from the buffer."""
    stream = _streams.get(suite_id)
    if stream is None:
        raise HTTPException(404, "no such suite, or its stream has been reclaimed")

    async def gen():
        q: asyncio.Queue = asyncio.Queue(maxsize=4096)
        backlog = list(stream.buffer) if replay else []
        stream.subscribers.add(q)
        try:
            for payload in backlog:
                yield f"data: {json.dumps(payload, default=str)}\n\n"
            if stream.done:
                yield 'data: {"type": "suite.done"}\n\n'
                return
            while True:
                try:
                    payload = await asyncio.wait_for(q.get(), timeout=15)
                except asyncio.TimeoutError:
                    # Keep-alive: proxies drop an idle SSE connection, and a
                    # long judge phase is exactly when the stream goes quiet.
                    yield ": keep-alive\n\n"
                    continue
                yield f"data: {json.dumps(payload, default=str)}\n\n"
                if payload.get("type") == "suite.done":
                    return
        finally:
            stream.subscribers.discard(q)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── results ────────────────────────────────────────────────────────────────


@app.get("/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    row = store.get_run(run_id)
    if row is None:
        raise HTTPException(404, "no such run")
    return row


@app.get("/runs/{run_id}/trajectory")
def get_trajectory(run_id: str, raw: bool = False) -> dict[str, Any]:
    """The replayable trajectory: rolled-up messages, or raw events."""
    row = store.get_run(run_id)
    if row is None or not row.get("log_path"):
        raise HTTPException(404, "no such run, or its log was not persisted")
    from pathlib import Path

    path = Path(row["log_path"])
    if not path.exists():
        raise HTTPException(410, "the event log for this run is no longer on disk")

    events = list(read_log(path))
    if raw:
        return {"run_id": run_id, "events": events}

    # Rebuild the rollup from the persisted log rather than keeping the live
    # EventLog around, so replay works identically after a restart.
    from .events import EventLog

    log = EventLog(run_id=run_id, scenario_hash=row["scenario_hash"], variant=row["variant"])
    for e in events:
        log.turn = e.get("turn", 0)
        log.emit(e["type"], e.get("data") or {})
    return {
        "run_id": run_id,
        "verdict": row["verdict"],
        "first_compromise": row["first_compromise"],
        "messages": log.messages(),
    }


@app.get("/comparison")
def comparison(scenario_hash: str = Query(..., min_length=8)) -> dict[str, Any]:
    """Model-vs-model attack success for one scenario."""
    return {"scenario_hash": scenario_hash, "models": store.comparison(scenario_hash)}
