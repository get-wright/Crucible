"""Event log — one JSONL file per run.

Aligned to the OpenTelemetry GenAI semantic conventions so runs drop into an
existing tracing backend (PLATFORM_PLAN §4.1). Every event shares an envelope
and carries a monotonic `seq`, which is the coordinate everything else cites:
`first_compromise.seq`, judge citations, and the replay cursor all refer to it.

Deltas are stored raw *and* rolled up into a `messages[]` view. Both are kept
on purpose — the rollup is what a human reads, the deltas are what let you
point at the exact token where the agent's plan changed.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EventType = str


@dataclass(slots=True)
class Event:
    run_id: str
    scenario_hash: str
    variant: str
    repeat: int
    seq: int
    ts: str
    turn: int
    type: EventType
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_hash": self.scenario_hash,
            "variant": self.variant,
            "repeat": self.repeat,
            "seq": self.seq,
            "ts": self.ts,
            "turn": self.turn,
            "type": self.type,
            "data": self.data,
        }


class EventLog:
    """Append-only event sink. Writes JSONL and keeps events in memory.

    Both are needed: the file is the durable artifact and the replay source,
    the in-memory list is what the judge and the checks read without a second
    pass over disk. Runs are small enough (thousands of events) that holding
    them costs less than re-parsing.
    """

    def __init__(
        self,
        *,
        run_id: str,
        scenario_hash: str,
        variant: str = "attack",
        repeat: int = 0,
        path: Path | None = None,
    ):
        self.run_id = run_id
        self.scenario_hash = scenario_hash
        self.variant = variant
        self.repeat = repeat
        self.path = path
        self.events: list[Event] = []
        self.turn = 0
        self._seq = 0
        self._lock = threading.Lock()
        self._fh = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = path.open("w", encoding="utf-8")
        #: Optional live subscriber, used by the SSE endpoint.
        self.on_event = None

    def emit(self, type: EventType, data: dict[str, Any] | None = None) -> Event:
        with self._lock:
            self._seq += 1
            ev = Event(
                run_id=self.run_id,
                scenario_hash=self.scenario_hash,
                variant=self.variant,
                repeat=self.repeat,
                seq=self._seq,
                ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                turn=self.turn,
                type=type,
                data=data or {},
            )
            self.events.append(ev)
            if self._fh is not None:
                self._fh.write(json.dumps(ev.as_dict(), ensure_ascii=False, default=str) + "\n")
                self._fh.flush()
        if self.on_event is not None:
            try:
                self.on_event(ev)
            except Exception:
                # A broken subscriber must never take down a run.
                pass
        return ev

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "EventLog":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- views ---------------------------------------------------------------

    def of_type(self, *types: str) -> list[Event]:
        wanted = set(types)
        return [e for e in self.events if e.type in wanted]

    def messages(self) -> list[dict[str, Any]]:
        """Deltas rolled up into readable turns, for the trajectory UI.

        Consecutive reasoning/text deltas collapse into one block; tool calls
        and their results pair up by `call_id`.
        """
        out: list[dict[str, Any]] = []
        buf: dict[str, Any] | None = None

        def flush() -> None:
            nonlocal buf
            if buf and buf.get("text", "").strip():
                out.append(buf)
            buf = None

        results = {
            e.data.get("call_id"): e.data
            for e in self.events
            if e.type == "tool.result"
        }

        for e in self.events:
            if e.type in ("reasoning.delta", "text.delta"):
                kind = "reasoning" if e.type == "reasoning.delta" else "text"
                if buf is None or buf["kind"] != kind:
                    flush()
                    buf = {"kind": kind, "seq": e.seq, "turn": e.turn, "text": ""}
                buf["text"] += e.data.get("text", "")
                continue
            flush()
            if e.type == "turn.start":
                out.append({
                    "kind": "participant",
                    "seq": e.seq, "turn": e.turn,
                    "actor": e.data.get("actor"),
                    "display_name": e.data.get("display_name"),
                    "source": e.data.get("source"),
                    "text": e.data.get("content", ""),
                    "attachments": e.data.get("attachments") or [],
                })
            elif e.type == "tool.call":
                res = results.get(e.data.get("call_id")) or {}
                out.append({
                    "kind": "tool",
                    "seq": e.seq, "turn": e.turn,
                    "call_id": e.data.get("call_id"),
                    "tool": e.data.get("tool"),
                    "args": e.data.get("args"),
                    "valid": e.data.get("valid", True),
                    "schema_errors": e.data.get("schema_errors") or [],
                    "destructive": e.data.get("destructive", False),
                    "result": res.get("result"),
                    "is_error": res.get("is_error", False),
                    "served_by": res.get("served_by"),
                    "latency_ms": res.get("latency_ms"),
                    "injections": res.get("injections") or [],
                })
            elif e.type == "injection.delivered":
                out.append({"kind": "injection", "seq": e.seq, "turn": e.turn, **e.data})
            elif e.type == "state.patch":
                # A world mutation belongs in the trajectory a human reads:
                # "PR #47 state: open -> merged" is the moment the damage
                # landed, and showing only the call that caused it leaves the
                # reader to infer the effect.
                out.append({"kind": "patch", "seq": e.seq, "turn": e.turn, **e.data})
            elif e.type in ("limit.hit", "run.error", "egress.denied"):
                out.append({"kind": "notice", "seq": e.seq, "turn": e.turn, "type": e.type, **e.data})
            elif e.type in ("judge.start", "judge.complete"):
                out.append({"kind": "judge_status", "seq": e.seq, "turn": e.turn, "type": e.type, **e.data})
            elif e.type == "judge.item":
                out.append({"kind": "judge", "seq": e.seq, "turn": e.turn, **e.data})
        flush()
        return out

    def usage_totals(self) -> dict[str, int]:
        inp = out = 0
        for e in self.of_type("llm.response"):
            inp += int(e.data.get("input_tokens") or 0)
            out += int(e.data.get("output_tokens") or 0)
        return {"input_tokens": inp, "output_tokens": out}


def read_log(path: Path) -> Iterator[dict[str, Any]]:
    """Stream a persisted run back, for replay."""
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)
