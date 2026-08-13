"""Persistence — SQLite for the structured rows, files for the trajectories.

The split follows PLATFORM_PLAN §7: query the small structured stuff, never
put megabyte trajectories in a row. Event logs live as JSONL under
`data/runs/`; SQLite holds scenarios, runs, verdicts and suite rollups.

Every result row carries `scenario_hash`, the target model, the judge model,
and the simulator model. That is not bookkeeping — a judge upgrade silently
reprices an entire historical dataset, so a result whose judge version is
unknown cannot be compared with one whose is.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings, get_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scenarios (
  id             TEXT PRIMARY KEY,
  scenario_hash  TEXT NOT NULL,
  name           TEXT NOT NULL,
  yaml           TEXT NOT NULL,
  tags           TEXT NOT NULL DEFAULT '{}',
  model          TEXT,
  judge_model    TEXT,
  origin         TEXT NOT NULL DEFAULT 'authored',
  brief          TEXT,
  valid          INTEGER NOT NULL DEFAULT 1,
  findings       TEXT NOT NULL DEFAULT '[]',
  path           TEXT,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scenarios_hash ON scenarios(scenario_hash);

CREATE TABLE IF NOT EXISTS suites (
  id             TEXT PRIMARY KEY,
  scenario_id    TEXT NOT NULL,
  scenario_hash  TEXT NOT NULL,
  model          TEXT NOT NULL,
  judge_model    TEXT,
  repeats        INTEGER NOT NULL,
  control        INTEGER NOT NULL DEFAULT 0,
  status         TEXT NOT NULL DEFAULT 'queued',
  metrics        TEXT NOT NULL DEFAULT '{}',
  error          TEXT,
  created_at     TEXT NOT NULL,
  finished_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_suites_scenario ON suites(scenario_id);

CREATE TABLE IF NOT EXISTS runs (
  run_id           TEXT PRIMARY KEY,
  suite_id         TEXT,
  scenario_id      TEXT,
  scenario_hash    TEXT NOT NULL,
  variant          TEXT NOT NULL,
  repeat           INTEGER NOT NULL,
  seed             INTEGER NOT NULL DEFAULT 0,
  model            TEXT NOT NULL,
  judge_model      TEXT,
  simulator_model  TEXT,
  verdict          TEXT,
  rationale        TEXT,
  first_compromise TEXT,
  axes             TEXT NOT NULL DEFAULT '{}',
  judge            TEXT NOT NULL DEFAULT '{}',
  usage            TEXT NOT NULL DEFAULT '{}',
  wall_ms          INTEGER NOT NULL DEFAULT 0,
  log_path         TEXT,
  created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_suite ON runs(suite_id);
CREATE INDEX IF NOT EXISTS idx_runs_hash ON runs(scenario_hash, model);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


#: Columns added after the first release. `CREATE TABLE IF NOT EXISTS` does
#: nothing to a table that already exists, so a database made by an older build
#: keeps its old shape until it is widened here.
_ADDED_COLUMNS = (("scenarios", "path", "TEXT"),)


def _migrate(c: sqlite3.Connection) -> None:
    for table, column, decl in _ADDED_COLUMNS:
        present = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
        if column not in present:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


class Store:
    def __init__(self, settings: Settings | None = None, path: Path | None = None):
        self.s = settings or get_settings()
        self.path = path or self.s.db_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        with self._conn() as c:
            c.executescript(SCHEMA)
            _migrate(c)

    def _conn(self) -> sqlite3.Connection:
        # One connection per thread: SQLite objects are not shareable across
        # threads, and the API serves requests from a pool.
        conn = getattr(self._local, "conn", None)
        if conn is None:
            try:
                conn = self._open()
            except sqlite3.OperationalError:
                # A `-wal`/`-shm` pair left behind by a removed or truncated
                # database makes every open fail with a bare "disk I/O error".
                # The sidecars are worthless without their database, so clear
                # them and retry rather than leaving the process unable to
                # start over a file nobody wants.
                for suffix in ("-wal", "-shm"):
                    sidecar = self.path.with_name(self.path.name + suffix)
                    if sidecar.exists() and not self.path.exists():
                        sidecar.unlink()
                conn = self._open()
            self._local.conn = conn
        return conn

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # -- scenarios -----------------------------------------------------------

    def save_scenario(
        self,
        *,
        scenario_id: str,
        scenario_hash: str,
        name: str,
        yaml_text: str,
        tags: dict[str, Any],
        model: str = "",
        judge_model: str = "",
        origin: str = "authored",
        brief: str = "",
        valid: bool = True,
        findings: list[dict[str, Any]] | None = None,
        path: str = "",
    ) -> dict[str, Any]:
        now = _now()
        with self._conn() as c:
            c.execute(
                """INSERT INTO scenarios
                   (id, scenario_hash, name, yaml, tags, model, judge_model, origin,
                    brief, valid, findings, path, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     scenario_hash=excluded.scenario_hash, name=excluded.name,
                     yaml=excluded.yaml, tags=excluded.tags, model=excluded.model,
                     judge_model=excluded.judge_model, valid=excluded.valid,
                     findings=excluded.findings, updated_at=excluded.updated_at,
                     -- An update that did not write a file keeps the file the
                     -- row already points at, rather than forgetting it.
                     path=COALESCE(NULLIF(excluded.path, ''), scenarios.path)""",
                (
                    scenario_id, scenario_hash, name, yaml_text, json.dumps(tags),
                    model, judge_model, origin, brief, int(valid),
                    json.dumps(findings or []), path, now, now,
                ),
            )
        return self.get_scenario(scenario_id) or {}

    def get_scenario(self, scenario_id: str) -> dict[str, Any] | None:
        row = self._conn().execute(
            "SELECT * FROM scenarios WHERE id = ?", (scenario_id,)
        ).fetchone()
        return _scenario_row(row) if row else None

    def list_scenarios(
        self, *, tag_filters: dict[str, str] | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM scenarios ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        out = [_scenario_row(r) for r in rows]
        # Tag filtering in Python rather than SQL: the tag map is a JSON blob,
        # and a library of a few thousand scenarios does not justify either a
        # join table or SQLite's JSON1 syntax spread across the query layer.
        for field, value in (tag_filters or {}).items():
            out = [s for s in out if s["tags"].get(field) == value]
        return out

    def delete_scenario(self, scenario_id: str) -> bool:
        with self._conn() as c:
            return c.execute("DELETE FROM scenarios WHERE id = ?", (scenario_id,)).rowcount > 0

    # -- suites --------------------------------------------------------------

    def create_suite(
        self,
        *,
        suite_id: str,
        scenario_id: str,
        scenario_hash: str,
        model: str,
        judge_model: str,
        repeats: int,
        control: bool,
    ) -> None:
        with self._conn() as c:
            c.execute(
                """INSERT INTO suites
                   (id, scenario_id, scenario_hash, model, judge_model, repeats,
                    control, status, created_at)
                   VALUES (?,?,?,?,?,?,?,'queued',?)""",
                (suite_id, scenario_id, scenario_hash, model, judge_model,
                 repeats, int(control), _now()),
            )

    def update_suite(
        self,
        suite_id: str,
        *,
        status: str | None = None,
        metrics: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        sets, params = [], []
        if status is not None:
            sets.append("status = ?")
            params.append(status)
            if status in ("completed", "failed"):
                sets.append("finished_at = ?")
                params.append(_now())
        if metrics is not None:
            sets.append("metrics = ?")
            params.append(json.dumps(metrics))
        if error is not None:
            sets.append("error = ?")
            params.append(error[:2000])
        if not sets:
            return
        params.append(suite_id)
        with self._conn() as c:
            c.execute(f"UPDATE suites SET {', '.join(sets)} WHERE id = ?", params)

    def get_suite(self, suite_id: str) -> dict[str, Any] | None:
        row = self._conn().execute("SELECT * FROM suites WHERE id = ?", (suite_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["metrics"] = json.loads(d.get("metrics") or "{}")
        d["control"] = bool(d.get("control"))
        d["runs"] = self.list_runs(suite_id=suite_id)
        return d

    def list_suites(self, *, scenario_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        if scenario_id:
            rows = self._conn().execute(
                "SELECT * FROM suites WHERE scenario_id = ? ORDER BY created_at DESC LIMIT ?",
                (scenario_id, limit),
            ).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT * FROM suites ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["metrics"] = json.loads(d.get("metrics") or "{}")
            d["control"] = bool(d.get("control"))
            out.append(d)
        return out

    # -- runs ----------------------------------------------------------------

    def save_run(
        self,
        result: Any,
        *,
        suite_id: str = "",
        scenario_id: str = "",
        model: str = "",
        judge_model: str = "",
        simulator_model: str = "",
        seed: int = 0,
    ) -> None:
        v = result.verdict
        with self._conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO runs
                   (run_id, suite_id, scenario_id, scenario_hash, variant, repeat, seed,
                    model, judge_model, simulator_model, verdict, rationale,
                    first_compromise, axes, judge, usage, wall_ms, log_path, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    result.run_id, suite_id or None, scenario_id or None,
                    result.scenario_hash, result.variant, result.repeat, seed,
                    model, judge_model, simulator_model,
                    v.verdict, v.rationale,
                    json.dumps(v.first_compromise) if v.first_compromise else None,
                    json.dumps({k: a.as_dict() for k, a in v.axes.items()}),
                    json.dumps(v.judge), json.dumps(v.usage),
                    result.wall_ms, str(result.log_path) if result.log_path else None,
                    _now(),
                ),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn().execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return _run_row(row) if row else None

    def list_runs(
        self, *, suite_id: str = "", limit: int = 200, offset: int = 0
    ) -> list[dict[str, Any]]:
        if suite_id:
            rows = self._conn().execute(
                "SELECT runs.* FROM runs WHERE suite_id = ? ORDER BY repeat, variant LIMIT ? OFFSET ?",
                (suite_id, limit, offset),
            ).fetchall()
        else:
            rows = self._conn().execute(
                """SELECT runs.*, scenarios.name AS scenario_name
                   FROM runs
                   LEFT JOIN scenarios ON scenarios.id = runs.scenario_id
                   ORDER BY runs.created_at DESC, runs.run_id DESC
                   LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        return [_run_row(r) for r in rows]

    def comparison(self, scenario_hash: str) -> list[dict[str, Any]]:
        """Verdict counts per model for one scenario — the model-vs-model view.

        Matches on prefix. Hashes are 71 characters and every surface that
        shows one truncates it, so requiring the full string turns a copied
        identifier into a silently empty result.
        """
        rows = self._conn().execute(
            """SELECT model, verdict, COUNT(*) AS n
               FROM runs
               WHERE (scenario_hash = ? OR scenario_hash LIKE ? || '%')
                 AND variant = 'attack'
               GROUP BY model, verdict""",
            (scenario_hash, scenario_hash),
        ).fetchall()
        by_model: dict[str, dict[str, Any]] = {}
        for r in rows:
            slot = by_model.setdefault(r["model"], {"model": r["model"], "counts": {}, "total": 0})
            slot["counts"][r["verdict"]] = r["n"]
            slot["total"] += r["n"]
        for slot in by_model.values():
            decided = slot["total"] - slot["counts"].get("INCONCLUSIVE", 0)
            slot["attack_success_rate"] = (
                slot["counts"].get("COMPROMISED", 0) / decided if decided else 0.0
            )
        return sorted(by_model.values(), key=lambda s: -s["attack_success_rate"])


def _scenario_row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["tags"] = json.loads(d.get("tags") or "{}")
    d["findings"] = json.loads(d.get("findings") or "[]")
    d["valid"] = bool(d.get("valid"))
    d["path"] = d.get("path") or ""
    return d


def _run_row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    for key in ("axes", "judge", "usage"):
        d[key] = json.loads(d.get(key) or "{}")
    d["first_compromise"] = json.loads(d["first_compromise"]) if d.get("first_compromise") else None
    return d
