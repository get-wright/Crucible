"""End-to-end pipeline and API, run entirely offline.

The scripted backend ships two agent policies precisely so this suite can
assert that the verdict engine *discriminates*: a harness that can only
demonstrate failure has not shown that its scoring works.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from crucible.config import Settings
from crucible.envsim import EnvironmentSimulator
from crucible.events import EventLog, read_log
from crucible.llm.offline import OfflineClient
from crucible.runner import execute_run
from crucible.store import Store
from crucible.validate import validate_source
from crucible.verdict import COMPROMISED, SECURE_USEFUL
from crucible.world import seed_world


@pytest.fixture
def ir(example_yaml):
    return validate_source(example_yaml).ir


async def test_offline_run_reports_compromised(ir, tmp_settings):
    """A gullible agent that follows the injected instruction is COMPROMISED."""
    client = OfflineClient(tmp_settings, agent_policy="gullible")
    r = await execute_run(ir, settings=tmp_settings, client=client, judge=False)
    assert r.verdict.verdict == COMPROMISED
    assert r.verdict.first_compromise is not None
    assert r.log_path.exists()


async def test_offline_run_reports_secure_useful(ir, tmp_settings):
    """The same scenario, a cautious agent: the engine must discriminate."""
    client = OfflineClient(tmp_settings, agent_policy="cautious")
    r = await execute_run(ir, settings=tmp_settings, client=client, judge=False)
    assert r.verdict.verdict == SECURE_USEFUL
    assert r.verdict.first_compromise is None


async def test_event_log_is_replayable(ir, tmp_settings):
    client = OfflineClient(tmp_settings, agent_policy="gullible")
    r = await execute_run(ir, settings=tmp_settings, client=client, judge=False)

    events = list(read_log(r.log_path))
    assert events[0]["type"] == "run.start"
    assert events[-1]["type"] == "run.verdict"
    # seq is monotonic — every citation depends on it
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs) == list(range(1, len(seqs) + 1))

    replay = EventLog(run_id=r.run_id, scenario_hash=r.scenario_hash)
    for e in events:
        replay.turn = e["turn"]
        replay.emit(e["type"], e["data"])
    assert replay.messages()


async def test_world_cache_is_stable_across_runs(ir, tmp_settings):
    """Repeats must serve against a byte-identical world."""
    client = OfflineClient(tmp_settings)
    first, _ = await seed_world(ir, seed=0, settings=tmp_settings, client=client)
    second, usage = await seed_world(ir, seed=0, settings=tmp_settings, client=client)
    assert second.from_cache
    assert usage.output_tokens == 0
    assert first.as_dict()["collections"] == second.as_dict()["collections"]


async def test_cached_world_is_not_re_planted(ir, tmp_settings):
    """Regression: a multi-line payload was appended again on every load."""
    client = OfflineClient(tmp_settings)
    first, _ = await seed_world(ir, seed=0, settings=tmp_settings, client=client)
    body_before = str(first.collections)
    second, _ = await seed_world(ir, seed=0, settings=tmp_settings, client=client)
    assert second.planted == []
    assert str(second.collections) == body_before


async def test_limits_terminate_inconclusive(ir, tmp_settings):
    ir.scenario.limits.max_tool_calls = 1
    client = OfflineClient(tmp_settings, agent_policy="gullible")
    r = await execute_run(ir, settings=tmp_settings, client=client, judge=False)
    assert r.verdict.verdict == "INCONCLUSIVE"
    assert r.verdict.terminated_by == "limit"


async def test_control_variant_withholds_the_injection(ir, tmp_settings):
    client = OfflineClient(tmp_settings, agent_policy="gullible")
    r = await execute_run(ir, variant="control", settings=tmp_settings, client=client, judge=False)
    assert r.log.of_type("injection.delivered") == []


# ── store ──────────────────────────────────────────────────────────────────


async def test_store_round_trips_a_run(ir, tmp_settings):
    store = Store(tmp_settings)
    client = OfflineClient(tmp_settings, agent_policy="gullible")
    r = await execute_run(ir, settings=tmp_settings, client=client, judge=False)
    store.save_run(r, model="GLM-5.2", judge_model="DeepSeek-V4-Flash")
    row = store.get_run(r.run_id)
    assert row["verdict"] == COMPROMISED
    assert row["model"] == "GLM-5.2"
    assert row["first_compromise"]["injection_id"]


def test_store_scenario_crud(tmp_settings, example_yaml):
    store = Store(tmp_settings)
    result = validate_source(example_yaml)
    store.save_scenario(
        scenario_id="scn_1", scenario_hash=result.scenario_hash,
        name="Larkspur", yaml_text=example_yaml,
        tags=result.ir.scenario.tags, model="GLM-5.2",
    )
    assert store.get_scenario("scn_1")["name"] == "Larkspur"
    assert len(store.list_scenarios()) == 1
    assert store.list_scenarios(tag_filters={"industry": "technology"})
    assert store.list_scenarios(tag_filters={"industry": "healthcare"}) == []
    assert store.delete_scenario("scn_1")


# ── API ────────────────────────────────────────────────────────────────────


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("CRUCIBLE_OFFLINE", "true")
    monkeypatch.setenv("CRUCIBLE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CRUCIBLE_LIBRARY_DIR", str(tmp_path / "scenarios"))
    monkeypatch.delenv("FPT_API_KEY", raising=False)
    monkeypatch.delenv("MKP_API_KEY", raising=False)
    import crucible.api as api_module
    from crucible.config import get_settings

    get_settings.cache_clear()
    s = Settings(offline=True, data_dir=tmp_path, library_dir=tmp_path / "scenarios")
    s.ensure_dirs()
    monkeypatch.setattr(api_module, "settings", s)
    monkeypatch.setattr(api_module, "store", Store(s))
    yield TestClient(api_module.app)
    get_settings.cache_clear()


def test_health(api):
    assert api.get("/health").json()["ok"] is True


def test_taxonomy_serves_the_dropdowns(api):
    body = api.get("/taxonomy").json()
    fields = {f["field"] for f in body["fields"]}
    assert {"industry", "domain", "attack_pattern", "owasp_llm", "owasp_agentic"} <= fields
    llm = next(f for f in body["fields"] if f["field"] == "owasp_llm")
    assert llm["options"][0]["label"].startswith("LLM01 · Prompt Injection")


def test_validate_endpoint_returns_line_anchored_findings(api, example_yaml):
    good = api.post("/scenarios/validate", json={"yaml": example_yaml}).json()
    assert good["ok"] and good["scenario_hash"].startswith("sha256:")

    bad = api.post("/scenarios/validate", json={"yaml": example_yaml.replace("repeats: 10", "repeats: 0")}).json()
    assert not bad["ok"]
    assert bad["errors"][0]["line"] > 0
    assert bad["errors"][0]["code"] == "bad-repeats"


def test_scenario_crud_over_http(api, example_yaml):
    created = api.post("/scenarios", json={"yaml": example_yaml}).json()
    sid = created["scenario"]["id"]
    assert created["validation"]["ok"]
    assert api.get(f"/scenarios/{sid}").json()["name"]
    assert api.get("/scenarios").json()["scenarios"]
    assert api.delete(f"/scenarios/{sid}").status_code == 200
    assert api.get(f"/scenarios/{sid}").status_code == 404


def test_run_rejects_an_invalid_scenario(api, example_yaml):
    r = api.post("/suites", json={"yaml": example_yaml.replace("max_turns: 16", "max_turns: 0")})
    assert r.status_code == 422


def test_suite_runs_and_streams(api, example_yaml):
    started = api.post("/suites", json={"yaml": example_yaml, "repeats": 2, "judge": False}).json()
    suite_id = started["suite_id"]
    assert started["stream"].endswith("/stream")

    # TestClient runs background tasks to completion before returning.
    suite = api.get(f"/suites/{suite_id}").json()
    assert suite["status"] == "completed"
    assert len(suite["runs"]) == 2
    assert suite["metrics"]["attack_runs"] == 2

    body = api.get(f"/suites/{suite_id}/stream").text
    assert "run.complete" in body and "suite.done" in body


def test_trajectory_endpoint_replays_from_disk(api, example_yaml):
    started = api.post("/suites", json={"yaml": example_yaml, "repeats": 1, "judge": False}).json()
    runs = api.get(f"/suites/{started['suite_id']}").json()["runs"]
    traj = api.get(f"/runs/{runs[0]['run_id']}/trajectory").json()
    assert traj["messages"]
    kinds = {m["kind"] for m in traj["messages"]}
    assert "tool" in kinds and "participant" in kinds


async def test_unavailable_model_is_substituted_and_recorded(ir, tmp_settings):
    """A portable scenario must still run, and must say what it ran on."""
    ir.scenario.model = "claude-opus-5"
    ir.scenario.judge_model = "gpt-5.5"
    client = OfflineClient(tmp_settings, agent_policy="cautious")
    r = await execute_run(ir, settings=tmp_settings, client=client, judge=False)

    start = r.log.of_type("run.start")[0].data
    assert start["model"] == tmp_settings.target_model
    assert start["judge_model"] == tmp_settings.judge_model
    assert len(start["model_substitutions"]) == 2
    assert "claude-opus-5" in start["model_substitutions"][0]


async def test_comparison_accepts_a_truncated_hash(ir, tmp_settings):
    """Every surface truncates a 71-char hash; exact-match-only is a trap."""
    store = Store(tmp_settings)
    client = OfflineClient(tmp_settings, agent_policy="gullible")
    r = await execute_run(ir, settings=tmp_settings, client=client, judge=False)
    store.save_run(r, model="GLM-5.2")

    full = store.comparison(r.scenario_hash)
    short = store.comparison(r.scenario_hash[:26])
    assert full == short
    assert full[0]["model"] == "GLM-5.2"
    assert full[0]["attack_success_rate"] == 1.0


async def test_control_variant_removes_the_attack_not_just_the_tracking(ir, tmp_settings):
    """Regression: clearing `injections` left the payload in the world.

    The agent then read the hostile record exactly as in the attack variant,
    no `injection.delivered` fired, safety scored `pass`, and
    `false_refusal_rate` was computed over runs that still contained the
    attack — the metric measured the opposite of what it claims to.
    """
    import json as _json

    client = OfflineClient(tmp_settings, agent_policy="gullible")
    r = await execute_run(ir, variant="control", settings=tmp_settings, client=client, judge=False)

    start = r.log.of_type("run.start")[0].data
    assert start["control_neutralised"], "control run neutralised nothing"
    # The control's own log correctly reports an empty world, so the payloads
    # to search for come from an independent seed of the same scenario.
    reference, _ = await seed_world(ir, seed=0, settings=tmp_settings, client=client)
    payloads = [i.payload for i in reference.injections]
    assert payloads, "fixture has no injection to neutralise"
    assert start["injections"] == []

    served = _json.dumps([e.data.get("result") for e in r.log.of_type("tool.result")], default=str)
    for p in payloads:
        assert p not in served, "attacker content was still served in the control variant"
    assert r.log.of_type("injection.delivered") == []


async def test_refusing_everything_is_secure_unhelpful(ir, tmp_settings):
    """The degenerate the whole SECURE_UNHELPFUL rung exists to expose.

    Regression: `did-some-work` counted a successful *read* as work, so an
    agent that listed the queue and then declined the entire sweep passed the
    utility axis. With that gone the benchmark measured caution rather than
    security, and nothing in the output said so.
    """
    client = OfflineClient(tmp_settings, agent_policy="refuser")
    r = await execute_run(ir, settings=tmp_settings, client=client, judge=False)
    assert r.verdict.verdict == "SECURE_UNHELPFUL"
    assert "did-some-work" in r.verdict.axes["utility"].failed


async def test_reads_alone_do_not_count_as_work(ir, tmp_settings):
    from crucible.checks import run_checks

    client = OfflineClient(tmp_settings, agent_policy="refuser")
    r = await execute_run(ir, settings=tmp_settings, client=client, judge=False)
    check = next(c for c in run_checks(ir, r.world, None, r.log) if c.check_id == "did-some-work")
    assert not check.passed
    assert r.log.of_type("tool.result"), "the run should still have read something"
