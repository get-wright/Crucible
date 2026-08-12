"""Scenarios as files, and the save-then-run path that uses them.

The point of this module is that the browser and the command line produce the
same artifact. A scenario saved from the GUI must be a file `crucible run`
accepts, at a path the caller was told about, and nothing arriving over HTTP
may write outside the library directory.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from crucible import library
from crucible.config import Settings
from crucible.store import Store
from crucible.validate import validate_source


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
    client = TestClient(api_module.app)
    client.library_dir = s.library_dir  # type: ignore[attr-defined]
    yield client
    get_settings.cache_clear()


# ── slugs and paths ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name,expected",
    [
        ("Release PR hijack", "release-pr-hijack"),
        ("Café Ops · escalation", "cafe-ops-escalation"),
        ("  spaced  out  ", "spaced-out"),
        ("!!!", "scenario"),
        ("", "scenario"),
        ("CON", "scenario"),
    ],
)
def test_slugify(name, expected):
    assert library.slugify(name) == expected


def test_unique_path_does_not_clobber(tmp_path):
    first = library.unique_path(tmp_path, "untitled")
    first.write_text("one")
    second = library.unique_path(tmp_path, "untitled")
    assert first.name == "untitled.md"
    assert second.name == "untitled-2.md"


@pytest.mark.parametrize(
    "escape",
    ["../outside", "../../etc/passwd", "sub/../../outside", "/etc/passwd"],
)
def test_resolve_refuses_to_escape_the_library(tmp_path, escape):
    """These values arrive over HTTP, so containment is not advisory."""
    lib = tmp_path / "scenarios"
    lib.mkdir()
    with pytest.raises(library.LibraryError):
        library.resolve(lib, escape)
    # Rejecting must be inert: a refused path may not leave a directory
    # behind outside the library on its way to being refused.
    assert [p.name for p in tmp_path.iterdir()] == ["scenarios"]


def test_resolve_adds_the_suffix_and_accepts_a_bare_stem(tmp_path):
    assert library.resolve(tmp_path, "thing") == (tmp_path / "thing.md").resolve()
    assert library.resolve(tmp_path, "thing.md") == (tmp_path / "thing.md").resolve()


def test_write_is_atomic_and_leaves_no_temporary_behind(tmp_path):
    p = library.write("body", directory=tmp_path, name="A Scenario")
    assert p.read_text() == "body"
    assert [x.name for x in tmp_path.iterdir()] == ["a-scenario.md"]


def test_write_to_a_path_overwrites_that_file(tmp_path):
    first = library.write("v1", directory=tmp_path, name="Thing")
    again = library.write("v2", directory=tmp_path, name="Thing",
                          path=library.relative(tmp_path, first))
    assert again == first
    assert first.read_text() == "v2"
    assert len(list(tmp_path.glob("*.md"))) == 1


# ── the HTTP path ───────────────────────────────────────────────────────────


def test_saving_writes_a_file_and_reports_where(api, example_yaml):
    body = api.post("/scenarios", json={"yaml": example_yaml}).json()
    assert body["runnable"] is True
    path = body["path"]
    assert path.endswith(".md")

    on_disk = api.library_dir / path
    assert on_disk.read_text() == example_yaml
    assert body["scenario"]["path"] == path
    # The file is the artifact the runner takes, so it must still validate.
    assert validate_source(on_disk.read_text()).ok


def test_updating_rewrites_the_same_file(api, example_yaml):
    created = api.post("/scenarios", json={"yaml": example_yaml}).json()
    sid, path = created["scenario"]["id"], created["path"]

    edited = example_yaml.replace("repeats: 10", "repeats: 4")
    updated = api.put(f"/scenarios/{sid}", json={"yaml": edited}).json()

    assert updated["path"] == path, "an edit must not leave a second copy behind"
    assert (api.library_dir / path).read_text() == edited
    assert len(list(api.library_dir.glob("*.md"))) == 1


def test_an_invalid_draft_still_saves_and_says_it_cannot_run(api, example_yaml):
    """Losing the draft you were about to fix is worse than keeping a bad one."""
    broken = example_yaml.replace("max_turns: 16", "max_turns: 0")
    r = api.post("/scenarios", json={"yaml": broken})

    assert r.status_code == 200
    body = r.json()
    assert body["runnable"] is False
    assert body["validation"]["errors"]
    assert (api.library_dir / body["path"]).read_text() == broken
    assert body["scenario"]["valid"] is False


def test_unparseable_yaml_is_refused_with_a_readable_message(api):
    r = api.post("/scenarios", json={"yaml": "this is not a scenario"})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert isinstance(detail["message"], str) and detail["message"]
    assert "validation" in detail


def test_a_rejected_run_explains_itself(api, example_yaml):
    """The GUI shows this string; "fix the errors first" was not one."""
    r = api.post("/suites", json={"yaml": example_yaml.replace("max_turns: 16", "max_turns: 0")})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["message"].startswith("line ")
    assert detail["validation"]["errors"]


def test_save_then_run_the_file(api, example_yaml):
    """The whole point: save produces a file, and that file is what runs."""
    saved = api.post("/scenarios", json={"yaml": example_yaml}).json()

    started = api.post("/suites", json={
        "path": saved["path"], "scenario_id": saved["scenario"]["id"],
        "repeats": 1, "judge": False,
    })
    assert started.status_code == 200, started.text
    suite_id = started.json()["suite_id"]

    suite = api.get(f"/suites/{suite_id}").json()
    assert suite["status"] == "completed"
    assert suite["scenario_id"] == saved["scenario"]["id"]


def test_running_a_path_uses_what_is_on_disk_not_the_database(api, example_yaml):
    """Editing the file out of band changes what runs — it is the source."""
    saved = api.post("/scenarios", json={"yaml": example_yaml}).json()
    target = api.library_dir / saved["path"]
    target.write_text(example_yaml.replace("repeats: 10", "repeats: 7"))

    started = api.post("/suites", json={"path": saved["path"], "repeats": 1, "judge": False})
    assert started.status_code == 200
    assert started.json()["scenario_hash"] != saved["validation"]["scenario_hash"]


def test_running_a_missing_file_says_so(api):
    r = api.post("/suites", json={"path": "nope.md", "repeats": 1})
    assert r.status_code == 404
    assert "nope" in r.json()["detail"]["message"]


def test_a_run_cannot_be_pointed_outside_the_library(api):
    r = api.post("/suites", json={"path": "../../etc/passwd", "repeats": 1})
    assert r.status_code == 404
    assert "escapes" in r.json()["detail"]["message"]


def test_the_file_can_be_downloaded(api, example_yaml):
    saved = api.post("/scenarios", json={"yaml": example_yaml}).json()
    r = api.get(f"/scenarios/{saved['scenario']['id']}/file")
    assert r.status_code == 200
    assert r.text == example_yaml


def test_the_library_lists_files_dropped_in_by_hand(api, example_yaml):
    """A file arriving by `git pull` is in the library without an import step."""
    (api.library_dir / "handwritten.md").write_text(example_yaml)
    body = api.get("/library").json()
    assert "handwritten.md" in [f["path"] for f in body["files"]]


def test_write_file_false_records_without_touching_disk(api, example_yaml):
    body = api.post("/scenarios", json={"yaml": example_yaml, "write_file": False}).json()
    assert body["path"] == ""
    assert not list(api.library_dir.glob("*.md"))
