"""Static contracts for the browser-only interface."""

from pathlib import Path


STATIC = Path(__file__).parents[1] / "crucible" / "static"


def _text(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def test_markdown_engine_is_vendored_and_loaded_before_the_app():
    html = _text("index.html")
    vendor = STATIC / "vendor" / "marked.min.js"

    assert vendor.is_file()
    assert (STATIC / "vendor" / "MARKED-LICENSE.txt").is_file()
    assert "marked@18.0.9" in vendor.read_text(encoding="utf-8")
    assert html.index('/static/vendor/marked.min.js') < html.index('/static/app.js')
    assert "cdn.jsdelivr" not in html


def test_transcript_uses_symbols_instead_of_role_pills():
    html = _text("index.html")
    js = _text("app.js")
    css = _text("app.css")

    assert "event-badge" not in js + css
    for symbol in ("i-user", "i-agent", "i-brain", "i-tool", "i-judge", "i-state"):
        assert f'id="{symbol}"' in html
    assert "eventIcon(" in js


def test_agent_output_uses_markdown_for_live_and_replay():
    js = _text("app.js")

    assert "window.marked.parse" in js
    assert "appendLiveDelta(" in js
    assert 'markdownHtml(m.text)' in js
    assert "sanitizeMarkdown" in js
    assert '["http:", "https:", "mailto:"]' in js
    assert 'attr.name.toLowerCase() === "href"' in js


def test_each_route_has_distinct_local_artwork():
    html = _text("index.html")
    js = _text("app.js")

    for motif in ("art-library", "art-author", "art-run", "art-result", "art-settings"):
        assert f'id="{motif}"' in html
        assert f'"{motif}"' in js
    assert 'class="screen-art"' in html
    assert "main.dataset.screen = name" in js


def test_settings_route_persists_and_sends_request_overrides():
    html = _text("index.html")
    js = _text("app.js")

    assert 'data-screen="settings"' in html
    assert 'id="s-settings"' in html
    for field in ("setting-target", "setting-judge", "setting-generator", "setting-timeout"):
        assert f'id="{field}"' in html
    assert '"settings"' in js
    assert 'const SETTINGS_KEY = "crucible-preferences-v1"' in js
    assert "localStorage.setItem(SETTINGS_KEY" in js
    assert "generator_model: state.preferences.generator_model" in js
    assert "...runPreferences()" in js
    assert "timeout_s: p.timeout_s" in js
    assert "preferencesMatch(" in js
    assert "updateSettingsState(" in js
    assert '$$("#s-settings select, #s-settings input")' in js
    assert '$("#settings-save").disabled = !dirty' in js


def test_navigation_does_not_disconnect_an_active_run():
    js = _text("app.js")
    route = js[js.index("function route()") : js.index('window.addEventListener("hashchange", route)')]

    assert "closeRunSource()" not in route
    assert "if (name !== \"run\")" not in route


def test_run_uses_a_bounded_internal_trajectory_scroller():
    html = _text("index.html")
    css = _text("app.css")

    assert 'class="run-chrome"' in html
    assert 'id="run-body" class="run-viewport" tabindex="0" role="region"' in html
    assert 'id="run-status"' in html
    assert 'id="run-history-section"' in html
    assert ".run-chrome {" in css
    assert "position: sticky" in css
    assert ".run-viewport {" in css
    assert "height: clamp(360px, calc(100dvh - 250px), 680px)" in css
    assert "overflow-y: auto" in css
    assert "overscroll-behavior: contain" in css
    assert "scrollbar-gutter: stable" in css
    assert "height: clamp(320px, calc(100dvh - 300px), 560px)" in css
    assert ".run-chrome { top: 58px; }" in css


def test_run_toolbar_navigates_latest_history_and_results():
    html = _text("index.html")
    js = _text("app.js")

    for control in ("run-latest", "run-past", "run-results"):
        assert f'id="{control}"' in html
    assert "function scrollRunToLatest(" in js
    assert '$("#run-history-section").scrollIntoView' in js
    assert 'if (state.suiteId && state.suiteHasResult) go("result", state.suiteId)' in js
    assert 'state.suiteHasResult = suite?.status === "completed"' in js
    assert 'state.suiteHasResult = true' in js


def test_live_following_targets_the_run_viewport_only():
    js = _text("app.js")

    assert "function runViewport()" in js
    assert "function runNearBottom(" in js
    assert "function followRunMutation(" in js
    assert "host.scrollTo({ top: host.scrollHeight" in js
    assert '$("#run-body").addEventListener("scroll"' in js
    assert 'latest.textContent = state.unseenRunEvents ? "Latest · new" : "Latest"' in js
    assert "window.scrollTo" not in js
    assert "document.body.scrollHeight" not in js


def test_navigation_is_a_persistent_monochrome_zebra():
    html = _text("index.html")
    css = _text("app.css")

    lowered = css.lower()
    assert "gradient(" not in lowered
    assert "backdrop-filter" not in lowered
    assert "style=" not in html.lower()
    assert "--tab-a: #fafafa" in lowered
    assert "--tab-b: #eeeeef" in lowered
    assert "--tab-a: #111113" in lowered
    assert "--tab-b: #202023" in lowered
    assert ".rail button:nth-child(odd) { --tab-bg: var(--tab-a); }" in css
    assert ".rail button:nth-child(even) { --tab-bg: var(--tab-b); }" in css
    assert "background: var(--tab-bg)" in css
    assert "--tab-accent" not in css
    assert '[aria-current="page"] svg' not in css
    for removed_token in ("--user-bg", "--thought-bg", "--tool-bg", "--judge-bg", "--model-bg"):
        assert removed_token not in css


def test_theme_control_describes_its_next_action():
    js = _text("app.js")

    assert "function updateThemeControl()" in js
    assert "Switch to ${next} theme" in js
    assert 'setAttribute("aria-label", label)' in js
    assert '$("#theme").title = label' in js


def test_tables_have_monochrome_row_striping():
    css = _text("app.css")

    assert "table.rows tbody tr:nth-child(even)" in css
    assert "var(--raised)" in css
    assert "table.rows tbody tr:hover { background: var(--raised-2); }" in css


def test_live_judge_phase_has_persistent_progress():
    js = _text("app.js")
    css = _text("app.css")

    assert "judgeProgress: new Map()" in js
    assert "function showJudgeActivity()" in js
    assert "function updateJudgeActivity(event, data)" in js
    assert 'event.type === "judge.start"' in js
    assert 'event.type === "judge.item"' in js
    assert 'event.type === "judge.complete"' in js
    assert 'class="activity-copy"' in js
    assert 'aria-label="Judge progress:' in js
    assert ".run-activity.judge-active" in css
    assert ".run-activity .spin { width: 24px; height: 24px;" in css
    assert "grid-template-columns: auto auto minmax(0, 1fr) minmax(120px, 220px)" in css


def test_results_expose_expandable_judge_reasoning_for_all_runs():
    js = _text("app.js")
    css = _text("app.css")

    assert "judgeBlock(suite.runs, lead?.run_id)" in js
    assert "function judgeRunDisclosure(run, leadRunId)" in js
    assert "function judgeCriterion(item)" in js
    assert 'class="judge-run"' in js
    assert 'class="judge-criterion"' in js
    assert "Judge reasoning" in js
    assert "item.confidence" in js
    assert "item.citation.join" in js
    assert 'data-judge-run="${esc(run.run_id)}"' in js
    assert ".judge-run > summary" in css
    assert ".judge-criterion > summary" in css
    assert ".judge-facts" in css
