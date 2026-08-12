"""Command line — validate, generate, run, serve.

Exists because PLATFORM_PLAN §8 Phase 1 is explicitly "a CLI that prints the
trajectory", and because a CLI is the fastest way to check the pipeline
without a browser.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .config import get_settings
from .validate import validate_source

RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
RED, GREEN, YELLOW, BLUE, MAGENTA = (
    "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m",
)
VERDICT_COLOUR = {
    "COMPROMISED": RED,
    "NON_COMPLIANT": YELLOW,
    "SECURE_UNHELPFUL": YELLOW,
    "SECURE_USEFUL": GREEN,
    "INCONCLUSIVE": DIM,
}


def _clip(text: str, width: int, full: bool) -> str:
    """Truncate for scanning, or hand back everything under -v.

    Every printed field goes through this, so `-v` is one switch rather than a
    dozen call sites that each have to remember their own limit.
    """
    text = str(text)
    if full or len(text) <= width:
        return text
    return text[:width] + "…"


def _print_findings(result) -> None:
    for f in result.findings:
        colour = RED if f.severity == "error" else YELLOW
        print(f"  {colour}{f.severity:>7}{RESET} line {f.line:>3}  {DIM}{f.code}{RESET}  {f.message}")


def cmd_validate(args: argparse.Namespace) -> int:
    text = Path(args.file).read_text()
    result = validate_source(text)
    status = f"{GREEN}valid{RESET}" if result.ok else f"{RED}invalid{RESET}"
    print(f"{BOLD}{args.file}{RESET}: {status}   {DIM}{result.scenario_hash[:26]}{RESET}")
    _print_findings(result)
    print(f"\n{len(result.errors)} error(s), {len(result.warnings)} warning(s)")
    return 0 if result.ok else 1


def cmd_generate(args: argparse.Namespace) -> int:
    from .generate import generate_scenario

    tags = json.loads(args.tags) if args.tags.startswith("{") else dict(
        pair.split("=", 1) for pair in args.tags.split(",")
    )

    async def go():
        return await generate_scenario(
            tags=tags, brief=args.brief, repeats=args.repeats,
            model=args.model, critique=not args.no_critique,
        )

    result = asyncio.run(go())
    if args.out:
        Path(args.out).write_text(result.yaml)
        print(f"{GREEN}wrote{RESET} {args.out}")
    else:
        print(result.yaml)

    print(
        f"\n{DIM}generator={result.generator_model} repaired={result.repaired} "
        f"revised={result.revised} tokens={result.usage.output_tokens}{RESET}",
        file=sys.stderr,
    )
    if result.critique.defects or result.critique.tells:
        print(f"{YELLOW}critique{RESET}: {result.critique.as_dict()}", file=sys.stderr)
    _print_findings(result.validation)
    return 0 if result.validation.ok else 1


def _print_trajectory(log, full: bool = False) -> None:
    for m in log.messages():
        kind, seq = m["kind"], m["seq"]
        if kind == "participant":
            print(f"  {BLUE}[{seq:>4}] {m['display_name']}{RESET}: {_clip(m['text'], 160, full)}")
            for a in m.get("attachments") or []:
                print(f"         {DIM}attached {a.get('name')}{RESET}")
                if full and a.get("content"):
                    for line in str(a["content"]).splitlines():
                        print(f"         {DIM}| {line}{RESET}")
        elif kind == "reasoning":
            print(f"  {DIM}[{seq:>4}] think: {_clip(m['text'], 160, full)}{RESET}")
        elif kind == "text":
            print(f"  [{seq:>4}] {BOLD}agent{RESET}: {_clip(m['text'], 160, full)}")
        elif kind == "tool":
            mark = f"{RED}✗{RESET}" if m.get("is_error") else f"{GREEN}✓{RESET}"
            danger = f" {RED}destructive{RESET}" if m.get("destructive") else ""
            inj = f" {RED}carried:{m['injections']}{RESET}" if m.get("injections") else ""
            args = json.dumps(m.get("args"), default=str)
            print(f"  [{seq:>4}] {mark} {m['tool']}({_clip(args, 90, full)}){danger}{inj}")
            if full:
                served = f" {DIM}via {m.get('served_by')}{RESET}" if m.get("served_by") else ""
                print(f"         {DIM}->{RESET}{served} {json.dumps(m.get('result'), default=str)}")
                if m.get("schema_errors"):
                    print(f"         {RED}schema errors:{RESET} {m['schema_errors']}")
        elif kind == "injection":
            print(
                f"  {MAGENTA}[{seq:>4}] ⚑ injection {m['injection_id']} "
                f"by {m['author']} via {m['channel']}{RESET}"
            )
        elif kind == "notice":
            rest = json.dumps({k: v for k, v in m.items() if k not in ("kind", "seq", "turn", "type")}, default=str)
            print(f"  {YELLOW}[{seq:>4}] {m.get('type')}{RESET} {_clip(rest, 140, full)}")


def _print_run_header(log) -> None:
    """What the run was configured with and what world it faced.

    Under -v this comes first, because a trajectory read without knowing which
    injections were seeded — or that a model was substituted — can be
    interpreted wrongly in both directions.
    """
    starts = log.of_type("run.start")
    if not starts:
        return
    d = starts[0].data
    print(f"  {DIM}model      {RESET}{d.get('model')}   {DIM}judge{RESET} {d.get('judge_model')}"
          f"   {DIM}simulator{RESET} {d.get('simulator_model')}")
    print(f"  {DIM}variant    {RESET}{d.get('variant')} #{d.get('repeat')}   "
          f"{DIM}seed{RESET} {d.get('seed')}   {DIM}world from cache{RESET} {d.get('world_from_cache')}")
    print(f"  {DIM}limits     {RESET}{json.dumps(d.get('limits'), default=str)}")
    for note in d.get("model_substitutions") or []:
        print(f"  {YELLOW}substituted{RESET} {note}")
    if d.get("world_summary"):
        print(f"  {DIM}world      {RESET}{d['world_summary']}")
    for inj in d.get("injections") or []:
        print(f"  {MAGENTA}seeded injection{RESET} {inj.get('id')} by {inj.get('author')} "
              f"via {inj.get('channel')} at {inj.get('target')}")
        print(f"      {DIM}{inj.get('payload')}{RESET}")
    for note in d.get("planted") or []:
        print(f"  {DIM}planted    {note}{RESET}")
    for note in d.get("control_neutralised") or []:
        print(f"  {DIM}neutralised {note}{RESET}")


def _print_events_full(log) -> None:
    """Every event, in sequence order, nothing withheld.

    Deliberately renders the raw stream rather than the rolled-up view the
    non-verbose path uses: the rollup drops state patches, per-call token
    usage, checks and the seeded world, which are exactly the things someone
    reaching for -v is looking for. Consecutive reasoning and text deltas are
    still merged into one block, because thousands of token-level events are
    noise rather than detail.
    """
    buf_kind, buf = None, []

    def flush() -> None:
        nonlocal buf_kind, buf
        if buf and "".join(buf).strip():
            text = "".join(buf)
            label = f"{DIM}think{RESET}" if buf_kind == "reasoning.delta" else f"{BOLD}agent{RESET}"
            body = f"{DIM}{text}{RESET}" if buf_kind == "reasoning.delta" else text
            print(f"  [{buf_seq:>5}] {label}: {body}")
        buf_kind, buf = None, []

    buf_seq = 0
    for e in log.events:
        if e.type in ("reasoning.delta", "text.delta"):
            if buf_kind != e.type:
                flush()
                buf_kind, buf_seq = e.type, e.seq
            buf.append(e.data.get("text", ""))
            continue
        flush()
        d, seq = e.data, e.seq
        if e.type == "run.start":
            continue  # rendered by _print_run_header
        if e.type == "turn.start":
            print(f"  {BLUE}[{seq:>5}] {d.get('display_name')}{RESET} "
                  f"{DIM}({d.get('source')}){RESET}: {d.get('content')}")
            for a in d.get("attachments") or []:
                print(f"          {DIM}attached {a.get('name')} ({a.get('type')}){RESET}")
                for line in str(a.get("content") or "").splitlines():
                    print(f"          {DIM}| {line}{RESET}")
        elif e.type == "tool.call":
            bad = f" {RED}INVALID{RESET}" if not d.get("valid", True) else ""
            danger = f" {RED}destructive{RESET}" if d.get("destructive") else ""
            print(f"  [{seq:>5}] {BOLD}call{RESET}  {d.get('tool')}"
                  f"({json.dumps(d.get('args'), default=str)}){danger}{bad}")
            for err in d.get("schema_errors") or []:
                print(f"          {RED}{err}{RESET}")
        elif e.type == "tool.result":
            mark = f"{RED}error{RESET}" if d.get("is_error") else f"{GREEN}ok{RESET}"
            print(f"  [{seq:>5}] {mark:<5} {DIM}{d.get('served_by')} "
                  f"{d.get('latency_ms')}ms{RESET} {json.dumps(d.get('result'), default=str)}")
        elif e.type == "injection.delivered":
            print(f"  {MAGENTA}[{seq:>5}] INJECTION DELIVERED {d.get('injection_id')} "
                  f"by {d.get('author')} via {d.get('channel')} "
                  f"(offset {d.get('char_offset')}, {d.get('char_len')} chars){RESET}")
        elif e.type == "state.patch":
            print(f"  {YELLOW}[{seq:>5}] state {d.get('path')}: "
                  f"{json.dumps(d.get('before'), default=str)} -> "
                  f"{json.dumps(d.get('after'), default=str)}{RESET}")
        elif e.type == "llm.response":
            print(f"  {DIM}[{seq:>5}] llm   finish={d.get('finish_reason')} "
                  f"in={d.get('input_tokens')} out={d.get('output_tokens')} "
                  f"calls={d.get('tool_call_count')}{RESET}")
        elif e.type == "check.evaluated":
            mark = f"{GREEN}PASS{RESET}" if d.get("passed") else f"{RED}FAIL{RESET}"
            print(f"  [{seq:>5}] check {mark} {d.get('check_id')} ({d.get('axis')}) "
                  f"{DIM}expected {d.get('expect')}, observed {d.get('actual')} "
                  f"evidence={d.get('evidence')}{RESET}")
            print(f"          {DIM}{d.get('assert')}{RESET}")
        elif e.type == "world.final":
            print(f"  {DIM}[{seq:>5}] final world state:{RESET}")
            print(f"          {DIM}{json.dumps(d.get('collections'), default=str)}{RESET}")
        elif e.type in ("limit.hit", "run.error", "egress.denied"):
            print(f"  {RED}[{seq:>5}] {e.type}{RESET} {json.dumps(d, default=str)}")
        elif e.type == "judge.item":
            mark = f"{GREEN}YES{RESET}" if d.get("answer") else f"{RED}NO{RESET}"
            print(f"  [{seq:>5}] judge {mark} {d.get('rubric_id')} "
                  f"{DIM}conf={d.get('confidence')} cites={d.get('citation')}{RESET}")
        elif e.type not in ("run.verdict", "llm.request"):
            print(f"  {DIM}[{seq:>5}] {e.type} {json.dumps(d, default=str)}{RESET}")
    flush()


def _print_verdict(r, full: bool = False) -> None:
    colour = VERDICT_COLOUR.get(r.verdict.verdict, "")
    print(f"\n{colour}{BOLD}{r.verdict.verdict}{RESET}  {r.verdict.rationale}")
    for name, axis in r.verdict.axes.items():
        mark = GREEN + "pass" if axis.result == "pass" else RED + "fail"
        detail = ", ".join(axis.failed)
        if full and axis.inconclusive:
            detail += f"  (inconclusive: {', '.join(axis.inconclusive)})"
        print(f"  {name:<11} {mark}{RESET} {DIM}{detail}{RESET}")
    for j in r.verdict.judge.get("items", []):
        mark = f"{GREEN}YES{RESET}" if j["answer"] else f"{RED}NO {RESET}"
        ok = f"{GREEN}✓{RESET}" if j["passed"] else f"{RED}✗{RESET}"
        print(f"  {ok} {mark} {j['rubric_id']:<32} {DIM}cites {j['citation'][:4]}{RESET}")
        if full:
            print(f"        {DIM}{j['reason']}{RESET}")
    if full and r.verdict.first_compromise:
        print(f"  {DIM}first_compromise: {json.dumps(r.verdict.first_compromise, default=str)}{RESET}")
    if full and r.log_path:
        print(f"  {DIM}events: {r.log_path}{RESET}")
    print(f"\n{DIM}{r.wall_ms/1000:.1f}s · {r.usage.input_tokens} in / {r.usage.output_tokens} out{RESET}")


def cmd_run(args: argparse.Namespace) -> int:
    from .orchestrator import run_suite
    from .runner import execute_run
    from .store import Store

    result = validate_source(Path(args.file).read_text())
    if not result.ok or result.ir is None:
        print(f"{RED}scenario is invalid{RESET}")
        _print_findings(result)
        return 1
    ir = result.ir
    if args.model:
        ir.scenario.model = args.model

    if args.repeats == 1 and not args.control:
        r = asyncio.run(execute_run(ir, seed=args.seed, judge=not args.no_judge))
        print(f"\n{BOLD}{ir.scenario.name}{RESET}")
        if args.verbose:
            _print_run_header(r.log)
            _print_events_full(r.log)
        elif args.trajectory:
            _print_trajectory(r.log)
        _print_verdict(r, full=args.verbose)
        return 0

    store = Store() if args.save else None
    suite = asyncio.run(
        run_suite(
            ir, repeats=args.repeats, control=args.control, seed=args.seed,
            concurrency=args.concurrency, judge=not args.no_judge, store=store,
        )
    )
    print(f"\n{BOLD}{ir.scenario.name}{RESET}  {DIM}{suite.suite_id}{RESET}")
    for r in sorted(suite.runs, key=lambda r: (r.variant, r.repeat)):
        colour = VERDICT_COLOUR.get(r.verdict.verdict, "")
        print(f"  {r.variant:<8} #{r.repeat:<3} {colour}{r.verdict.verdict:<17}{RESET} {DIM}{r.wall_ms/1000:>6.1f}s{RESET}")
    # Under -v each repeat is printed whole. The one-line summary above is
    # still shown first, so the shape of the suite stays readable before the
    # transcripts scroll past.
    if args.verbose or args.trajectory:
        for r in sorted(suite.runs, key=lambda r: (r.variant, r.repeat)):
            print(f"\n{BOLD}── {r.variant} #{r.repeat}{RESET} {DIM}{r.run_id}{RESET}")
            if args.verbose:
                _print_run_header(r.log)
                _print_events_full(r.log)
            else:
                _print_trajectory(r.log)
            _print_verdict(r, full=args.verbose)
    m = suite.metrics
    print(f"\n{BOLD}metrics{RESET}")
    print(f"  attack_success_rate   {m.attack_success_rate:.0%}   ({m.attack_runs} attack runs)")
    print(f"  false_refusal_rate    {m.false_refusal_rate:.0%}   ({m.control_runs} control runs)")
    print(f"  pass^{m.attack_runs:<17} {m.pass_hat_k:.0%}")
    print(f"  utility_under_attack  {m.utility_under_attack:.0%}")
    if m.time_to_compromise_steps is not None:
        print(f"  time_to_compromise    {m.time_to_compromise_steps:.0f} steps")
    print(f"  {DIM}{m.verdict_counts}{RESET}")
    for e in suite.errors:
        print(f"  {RED}error{RESET} {e}")
    return 0


def cmd_convert(args: argparse.Namespace) -> int:
    import yaml as _yaml

    from .convert import convert, pin_world
    from .config import get_settings

    doc = _yaml.safe_load(Path(args.file).read_text())
    report = convert(
        doc, model=args.model, judge_model=args.judge_model,
        repeats=args.repeats, max_turns=args.max_turns,
    )
    result = validate_source(report.yaml)

    out = Path(args.out) if args.out else None
    if out:
        out.write_text(report.yaml)
        print(f"{GREEN}wrote{RESET} {out}")
    else:
        print(report.yaml)

    print(f"\n{BOLD}conversion notes{RESET}", file=sys.stderr)
    for n in report.notes:
        print(f"  {DIM}·{RESET} {n}", file=sys.stderr)
    if report.dropped:
        print(f"  {YELLOW}dropped{RESET}: {', '.join(report.dropped)}", file=sys.stderr)

    if report.world and args.pin_world and result.ir is not None:
        path = pin_world(result.ir, report.world, settings=get_settings(), seed=args.seed)
        n = sum(len(v) for v in report.world["collections"].values())
        print(f"  {GREEN}pinned{RESET} recovered world ({n} records, "
              f"{len(report.world['injections'])} injections) -> {path}", file=sys.stderr)

    status = f"{GREEN}valid{RESET}" if result.ok else f"{RED}invalid{RESET}"
    print(f"\n{status}  {len(result.errors)} error(s), {len(result.warnings)} warning(s)", file=sys.stderr)
    _print_findings(result)
    return 0 if result.ok else 1


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("crucible.api:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def cmd_info(_: argparse.Namespace) -> int:
    s = get_settings()
    print(f"provider   {s.fpt_base_url}")
    print(f"key        {'present' if s.resolved_key else 'MISSING (offline mode)'}")
    print(f"offline    {s.is_offline}")
    print(f"target     {s.target_model}")
    print(f"judge      {s.judge_model}")
    print(f"simulator  {s.simulator_model}")
    print(f"generator  {s.generator_model}")
    print(f"data       {s.data_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="crucible", description="Adversarial agent benchmark")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="parse and validate a scenario file")
    v.add_argument("file")
    v.set_defaults(fn=cmd_validate)

    g = sub.add_parser("generate", help="draft a scenario from tags + a brief")
    g.add_argument("--tags", required=True, help='JSON object, or k=v,k=v')
    g.add_argument("--brief", required=True)
    g.add_argument("--out")
    g.add_argument("--model")
    g.add_argument("--repeats", type=int, default=10)
    g.add_argument("--no-critique", action="store_true")
    g.set_defaults(fn=cmd_generate)

    r = sub.add_parser("run", help="execute a scenario")
    r.add_argument("file")
    r.add_argument("--repeats", type=int, default=1)
    r.add_argument("--control", action="store_true", help="also run the benign control variant")
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--model")
    r.add_argument("--concurrency", type=int, default=4)
    r.add_argument("--trajectory", action="store_true", help="print the trajectory")
    r.add_argument("-v", "--verbose", action="store_true",
                   help="full untruncated output: trajectory, tool results, judge reasoning, "
                        "and every repeat of a suite")
    r.add_argument("--no-judge", action="store_true")
    r.add_argument("--save", action="store_true", help="persist to the store")
    r.set_defaults(fn=cmd_run)

    cv = sub.add_parser("convert", help="import a v0.1 scenario into SPEC v0.2")
    cv.add_argument("file")
    cv.add_argument("--out")
    cv.add_argument("--model", default="DeepSeek-V4-Flash", help="the model under test")
    cv.add_argument("--judge-model", default="GLM-5.2")
    cv.add_argument("--repeats", type=int, default=10)
    cv.add_argument("--max-turns", type=int, default=16)
    cv.add_argument("--seed", type=int, default=0)
    cv.add_argument("--pin-world", action="store_true",
                    help="write the recovered return_value world into the cache")
    cv.set_defaults(fn=cmd_convert)

    s = sub.add_parser("serve", help="run the HTTP API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--reload", action="store_true")
    s.set_defaults(fn=cmd_serve)

    i = sub.add_parser("info", help="show resolved configuration")
    i.set_defaults(fn=cmd_info)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
