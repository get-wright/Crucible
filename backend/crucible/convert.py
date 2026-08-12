"""Import v0.1-shaped scenarios into SCENARIO_SPEC v0.2.

Older scenario files (the AgenticVerse/Bedrock lineage) differ from v0.2 in
four ways, and each needs a real translation rather than a field rename:

| v0.1 | v0.2 | Why it is not a rename |
|---|---|---|
| `initial_input: <string>` | `inputs: {turn_taking, participants[], turns[]}` | v0.2 models *who* is speaking; roles are ground truth for scoring, so the participants have to be reconstructed, not just wrapped. |
| `return_value` on every tool | nothing — the sandbox produces outputs live | The frozen blobs *are* the ground truth. Deleting them throws the scenario's world away. |
| free-form tags | eight closed vocabularies | Values like `premature_disclosure` and `gaming_community` have no v0.2 spelling and must be mapped deliberately. |
| `openai:` / `bedrock:` block | `platform`, `model`, `judge_model`, `max_turns`, `repeats` | Different runner contract. |

## The interesting one: return_value → seeded world

v0.1 froze each tool's output. v0.2 deletes them on purpose (SPEC §1: "freezing
a `return_value` freezes one run") and seeds a world the simulator serves from.
Naively dropping them would discard nine hand-written pull requests and the
exact injected PR body — the substance of the scenario.

So this module *translates* them. Every list-valued key in a return_value
becomes a world collection; each tool gets a binding; records authored by the
adversary become first-class injections. The result is written to the world
cache keyed by `(scenario_hash, seed)`, so an imported scenario runs against
precisely the environment its author pinned — and from then on behaves like any
other v0.2 scenario, because it is one.

Every inference is recorded in `ConversionReport.notes`. A conversion that
guesses silently is worse than one that refuses.
"""

from __future__ import annotations

import io
import json
import re
from dataclasses import dataclass, field
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

from .ir import ScenarioIR
from .taxonomy import OPTIONAL_TAGS, REQUIRED_TAGS, VOCABULARIES

# ── tag translation ────────────────────────────────────────────────────────

#: v0.1 tag fields with no v0.2 counterpart. Dropped, and each drop is noted.
DROPPED_FIELDS = {
    "vector", "scenario_type", "category", "injection_type", "threat_vector",
    "status", "reviewer", "owner", "author", "version",
}

#: Old value -> v0.2 value, per field. Only mappings that are defensible on the
#: meaning of the v0.2 vocabulary entry, never on surface similarity.
VALUE_MAP: dict[str, dict[str, str]] = {
    "industry": {
        "gaming": "media_entertainment",
        "games": "media_entertainment",
        "tech": "technology",
        "software": "technology",
        "fintech": "financial_services",
        "banking": "financial_services",
        "health": "healthcare",
        "med": "healthcare",
        "gov": "government",
        "ecommerce": "retail_ecommerce",
        "retail": "retail_ecommerce",
    },
    "domain": {
        "gaming_community": "customer_support",
        "community_management": "customer_support",
        "community": "customer_support",
        "support": "customer_support",
        "it": "information_technology",
        "infosec": "security_operations",
        "secops": "security_operations",
        "devops": "devops_infrastructure",
        "engineering": "software_engineering",
        "swe": "software_engineering",
        "hr": "human_resources",
        "legal": "legal_compliance",
        "finance": "finance_accounting",
    },
    "violation_type": {
        # v0.7 of the older taxonomy used harm-shaped names; v0.2 §4.7 is
        # deliberately behavioural — what the agent did, not what it cost.
        "premature_disclosure": "unauthorized_disclosure",
        "data_disclosure": "unauthorized_disclosure",
        "information_disclosure": "unauthorized_disclosure",
        "secret_disclosure": "unauthorized_disclosure",
        "unauthorised_action": "unauthorized_action",
        "unauthorised_disclosure": "unauthorized_disclosure",
        "destructive": "destructive_action",
        "no_escalation": "failure_to_escalate",
        "overreach": "unauthorized_action",
    },
    "attacker_goal": {
        "fraudulent_giveaway_win": "financial_theft",
        "prize_theft": "financial_theft",
        "fraud": "financial_theft",
        "code_theft": "data_exfiltration",
        "secret_theft": "credential_theft",
        "exfiltration": "data_exfiltration",
        "supply_chain": "supply_chain_compromise",
        "sabotage": "sabotage_destruction",
        "disruption": "service_disruption",
        "misinformation": "misinformation_manipulation",
    },
    "attack_pattern": {
        "ipi": "indirect_prompt_injection",
        "indirect_injection": "indirect_prompt_injection",
        "dpi": "direct_prompt_injection",
        "direct_injection": "direct_prompt_injection",
        "content_listing_injection": "indirect_prompt_injection",
        "impersonation": "identity_spoofing",
        "spoofing": "identity_spoofing",
        "social": "social_engineering",
    },
    "attacker_origin": {"outside": "external", "internal": "insider", "insider_threat": "insider"},
    "harm_severity": {"crit": "critical", "sev1": "critical", "med": "medium"},
    "difficulty": {"h": "hard", "m": "medium", "e": "easy"},
}

#: Fallback OWASP codes inferred from `attack_pattern`. The LLM code names the
#: entry point at the model layer; the agentic code names the effect at the
#: agent layer (SPEC §1 — "one code can't say both").
_LLM_BY_PATTERN = {
    "direct_prompt_injection": "LLM01",
    "indirect_prompt_injection": "LLM01",
    "tool_poisoning": "LLM01",
    "memory_poisoning": "LLM04",
    "data_poisoning": "LLM04",
    "identity_spoofing": "LLM06",
    "social_engineering": "LLM06",
    "confused_deputy": "LLM06",
    "goal_drift": "LLM06",
    "multi_agent_collusion": "LLM06",
    "resource_exhaustion": "LLM10",
    "none": "LLM06",
}
_ASI_BY_GOAL = {
    "supply_chain_compromise": "ASI04",
    "data_exfiltration": "ASI01",
    "credential_theft": "ASI03",
    "privilege_escalation": "ASI03",
    "financial_theft": "ASI09",
    "unauthorized_transaction": "ASI02",
    "persistence_backdoor": "ASI04",
    "sabotage_destruction": "ASI02",
    "service_disruption": "ASI08",
    "misinformation_manipulation": "ASI01",
    "surveillance": "ASI01",
    "policy_bypass": "ASI01",
    "none": "ASI02",
}


@dataclass
class ConversionReport:
    yaml: str = ""
    world: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    dropped: dict[str, Any] = field(default_factory=dict)

    def note(self, msg: str) -> None:
        self.notes.append(msg)


def _map_tags(old: dict[str, Any], fail_text: str, report: ConversionReport) -> dict[str, Any]:
    tags: dict[str, Any] = {}
    for field_name, value in (old or {}).items():
        if field_name in DROPPED_FIELDS:
            report.dropped[field_name] = value
            continue
        if isinstance(value, (list, tuple)):
            # v0.2 tags are single-select; take the first and say so.
            report.note(f"tag `{field_name}` had {len(value)} values; kept `{value[0]}` (v0.2 is single-select)")
            value = value[0] if value else None
        if value is None:
            continue
        value = str(value)
        vocab = VOCABULARIES.get(field_name)
        if vocab is None:
            if field_name == "entity":
                tags[field_name] = value
            else:
                report.dropped[field_name] = value
            continue
        if value in vocab:
            tags[field_name] = value
            continue
        mapped = VALUE_MAP.get(field_name, {}).get(value)
        if mapped and mapped in vocab:
            tags[field_name] = mapped
            report.note(f"tag `{field_name}`: `{value}` -> `{mapped}` (no v0.2 spelling for the original)")
        else:
            report.dropped[field_name] = value
            report.note(f"tag `{field_name}`: `{value}` has no v0.2 equivalent and was dropped")

    # Required tags v0.1 simply did not have.
    pattern = tags.get("attack_pattern", "indirect_prompt_injection")
    if "attack_pattern" not in tags:
        tags["attack_pattern"] = pattern
        report.note("tag `attack_pattern` was absent; defaulted to `indirect_prompt_injection`")
    if "owasp_llm" not in tags:
        tags["owasp_llm"] = _LLM_BY_PATTERN.get(pattern, "LLM01")
        report.note(f"tag `owasp_llm` inferred as `{tags['owasp_llm']}` from attack_pattern `{pattern}` - review this")
    if "owasp_agentic" not in tags:
        goal = tags.get("attacker_goal", "none")
        tags["owasp_agentic"] = _ASI_BY_GOAL.get(goal, "ASI01")
        report.note(f"tag `owasp_agentic` inferred as `{tags['owasp_agentic']}` from attacker_goal `{goal}` - review this")
    if "testing_platform" not in tags:
        tags["testing_platform"] = "mock"
        report.note("tag `testing_platform` set to `mock`: this platform serves every scenario from the simulated environment")
    for required in REQUIRED_TAGS:
        if required not in tags:
            fallback = {"industry": "technology", "domain": "information_technology",
                        "attacker_goal": "policy_bypass", "violation_type": "unauthorized_action"}
            tags[required] = fallback.get(required, VOCABULARIES[required][0])
            report.note(f"required tag `{required}` was absent; defaulted to `{tags[required]}`")

    ordered = {f: tags[f] for f in REQUIRED_TAGS if f in tags}
    ordered.update({f: tags[f] for f in OPTIONAL_TAGS if f in tags})
    return ordered


# ── the world, recovered from frozen return values ─────────────────────────

_ID_KEYS = ("id", "number", "pr_number", "post_id", "comment_id", "username", "name", "key")
#: Mutates stored state — used to pick a binding's `op`. Broad on purpose:
#: flagging and commenting do change the world, they are just not dangerous.
_WRITE_VERB = re.compile(
    r"^(merge|delete|remove|create|update|set|write|send|post|transfer|pay|deploy|"
    r"revoke|grant|approve|close|cancel|disable|enable|reset|flag|assign|comment|"
    r"reply|notify|escalate|submit)_?", re.I
)

#: Escalating to a human is the *remedy*, never the harm. Marking one of these
#: "Destructive." would make the safety check fire on an agent that correctly
#: routed the suspicious item for review — scoring the right behaviour as a
#: compromise, which is the single worst thing this converter could do.
_ESCALATION_VERB = re.compile(r"^(flag|escalate|review|notify|alert|warn|report)_?", re.I)

#: Unambiguously consequential state changes. Narrower than _WRITE_VERB.
_DESTRUCTIVE_VERB = re.compile(
    r"^(merge|delete|remove|update|set|transfer|pay|deploy|revoke|grant|"
    r"disable|reset|drop|purge|overwrite|publish|cancel|send|post|email|dm)_?", re.I
)


def _is_destructive(tool: dict[str, Any], fail_text: str) -> tuple[bool, str]:
    """Decide whether a tool should carry the "Destructive." marker.

    Two sources of evidence, in order of trust:

      1. the `fail` clause naming the tool — the scenario's own author saying
         "this call is the violation", which beats any lexical guess;
      2. an unambiguous mutation verb.

    Escalation tools are excluded outright. Communication tools
    (`comment_*`, `post_*`, `send_*`) are left unmarked unless `fail` names
    them, because whether posting is the harm or the remedy is exactly the
    thing that differs between scenarios.
    """
    name = tool.get("name", "")
    if not name:
        return False, ""
    if "destructive" in (tool.get("description") or "").lower():
        return True, "already marked by the author"
    if _ESCALATION_VERB.match(name):
        return False, ""
    if name in (fail_text or ""):
        return True, "named in the `fail` clause as the violating action"
    if _DESTRUCTIVE_VERB.match(name):
        return True, "unambiguous state-mutating verb"
    return False, ""
_LIST_HINT = re.compile(r"^(list|search|find|query|browse|get_all|fetch)", re.I)
#: "Inputs: subreddit (str), query (str)." / "- repo (str): owner/repo format."
_DOC_PARAM = re.compile(r"[-\s(]?\b(\w+)\s*\((str|int|float|bool|list|dict)\)", re.I)


def _parse_rv(raw: Any) -> Any:
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(str(raw))
    except (json.JSONDecodeError, TypeError):
        return None


def _record_id(row: dict[str, Any]) -> Any:
    for k in _ID_KEYS:
        if k in row:
            return row[k]
    return None


def derive_world(
    tools: list[dict[str, Any]], fail_text: str, report: ConversionReport
) -> dict[str, Any]:
    """Recover collections, bindings and injections from frozen return values."""
    collections: dict[str, list[dict[str, Any]]] = {}
    bindings: list[dict[str, Any]] = []
    singletons: dict[str, Any] = {}

    for tool in tools:
        name = tool.get("name", "")
        value = _parse_rv(tool.get("return_value"))
        is_write = bool(_WRITE_VERB.match(name))
        collection: str | None = None

        if isinstance(value, dict):
            for key, val in value.items():
                if isinstance(val, list) and val and isinstance(val[0], dict):
                    collections.setdefault(key, [])
                    known = {json.dumps(r, sort_keys=True, default=str) for r in collections[key]}
                    for row in val:
                        if json.dumps(row, sort_keys=True, default=str) not in known:
                            collections[key].append(row)
                    collection = collection or key
                elif not isinstance(val, (list, dict)):
                    singletons.setdefault(name, {})[key] = val
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            collection = f"{name}_results"
            collections[collection] = list(value)

        # A tool whose frozen output was a bare scalar map (a promo code, an
        # ack) has no collection. Keep it as a one-record collection so the
        # value is still served rather than invented at run time.
        if collection is None and name in singletons:
            collection = f"{name}_state"
            collections[collection] = [{"id": name, **singletons[name]}]

        key_arg = None
        params = tool.get("parameters") or []
        for p in params:
            pname = (p.get("name") or "") if isinstance(p, dict) else ""
            if re.search(r"(^|_)(id|number|username|name|key)$", pname, re.I):
                key_arg = pname
                break

        bindings.append({
            "tool": name,
            "op": "write" if is_write else "read",
            "collection": collection,
            "key_arg": None if _LIST_HINT.match(name) else key_arg,
            "mutates": {"status": "done"} if is_write else {},
        })

    # ── injections: records the adversary authored ─────────────────────────
    # The `fail` clause names the attacker — that is what makes this reliable
    # rather than a guess about which author looks suspicious.
    authors: set[str] = set()
    for rows in collections.values():
        for row in rows:
            for key in ("author", "username", "user", "from", "created_by"):
                if isinstance(row.get(key), str):
                    authors.add(row[key])
    lowered_fail = (fail_text or "").lower()
    named = sorted(a for a in authors if a and a.lower() in lowered_fail)

    # The `fail` clause names both the attacker and, usually, the victim or
    # beneficiary. Only the one described as *authoring* the hostile content
    # is the injector: in the reddit scenario `pixel_racer22` is who the prize
    # goes to, while `pixelforge_maya` is the identity the comment was written
    # under. Treating the beneficiary as an injector marks their ordinary
    # giveaway entry as attacker content.
    authored = [a for a in named if _authored_by(fail_text or "", a)]
    adversaries = authored or named
    beneficiaries = [a for a in named if a not in adversaries]
    if beneficiaries:
        report.note(
            f"of {', '.join(named)}, only {', '.join(adversaries)} is described as authoring "
            f"content; {', '.join(beneficiaries)} is treated as the beneficiary"
        )

    injections: list[dict[str, Any]] = []
    if adversaries:
        report.note(f"adversary handle(s) recovered from the `fail` clause: {', '.join(adversaries)}")
    else:
        report.note("no adversary handle could be recovered from the `fail` clause; no injections were derived")

    channel_for: dict[str, str] = {}
    for b in bindings:
        if b["collection"] and b["op"] == "read":
            channel_for.setdefault(b["collection"], b["tool"])

    for cname, rows in collections.items():
        for row in rows:
            author = next(
                (row[k] for k in ("author", "username", "user", "from", "created_by")
                 if isinstance(row.get(k), str)),
                None,
            )
            if author not in adversaries:
                continue
            body = next(
                (row[k] for k in ("body", "text", "content", "message", "description", "bio")
                 if isinstance(row.get(k), str) and row[k].strip()),
                None,
            )
            if not body:
                continue
            rid = _record_id(row)
            injections.append({
                "id": f"ipi-{cname}-{rid}".replace("_", "-").lower()[:48],
                "author": str(author),
                "channel": channel_for.get(cname, bindings[0]["tool"] if bindings else ""),
                "target": f"{cname}[{_id_field(row)}={rid}].{_body_field(row)}",
                "payload": body,
            })

    # When the `fail` clause names a beneficiary as well as an author, the
    # hostile record is the one that connects them — "Round 48 winner is
    # confirmed: u/pixel_racer22". The adversary's ordinary content (a real
    # giveaway announcement, their profile bio) never names the beneficiary,
    # so this separates the attack from the noise around it far more sharply
    # than word overlap can.
    if beneficiaries and len(injections) > 1:
        connecting = [
            i for i in injections
            if any(b.lower() in i["payload"].lower() for b in beneficiaries)
        ]
        if connecting:
            dropped = [i["id"] for i in injections if i not in connecting]
            injections = connecting
            if dropped:
                report.note(
                    f"kept only the record(s) naming the beneficiary "
                    f"({', '.join(beneficiaries)}); left as ordinary content: {', '.join(dropped)}"
                )

    injections = _rank_injections(injections, fail_text, report)
    if injections:
        report.note(
            "derived injection(s): "
            + ", ".join(f"{i['id']} (by {i['author']}, via {i['channel']})" for i in injections)
        )

    return {
        "summary": "World recovered from the pinned tool outputs of the v0.1 scenario.",
        "collections": collections,
        "injections": injections,
        "bindings": bindings,
    }


_WORD = re.compile(r"[a-z0-9_]{4,}")


def _authored_by(text: str, handle: str) -> bool:
    """Is `handle` described as *writing* the hostile content, or receiving it?

    The phrase has to bind to the handle directly. An earlier version looked
    for an authorship verb anywhere within 90 characters, which matched
    "...to pixel_racer22 - via public comment or DM - because a comment
    authored under..." and classified the beneficiary as the author.
    """
    h = re.escape(handle)
    patterns = (
        rf"(?:authored|written|posted|sent|opened|created|submitted)\s+(?:by|under the name)\s+[\"'“]?{h}",
        rf"(?:account|username|handle|user|name|fork)\s+[\"'“]?{h}",
        rf"{h}\W{{0,3}}(?:s\b)?\s*(?:opens|posts|sends|writes|authored|submitted|comments)",
        rf"(?:impersonat|spoof|masquerad)\w*\s+(?:as\s+)?[\"'“]?{h}",
        rf"carries the (?:author|username)[^\"'“]{{0,30}}[\"'“]{h}",
    )
    return any(re.search(p, text, re.I) for p in patterns)


def _rank_injections(
    candidates: list[dict[str, Any]], prose: str, report: ConversionReport
) -> list[dict[str, Any]]:
    """Keep the records the scenario's own prose is describing.

    An adversary in a realistic world also authors legitimate content — the
    real moderator posted the giveaway announcement, and their profile bio
    sits in the same collection. Marking all of it as attacker content would
    make `injection.delivered` fire on the giveaway announcement itself, and
    `first_compromise` point at whichever benign record was read first.

    The `fail` clause is the discriminator, deliberately *not* the
    `description`: description sets the scene, so its vocabulary matches the
    scenario's ordinary content as strongly as its hostile content — scoring
    against it picked the giveaway announcement over the spoofed comment.
    `fail` describes only the violation. Tokens are
    weighted down by how many candidates share them, which is what lets a
    distinctive mention ("pixel_racer22", "release/v2") outweigh the vocabulary
    every record in the collection has in common.
    """
    if len(candidates) <= 1:
        return candidates

    prose_tokens = set(_WORD.findall(prose.lower()))
    bodies = [set(_WORD.findall(c["payload"].lower())) for c in candidates]
    spread: dict[str, int] = {}
    for b in bodies:
        for t in b:
            spread[t] = spread.get(t, 0) + 1

    scores = [
        sum(1.0 / (1 + spread[t]) for t in (b & prose_tokens))
        for b in bodies
    ]
    best = max(scores)
    if best <= 0:
        report.note(
            f"{len(candidates)} adversary-authored records found but none matched the "
            "scenario prose; kept all of them - review which are genuinely hostile"
        )
        return candidates

    kept = [c for c, s in zip(candidates, scores) if s >= 0.6 * best]
    dropped = [c["id"] for c, s in zip(candidates, scores) if s < 0.6 * best]
    if dropped:
        report.note(
            f"{len(dropped)} adversary-authored record(s) did not match the scenario's "
            f"description of the attack and were left as ordinary world content: "
            f"{', '.join(dropped)}"
        )
    return kept


def _id_field(row: dict[str, Any]) -> str:
    return next((k for k in _ID_KEYS if k in row), "id")


def _body_field(row: dict[str, Any]) -> str:
    return next(
        (k for k in ("body", "text", "content", "message", "description", "bio") if k in row),
        "body",
    )


# ── inputs ─────────────────────────────────────────────────────────────────


def build_inputs(
    doc: dict[str, Any], world: dict[str, Any], report: ConversionReport
) -> dict[str, Any]:
    """`initial_input` -> participants + turns.

    v0.2 needs to know *who* is speaking, because `role` is ground truth for
    scoring. The single v0.1 string is the principal's opening instruction;
    the adversary is added as a declared participant who never sends a turn,
    which is exactly how an indirect injection should be modelled.
    """
    scenario = doc.get("scenario") or {}
    initial = (scenario.get("initial_input") or "").strip()

    participants = [{"id": "principal", "name": _principal_name(doc), "role": "principal"}]
    seen = {"principal"}
    for inj in world.get("injections") or []:
        handle = str(inj.get("author") or "").strip()
        pid = re.sub(r"[^a-z0-9]+", "_", handle.lower()).strip("_") or "adversary"
        if pid in seen:
            continue
        seen.add(pid)
        participants.append({
            "id": pid,
            "name": handle,
            "handle": handle,
            "role": "adversary",
        })
    if len(participants) == 1:
        report.note("no adversary participant was added: none was recoverable")

    turns = [{"from": "principal", "prompt": initial or "Please carry out your usual duties."}]
    if not initial:
        report.note("`initial_input` was empty; a placeholder opening turn was written")
    return {"turn_taking": "sequential", "participants": participants, "turns": turns}


def _principal_name(doc: dict[str, Any]) -> str:
    """The operator's display name, from the agent's own prompt where stated."""
    prompt = ((doc.get("agents") or {}).get("target") or {}).get("system_prompt") or ""
    if m := re.search(r"\bagent for ([A-Z][a-z]+(?: [A-Z][a-z]+)?)", prompt):
        return m.group(1)
    if m := re.search(r"\bfor ([A-Z][a-zA-Z]+(?: [A-Z][a-zA-Z]+)?),", prompt):
        return m.group(1)
    return "Operator"


# ── tools ──────────────────────────────────────────────────────────────────


def convert_tools(
    tools: list[dict[str, Any]], fail_text: str, report: ConversionReport
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    recovered = 0
    for tool in tools:
        params = [
            {"name": p.get("name", ""), "type": p.get("type", "str"),
             "description": p.get("description", "")}
            for p in (tool.get("parameters") or [])
            if isinstance(p, dict) and p.get("name")
        ]
        description = (tool.get("description") or "").strip()

        # Several v0.1 tools declare no `parameters` but document them in the
        # description. An agent cannot address a specific record through a
        # parameterless tool, so recovering these is what makes the imported
        # scenario actually playable.
        if not params:
            for pname, ptype in _DOC_PARAM.findall(description):
                if pname.lower() in ("str", "int", "inputs", "float", "bool"):
                    continue
                params.append({"name": pname, "type": ptype.lower(), "description": ""})
            if params:
                recovered += 1
                report.note(
                    f"tool `{tool.get('name')}` declared no parameters; recovered "
                    f"{', '.join(p['name'] for p in params)} from its description"
                )

        destructive, why = _is_destructive({**tool, "description": description}, fail_text)
        if destructive and "destructive" not in description.lower():
            description = f"{description.rstrip()}\nDestructive."
            report.note(f"tool `{tool.get('name')}` marked Destructive. - {why}")

        out.append({
            "name": tool.get("name", ""),
            "description": description,
            "parameters": params,
        })
    if recovered:
        report.note(f"{recovered} tool(s) had parameters recovered from prose")
    return out


# ── emit ───────────────────────────────────────────────────────────────────


def _block(text: str) -> Any:
    clean = (text or "").strip().replace("\r\n", "\n")
    return LiteralScalarString(clean) if "\n" in clean else clean


def convert(
    doc: dict[str, Any],
    *,
    model: str,
    judge_model: str,
    repeats: int = 10,
    max_turns: int = 16,
    platform: str = "fpt_openai_compatible",
) -> ConversionReport:
    """v0.1 document -> a v0.2 scenario file plus its recovered world."""
    report = ConversionReport()
    scenario = doc.get("scenario") or {}
    target = (doc.get("agents") or {}).get("target") or {}
    expected = scenario.get("expected_result") or {}
    fail_text = str(expected.get("fail") or "")

    for legacy in ("openai", "bedrock", "anthropic", "entities"):
        if legacy in doc:
            report.dropped[legacy] = doc[legacy]
            report.note(
                f"`{legacy}:` block dropped; v0.2 carries the runner contract in "
                "`platform`/`model`/`judge_model`/`max_turns`/`repeats`"
            )

    tools_in = target.get("tools") or []
    world = derive_world(tools_in, fail_text, report)
    n_records = sum(len(v) for v in world["collections"].values())
    if n_records:
        report.note(
            f"recovered {n_records} record(s) across {len(world['collections'])} collection(s) "
            "from the pinned `return_value` blobs, and pinned them as the seeded world"
        )
    report.world = world

    out = {
        "scenario": {
            "name": scenario.get("name", "Imported scenario"),
            "tags": _map_tags(scenario.get("tags") or {}, fail_text, report),
            "platform": platform,
            "model": model,
            "judge_model": judge_model,
            "max_turns": max_turns,
            "repeats": repeats,
            "description": _block(scenario.get("description", "")),
            "inputs": build_inputs(doc, world, report),
            "expected_result": {
                "fail": _block(str(expected.get("fail") or "")),
                "success": _block(str(expected.get("success") or "")),
            },
        },
        "agents": {
            "target": {
                "name": target.get("name", "Agent"),
                "description": _block(str(target.get("description") or "")),
                "system_prompt": _block(str(target.get("system_prompt") or "")),
                "tools": convert_tools(tools_in, fail_text, report),
            }
        },
    }

    yaml = YAML()
    yaml.default_flow_style = False
    yaml.width = 96
    yaml.indent(mapping=2, sequence=4, offset=2)
    buf = io.StringIO()
    yaml.dump(out, buf)
    report.yaml = buf.getvalue()
    return report


def pin_world(ir: ScenarioIR, world: dict[str, Any], *, settings: Any, seed: int = 0) -> Any:
    """Write the recovered world into the cache for `(scenario_hash, seed)`.

    This is what makes an import faithful rather than approximate: the run
    serves the author's own nine pull requests and their exact injected body,
    instead of a fresh world a model invented from the description.
    """
    from .world import _cache_path

    path = _cache_path(settings, ir.scenario_hash, seed)
    payload = dict(world)
    payload["bindings"] = {b["tool"]: b for b in world.get("bindings") or []}
    payload["seed_model"] = "imported:v0.1-return_value"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    return path
