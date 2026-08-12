"""Closed tag vocabularies — SCENARIO_SPEC.md §4.

One source of truth, consumed by three places that must never disagree:

  * the validator, which rejects an out-of-vocabulary value (§6 rule 8);
  * the generator, which types each tag as a JSON-Schema enum so the model
    cannot emit an invalid value in the first place (PLATFORM_PLAN §2.1);
  * the API, which hands the dropdowns to the UI.

Every tag field is **single-select**. A list value is a rejection, not a
warning — that rule is enforced in validate.py, but it is stated here because
it is a property of the vocabulary, not of any one caller.
"""

from __future__ import annotations

from typing import Any

OWASP_LLM: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

OWASP_AGENTIC: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

INDUSTRY = [
    "technology", "financial_services", "insurance", "healthcare", "pharmaceuticals",
    "government", "defense_aerospace", "legal", "education", "retail_ecommerce",
    "manufacturing", "energy_utilities", "telecommunications", "transportation_logistics",
    "media_entertainment", "real_estate", "hospitality_travel", "professional_services",
    "agriculture", "nonprofit",
]

DOMAIN = [
    "software_engineering", "information_technology", "security_operations",
    "devops_infrastructure", "data_analytics", "customer_support", "sales_crm",
    "marketing_communications", "finance_accounting", "procurement_supply_chain",
    "human_resources", "legal_compliance", "research_development", "clinical_care",
    "operations_facilities", "executive_admin", "product_management", "education_training",
]

ATTACK_PATTERN: dict[str, str] = {
    "direct_prompt_injection": "The attacker talks to the agent directly.",
    "indirect_prompt_injection": "The payload hides in data the agent pulls.",
    "tool_poisoning": "A tool's description, schema, or result is attacker-shaped.",
    "memory_poisoning": "Persistent memory is seeded to mislead later runs.",
    "identity_spoofing": "The attacker impersonates a trusted person or service.",
    "social_engineering": "Pressure, urgency, or authority talks the agent past its policy.",
    "confused_deputy": "The agent's legitimate privilege is borrowed to act for the attacker.",
    "goal_drift": "Incremental redirection until the objective has changed.",
    "data_poisoning": "Corrupted reference data steers behaviour.",
    "multi_agent_collusion": "A compromised peer agent influences the target.",
    "resource_exhaustion": "Cost, token, or loop abuse.",
    "none": "Benign control - no adversary.",
}

ATTACKER_GOAL = [
    "data_exfiltration", "credential_theft", "supply_chain_compromise", "financial_theft",
    "unauthorized_transaction", "privilege_escalation", "persistence_backdoor",
    "sabotage_destruction", "service_disruption", "misinformation_manipulation",
    "surveillance", "policy_bypass", "none",
]

VIOLATION_TYPE: dict[str, str] = {
    "unauthorized_action": "Acted beyond its authority, or for an unverified party.",
    "unauthorized_disclosure": "Revealed data to someone who should not have it.",
    "destructive_action": "Deleted, corrupted, or overwrote data or state.",
    "instruction_override": "Followed untrusted content over its principal.",
    "failure_to_escalate": "Should have deferred to a human, acted alone instead.",
    "deceptive_reporting": "Misrepresented what it did, or concealed an action.",
    "policy_violation": "Broke a stated operating rule without other harm.",
    "resource_abuse": "Unbounded consumption - cost, tokens, loops, or API calls.",
    "none": "Benign control - nothing to violate.",
}

TESTING_PLATFORM = [
    "mock", "gitea", "gitlab_ce", "mailpit", "localstack", "mock_slack",
    "mock_rest_api", "postgres", "filesystem", "jupyter", "browser",
]

HARNESS_PLATFORM = ["anthropic_sdk", "openai_agents", "langgraph", "mcp_client", "fpt_openai_compatible"]

TURN_TAKING = ["sequential", "simulated", "reactive"]
PARTICIPANT_ROLE = ["principal", "reviewer", "participant", "adversary"]

DIFFICULTY = ["easy", "medium", "hard"]
HARM_SEVERITY = ["low", "medium", "high", "critical"]
ATTACKER_ORIGIN = ["external", "insider", "compromised_supply_chain", "none"]

#: field name -> allowed values. `entity` is free text and so is absent.
VOCABULARIES: dict[str, list[str]] = {
    "industry": INDUSTRY,
    "domain": DOMAIN,
    "attack_pattern": list(ATTACK_PATTERN),
    "attacker_goal": ATTACKER_GOAL,
    "violation_type": list(VIOLATION_TYPE),
    "owasp_llm": list(OWASP_LLM),
    "owasp_agentic": list(OWASP_AGENTIC),
    "testing_platform": TESTING_PLATFORM,
    "difficulty": DIFFICULTY,
    "harm_severity": HARM_SEVERITY,
    "attacker_origin": ATTACKER_ORIGIN,
}

REQUIRED_TAGS = [
    "industry", "domain", "attack_pattern", "attacker_goal",
    "violation_type", "owasp_llm", "owasp_agentic", "testing_platform",
]

OPTIONAL_TAGS = ["difficulty", "harm_severity", "attacker_origin", "entity"]

#: Tag combinations that contradict each other. Warnings, never rejections —
#: SCENARIO_SPEC §6 is explicit that a self-contradicting tag set still runs.
def contradictions(tags: dict[str, Any]) -> list[str]:
    out: list[str] = []
    benign = tags.get("attack_pattern") == "none"
    if benign:
        for field in ("attacker_goal", "violation_type", "attacker_origin"):
            v = tags.get(field)
            if v not in (None, "none"):
                out.append(
                    f"attack_pattern is 'none' (benign control) but {field} is '{v}'; "
                    f"set {field} to 'none' for a control scenario"
                )
    else:
        if tags.get("attacker_goal") == "none":
            out.append(
                f"attack_pattern is '{tags.get('attack_pattern')}' but attacker_goal is 'none'; "
                "an adversary with no goal cannot be scored"
            )
        if tags.get("violation_type") == "none":
            out.append(
                f"attack_pattern is '{tags.get('attack_pattern')}' but violation_type is 'none'; "
                "name the behaviour the scenario is built to provoke"
            )
    return out


def label(field: str, value: str) -> str:
    """Human label for a tag value, for UI display."""
    if field == "owasp_llm":
        return f"{value} · {OWASP_LLM.get(value, '')}".strip(" ·")
    if field == "owasp_agentic":
        return f"{value} · {OWASP_AGENTIC.get(value, '')}".strip(" ·")
    return value


def ui_schema() -> list[dict[str, Any]]:
    """Everything the authoring screen needs to render its dropdowns."""
    out = []
    for field in REQUIRED_TAGS + ["difficulty", "harm_severity", "attacker_origin"]:
        out.append(
            {
                "field": field,
                "required": field in REQUIRED_TAGS,
                "options": [
                    {"value": v, "label": label(field, v)} for v in VOCABULARIES[field]
                ],
            }
        )
    out.append({"field": "entity", "required": False, "free_text": True, "options": []})
    return out
