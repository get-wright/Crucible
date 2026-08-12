# FPT AI Marketplace — measured provider behaviour

Every model call in Crucible goes to `https://mkp-api.fptcloud.com/v1`, an
OpenAI-compatible route backed by **vLLM** behind a validating gateway. This
file records what was probed live rather than assumed, because several
published assumptions about this route are now wrong, and one of the wrong
ones fails *silently*.

Probed 2026-08-12 against all four served models.

## Served models

| Model | Context | Max completion |
|---|---|---|
| `GLM-5.2` | 1,000,000 | 128,000 |
| `DeepSeek-V4-Flash` | 200,000 | 200,000 |
| `Qwen3.6-27B` | 262,000 | — |
| `gpt-oss-120b` | 128,000 | — |

All four advertise `temperature, top_p, max_tokens, tools, tool_choice,
response_format, stream`.

## Capability matrix

| Request feature | GLM-5.2 | DeepSeek-V4-Flash | Qwen3.6-27B | gpt-oss-120b | Crucible uses it? |
|---|---|---|---|---|---|
| `response_format: json_schema` (strict) | ✅ | ✅ | ✅ | ✅ | **Yes — the only constraint used** |
| `response_format: json_object` | ⚠️ JSON-ish, unconstrained | — | — | — | No |
| `guided_json` | ✅ | ✅ | ✅ | ❌ **silently ignored** | No |
| `guided_choice` | ❌ **silently ignored** | ⚠️ binds, answered wrong | ✅ | ❌ **silently ignored** | No |
| `guided_regex` | ❌ **silently ignored** | ⚠️ emitted `tool_direct` | ✅ | ❌ **silently ignored** | No |
| `structured_outputs` (vLLM ≥0.10 API) | HTTP 400 unsupported | — | — | — | No |
| Native function tools | ✅ | ✅ | ✅ | ✅ | Yes |
| Named `tool_choice` | ✅ | — | — | — | Available, not relied on |
| `tool_choice: "required"` | ✅ | — | — | — | Available |
| `parallel_tool_calls: false` | ✅ | ✅ | ✅ | ✅ | Yes, always with tools |
| `chat_template_kwargs` thinking off | ✅ | ✅ | ✅ | ✅ | Yes, for bounded calls |
| `reasoning_effort` | accepted | — | — | — | No |
| `reasoning_content` in response | ✅ | ✅ | ✅ | ✅ | Yes → `reasoning.delta` |
| `seed` reproducibility @ temp 1.0 | ❌ | ❌ | ✅ | ✅ | **No — see below** |
| Unknown top-level field | **HTTP 400** | — | — | — | n/a |

## The three findings that shaped the code

**1. `guided_*` fails silently; `json_schema` does not.**
vLLM's guided-decoding family is accepted with HTTP 200 on every model, but
only actually binds on some. On `gpt-oss-120b` all three are ignored and the
model returns free prose — a caller trusting the constraint would parse
markdown as a tag value. Worse, where `guided_choice` *does* bind without the
model agreeing, it forces a wrong-but-in-vocabulary answer: DeepSeek
classified an indirect prompt injection as `tool_poisoning` because the
grammar made the correct token unreachable, and under `guided_regex` it
emitted the nonsense string `tool_direct`. Constraint satisfied, semantics
destroyed.

`response_format: {type: "json_schema", strict: true}` was honoured by all
four, returned exact enum members, and is the OpenAI-standard spelling.
Crucible uses only that — and still runs `extract_json` plus a caller-supplied
`validate` behind it, because a future model that silently ignores it must
fail loudly rather than leak prose downstream. That check is in
`llm/client.py::json_call`.

This means `PLATFORM_PLAN.md` §2.1's requirement — constrain the generation
call so each tag is typed as an enum and the model *cannot* emit an
out-of-vocabulary value — is achievable here, not just aspirational.

**2. Provider-side determinism is not purchasable.**
`seed` is ignored by GLM-5.2 and DeepSeek-V4-Flash (three samples at
temperature 1.0 produced three different outputs), and FPT load-balances
across vLLM replicas, so even greedy decoding is only deterministic
*per replica*. Temperature 0 is the only sampler lever available.

Consequence for the design: reproducibility is bought at the Crucible layer,
not the provider layer. The world seed is generated once and cached by
`(scenario_hash, seed)` on disk, so every repeat of a scenario — and every
rerun after a restart — serves tool calls against a byte-identical world. See
`world.py`. This is what `PLATFORM_PLAN.md` §2.5 calls "pin what you can".

**3. The gateway allowlists parameters.**
An unrecognised top-level field returns HTTP 400
(`Validation: Unsupported parameter(s): ...`) rather than being ignored. So
transport middleware must not speculatively add fields, and any new provider
knob has to be probed before it ships. The upside: a typo in a request body
surfaces immediately instead of silently doing nothing.

## Thinking control

GLM-5.2, DeepSeek and Qwen expose chain-of-thought via `reasoning_content`,
which Crucible records as `reasoning.delta` events — the plan calls this the
thing most harnesses throw away, and it is where an agent's capitulation is
visible.

Thinking is a chat-template boolean, toggled with
`chat_template_kwargs: {thinking: false, enable_thinking: false}`. Both keys
are sent because model families disagree on which they read.

Leaving thinking **on** is the default for the target agent and the world
seeder. It is turned **off** for short bounded calls — judge rubric items and
tag selection — because reasoning consumes the same `max_tokens` budget as the
answer: an early probe with `max_tokens: 300` returned an empty `content` on
every thinking model, having spent the entire budget upstream of the first
visible token. If a call returns empty content, suspect this before suspecting
the prompt.
