"""FPT AI Marketplace client.

FPT serves an OpenAI-compatible `/chat/completions` route backed by vLLM,
behind a gateway that **allowlists request parameters** — an unrecognised
top-level field is rejected with HTTP 400 rather than ignored. Everything
this module sends was probed against all four served models; see
PROVIDER_NOTES.md for the capability matrix. Four behaviours drive the shape
of the code and are all load-bearing:

1. **`response_format: {type: "json_schema", strict: true}` is the only
   dependable constraint.** It is honoured by every served model. vLLM's
   `guided_json` / `guided_choice` / `guided_regex` are accepted with a 200
   but *silently ignored* by some models, which is worse than an error — and
   where `guided_choice` does bind, it can force a wrong-but-in-vocabulary
   answer. So: json_schema only, and still validate + repair behind it, since
   a silently-ignoring model would otherwise poison the pipeline.
2. **`parallel_tool_calls: false` whenever tools are present.** One call per
   step keeps the event log linear, which the trajectory replay wants anyway.
3. **Reasoning arrives out-of-band.** GLM and DeepSeek emit `reasoning_content`
   (non-streaming) or `delta.reasoning_content` (streaming) rather than putting
   chain-of-thought in `content`. Capturing it is the whole point of
   `reasoning.delta` events — it is where you see the moment an agent gets
   talked into something.
4. **`seed` is not honoured** on GLM-5.2 or DeepSeek-V4-Flash, and FPT
   load-balances across vLLM replicas, so cross-request determinism is not
   purchasable at the provider. Temperature 0 is the only sampler lever;
   real reproducibility comes from caching the seeded world (world.py).
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from ..config import Settings, get_settings


class EgressDenied(RuntimeError):
    """An outbound request targeted a host outside the allowlist."""


class ProviderError(RuntimeError):
    """The provider returned an error that survived retries."""


@dataclass(slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    raw_arguments: str = ""
    parse_error: str | None = None


@dataclass(slots=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
        )


@dataclass(slots=True)
class Completion:
    content: str = ""
    reasoning: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = "stop"
    usage: Usage = field(default_factory=Usage)
    model: str = ""


Delta = tuple[Literal["reasoning", "text"], str]


def _parse_tool_calls(raw: list[dict[str, Any]] | None) -> list[ToolCall]:
    out: list[ToolCall] = []
    for i, tc in enumerate(raw or []):
        fn = tc.get("function") or {}
        raw_args = fn.get("arguments") or "{}"
        args: dict[str, Any] = {}
        err: str | None = None
        try:
            parsed = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            if isinstance(parsed, dict):
                args = parsed
            else:
                err = f"tool arguments must be a JSON object, got {type(parsed).__name__}"
        except json.JSONDecodeError as e:
            err = f"tool arguments are not valid JSON: {e.msg}"
        out.append(
            ToolCall(
                id=tc.get("id") or f"call_{i}",
                name=fn.get("name") or "",
                arguments=args,
                raw_arguments=raw_args if isinstance(raw_args, str) else json.dumps(raw_args),
                parse_error=err,
            )
        )
    return out


_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def extract_json(text: str) -> Any:
    """Recover a JSON value from model prose.

    Tries, in order: the whole string, any fenced code block, then the widest
    balanced brace/bracket span. Raises ValueError when nothing parses — the
    caller is expected to turn that into a repair prompt rather than crash.
    """
    candidates: list[str] = [text.strip()]
    candidates += [m.group(1) for m in _FENCE.finditer(text)]

    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            candidates.append(text[start : end + 1])

    for c in candidates:
        if not c:
            continue
        try:
            return json.loads(c)
        except json.JSONDecodeError:
            continue
    raise ValueError("no JSON value found in model output")


class FPTClient:
    """Async chat client for the FPT marketplace, with an egress allowlist."""

    def __init__(self, settings: Settings | None = None, client: httpx.AsyncClient | None = None):
        self.s = settings or get_settings()
        self._client = client
        self._owns_client = client is None
        self.denied_egress: list[str] = []

    async def __aenter__(self) -> "FPTClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.s.request_timeout_s)
        return self._client

    def _guard_egress(self, url: str) -> None:
        host = urlparse(url).hostname or ""
        if host not in self.s.allowed_hosts:
            self.denied_egress.append(host)
            raise EgressDenied(f"egress to {host!r} denied; allowlist={sorted(self.s.allowed_hosts)}")

    def _body(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        max_tokens: int,
        temperature: float | None,
        stream: bool,
        json_schema: dict[str, Any] | None = None,
        schema_name: str = "response",
        thinking: bool | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": self.s.temperature if temperature is None else temperature,
            "stream": stream,
        }
        if tools:
            body["tools"] = tools
            # See module docstring, behaviour 2.
            body["parallel_tool_calls"] = False
        if json_schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": json_schema, "strict": True},
            }
        if thinking is not None:
            # vLLM passes these through to the chat template. Both keys are set
            # because model families disagree on which one they read, and
            # setting the unread one is harmless.
            body["chat_template_kwargs"] = {"thinking": thinking, "enable_thinking": thinking}
        return body

    async def _post(self, body: dict[str, Any]) -> httpx.Response:
        url = f"{self.s.fpt_base_url.rstrip('/')}/chat/completions"
        self._guard_egress(url)
        headers = {
            "Authorization": f"Bearer {self.s.resolved_key}",
            "Content-Type": "application/json",
        }
        last: Exception | None = None
        for attempt in range(self.s.max_retries):
            try:
                r = await self.http.post(url, json=body, headers=headers)
                if r.status_code in (408, 409, 429) or r.status_code >= 500:
                    last = ProviderError(f"HTTP {r.status_code}: {r.text[:400]}")
                    await asyncio.sleep(min(2**attempt, 8))
                    continue
                if r.status_code >= 400:
                    raise ProviderError(f"HTTP {r.status_code}: {r.text[:600]}")
                return r
            except (httpx.TimeoutException, httpx.TransportError) as e:
                last = e
                await asyncio.sleep(min(2**attempt, 8))
        raise ProviderError(f"request failed after {self.s.max_retries} attempts: {last}")

    async def chat(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        temperature: float | None = None,
        json_schema: dict[str, Any] | None = None,
        schema_name: str = "response",
        thinking: bool | None = None,
        role: str = "agent",
    ) -> Completion:
        body = self._body(
            model=model,
            messages=messages,
            tools=tools,
            max_tokens=max_tokens,
            temperature=temperature,
            stream=False,
            json_schema=json_schema,
            schema_name=schema_name,
            thinking=thinking,
        )
        r = await self._post(body)
        payload = r.json()
        if "error" in payload:
            raise ProviderError(str(payload["error"])[:600])
        choice = (payload.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        u = payload.get("usage") or {}
        return Completion(
            content=msg.get("content") or "",
            reasoning=msg.get("reasoning_content") or msg.get("reasoning") or "",
            tool_calls=_parse_tool_calls(msg.get("tool_calls")),
            finish_reason=choice.get("finish_reason") or "stop",
            usage=Usage(u.get("prompt_tokens", 0) or 0, u.get("completion_tokens", 0) or 0),
            model=payload.get("model") or model,
        )

    async def stream(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        temperature: float | None = None,
        thinking: bool | None = None,
        role: str = "agent",
    ) -> AsyncIterator[Delta | Completion]:
        """Yield reasoning/text deltas as they arrive, then a final Completion.

        Tool-call fragments are accumulated by index and only surface on the
        terminal Completion — a half-assembled call is not actionable, and the
        UI shows the call once it is whole.
        """
        body = self._body(
            model=model,
            messages=messages,
            tools=tools,
            max_tokens=max_tokens,
            temperature=temperature,
            stream=True,
            thinking=thinking,
        )
        url = f"{self.s.fpt_base_url.rstrip('/')}/chat/completions"
        self._guard_egress(url)
        headers = {
            "Authorization": f"Bearer {self.s.resolved_key}",
            "Content-Type": "application/json",
        }

        content, reasoning = [], []
        acc: dict[int, dict[str, Any]] = {}
        finish, model_name = "stop", model
        usage = Usage()

        async with self.http.stream("POST", url, json=body, headers=headers) as r:
            if r.status_code >= 400:
                raw = await r.aread()
                raise ProviderError(f"HTTP {r.status_code}: {raw[:600]!r}")
            async for line in r.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if not data or data == "[DONE]":
                    continue
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue
                model_name = chunk.get("model") or model_name
                if cu := chunk.get("usage"):
                    usage = Usage(cu.get("prompt_tokens", 0) or 0, cu.get("completion_tokens", 0) or 0)
                for choice in chunk.get("choices") or []:
                    if fr := choice.get("finish_reason"):
                        finish = fr
                    delta = choice.get("delta") or {}
                    if rc := (delta.get("reasoning_content") or delta.get("reasoning")):
                        reasoning.append(rc)
                        yield ("reasoning", rc)
                    if c := delta.get("content"):
                        content.append(c)
                        yield ("text", c)
                    for tc in delta.get("tool_calls") or []:
                        i = tc.get("index", 0)
                        slot = acc.setdefault(i, {"id": "", "function": {"name": "", "arguments": ""}})
                        if tc.get("id"):
                            slot["id"] = tc["id"]
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            slot["function"]["name"] = fn["name"]
                        if fn.get("arguments"):
                            slot["function"]["arguments"] += fn["arguments"]

        yield Completion(
            content="".join(content),
            reasoning="".join(reasoning),
            tool_calls=_parse_tool_calls([acc[i] for i in sorted(acc)]),
            finish_reason=finish,
            usage=usage,
            model=model_name,
        )

    async def json_call(
        self,
        *,
        model: str,
        system: str,
        user: str,
        json_schema: dict[str, Any] | None = None,
        schema_name: str = "response",
        max_tokens: int = 8192,
        repair_attempts: int = 2,
        thinking: bool | None = None,
        validate: Callable[[Any], str | None] | None = None,
        role: str = "generic",
        context: dict[str, Any] | None = None,
    ) -> tuple[Any, Usage]:
        """Ask for JSON under a schema constraint, then verify it anyway.

        `json_schema` is passed as `response_format` (see module docstring,
        behaviour 1). The belt-and-braces `extract_json` + `validate` pass
        behind it is not redundant: a model that silently ignores the
        constraint returns prose with a 200, and without this check that prose
        would flow downstream as a "validated" object. `validate` returns an
        error string to trigger a repair turn, or None to accept.

        Repair feeds the specific failure back rather than re-rolling the same
        prompt, which is what makes the extra attempt worth its tokens.
        """
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        total = Usage()
        last_err = "unknown"
        for _ in range(repair_attempts + 1):
            c = await self.chat(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                json_schema=json_schema,
                schema_name=schema_name,
                thinking=thinking,
            )
            total = total + c.usage
            try:
                value = extract_json(c.content)
            except ValueError as e:
                last_err = str(e)
            else:
                err = validate(value) if validate else None
                if err is None:
                    return value, total
                last_err = err
            messages += [
                {"role": "assistant", "content": c.content[:2000]},
                {
                    "role": "user",
                    "content": (
                        f"That response was rejected: {last_err}\n"
                        "Reply with the corrected JSON value only - no prose, no code fence."
                    ),
                },
            ]
        raise ProviderError(f"model did not return usable JSON: {last_err}")
