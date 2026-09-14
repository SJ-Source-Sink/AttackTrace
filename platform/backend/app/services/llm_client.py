"""
Provider-agnostic LLM client — the single seam every AI-calling code path in
the backend goes through, so "Claude API" vs. "self-hosted Qwen" (or any
other OpenAI-compatible server) is a config choice (`ai_config["provider"]`),
never a per-call-site branch.

There are three calling conventions used across the codebase, each with one
function here: a plain single-shot completion (`complete`), a streamed
completion (`stream_complete`), and one turn of a tool-use agent loop
(`chat_turn` + `build_tool_result_messages`). Tool schemas are always authored
once in Anthropic's native shape (`{"name","description","input_schema"}`) —
`chat_turn` converts to OpenAI's `{"type":"function","function":{...}}` shape
internally when the provider is "qwen", since both `input_schema` and
`parameters` are already JSON Schema.

`ai_config` is the dict produced by `app.services.ai_service.get_org_ai_config`:
`{"provider": "anthropic" | "qwen", "api_key", "base_url", "model"}`.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

import anthropic
import openai

from app.services.ai_activity import publish_activity

_DEFAULT_TIMEOUT = 60.0


class LLMConfigError(RuntimeError):
    """Raised when ai_config is missing what the selected provider needs."""


def _provider(ai_config: dict) -> str:
    return (ai_config or {}).get("provider") or "anthropic"


def _anthropic_client(ai_config: dict) -> anthropic.AsyncAnthropic:
    api_key = ai_config.get("api_key")
    if not api_key:
        raise LLMConfigError("ANTHROPIC_API_KEY is not configured")
    kwargs: dict = {"api_key": api_key, "timeout": _DEFAULT_TIMEOUT}
    if ai_config.get("base_url"):
        kwargs["base_url"] = ai_config["base_url"]
    return anthropic.AsyncAnthropic(**kwargs)


def _openai_client(ai_config: dict) -> openai.AsyncOpenAI:
    base_url = ai_config.get("base_url")
    if not base_url:
        raise LLMConfigError("Qwen base_url is not configured")
    # Self-hosted OpenAI-compatible servers frequently need no key at all —
    # the SDK still requires a non-empty string, so use an inert placeholder.
    api_key = ai_config.get("api_key") or "not-required"
    return openai.AsyncOpenAI(api_key=api_key, base_url=base_url, timeout=_DEFAULT_TIMEOUT)


def _model(ai_config: dict, default: str = "gpt-3.5-turbo") -> str:
    return ai_config.get("model") or default


async def _publish(
    ai_config: dict, label: str, system: Optional[str], messages: list, tools: Optional[list],
    status: str, response: Optional[str], tool_calls: Optional[list], error: Optional[str], start: float,
) -> None:
    org_id = ai_config.get("org_id")
    if not org_id:
        return
    await publish_activity(str(org_id), {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "org_id": str(org_id),
        "label": label,
        "provider": _provider(ai_config),
        "model": ai_config.get("model"),
        "system": system,
        "messages": messages,
        "tools": tools,
        "status": status,
        "response": response,
        "tool_calls": tool_calls,
        "error": error,
        "latency_ms": round((time.monotonic() - start) * 1000),
    })


async def complete(ai_config: dict, system: Optional[str], messages: list[dict], max_tokens: int, label: str = "unknown") -> str:
    """Plain single-shot completion. `messages` is provider-agnostic:
    [{"role": "user"|"assistant", "content": str}, ...]."""
    start = time.monotonic()
    try:
        if _provider(ai_config) == "qwen":
            async with _openai_client(ai_config) as client:
                full_messages = ([{"role": "system", "content": system}] if system else []) + messages
                resp = await client.chat.completions.create(
                    model=_model(ai_config), messages=full_messages, max_tokens=max_tokens,
                )
                result = (resp.choices[0].message.content or "").strip()
        else:
            async with _anthropic_client(ai_config) as client:
                kwargs: dict = {"model": _model(ai_config, "claude-sonnet-4-6"), "max_tokens": max_tokens, "messages": messages}
                if system:
                    kwargs["system"] = system
                resp = await client.messages.create(**kwargs)
                result = resp.content[0].text.strip()
    except Exception as exc:
        await _publish(ai_config, label, system, messages, None, "error", None, None, str(exc), start)
        raise
    await _publish(ai_config, label, system, messages, None, "success", result, None, None, start)
    return result


async def stream_complete(ai_config: dict, system: Optional[str], messages: list[dict], max_tokens: int, label: str = "unknown") -> AsyncGenerator[str, None]:
    """Streamed completion — yields text deltas as they arrive. Publishes one
    activity event after the stream is exhausted (the full assembled text),
    not one per chunk."""
    start = time.monotonic()
    full_text = ""
    try:
        if _provider(ai_config) == "qwen":
            async with _openai_client(ai_config) as client:
                full_messages = ([{"role": "system", "content": system}] if system else []) + messages
                stream = await client.chat.completions.create(
                    model=_model(ai_config), messages=full_messages, max_tokens=max_tokens, stream=True,
                )
                async for chunk in stream:
                    delta = chunk.choices[0].delta.content if chunk.choices else None
                    if delta:
                        full_text += delta
                        yield delta
        else:
            async with _anthropic_client(ai_config) as client:
                kwargs: dict = {"model": _model(ai_config, "claude-sonnet-4-6"), "max_tokens": max_tokens, "messages": messages}
                if system:
                    kwargs["system"] = system
                async with client.messages.stream(**kwargs) as stream:
                    async for text in stream.text_stream:
                        full_text += text
                        yield text
    except Exception as exc:
        await _publish(ai_config, label, system, messages, None, "error", full_text or None, None, str(exc), start)
        raise
    await _publish(ai_config, label, system, messages, None, "success", full_text, None, None, start)


def _anthropic_tools(tools: list[dict]) -> list[dict]:
    return tools


def _openai_tools(tools: list[dict]) -> list[dict]:
    return [
        {"type": "function", "function": {"name": t["name"], "description": t.get("description", ""), "parameters": t.get("input_schema", {"type": "object", "properties": {}})}}
        for t in tools
    ]


async def chat_turn(ai_config: dict, system: Optional[str], messages: list, tools: list[dict], max_tokens: int, label: str = "unknown") -> dict:
    """One turn of a tool-use agent loop. Returns a normalized
    {"text": list[str], "tool_calls": [{"id","name","input"}], "assistant_message": <opaque, append to `messages`>}.

    `messages` accumulates provider-native shapes from turn 2 onward — callers
    must only ever append what this function and `build_tool_result_messages`
    return, never construct assistant/tool messages themselves.
    """
    start = time.monotonic()
    try:
        if _provider(ai_config) == "qwen":
            async with _openai_client(ai_config) as client:
                full_messages = ([{"role": "system", "content": system}] if system else []) + messages
                resp = await client.chat.completions.create(
                    model=_model(ai_config), messages=full_messages, max_tokens=max_tokens,
                    tools=_openai_tools(tools) if tools else None,
                )
                msg = resp.choices[0].message
                text = [msg.content] if msg.content else []
                tool_calls = []
                raw_tool_calls = []
                for tc in (msg.tool_calls or []):
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    tool_calls.append({"id": tc.id, "name": tc.function.name, "input": args})
                    raw_tool_calls.append({"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"}})
                assistant_message: dict = {"role": "assistant", "content": msg.content}
                if raw_tool_calls:
                    assistant_message["tool_calls"] = raw_tool_calls
        else:
            async with _anthropic_client(ai_config) as client:
                kwargs: dict = {
                    "model": _model(ai_config, "claude-sonnet-4-6"), "max_tokens": max_tokens, "messages": messages,
                    "tools": _anthropic_tools(tools),
                }
                if system:
                    kwargs["system"] = system
                resp = await client.messages.create(**kwargs)
                content = resp.content
                text = [b.text for b in content if b.type == "text"]
                tool_calls = [{"id": b.id, "name": b.name, "input": b.input} for b in content if b.type == "tool_use"]
                assistant_message = {"role": "assistant", "content": content}
    except Exception as exc:
        await _publish(ai_config, label, system, messages, tools, "error", None, None, str(exc), start)
        raise
    await _publish(ai_config, label, system, messages, tools, "success", "\n".join(text) or None, tool_calls, None, start)
    return {"text": text, "tool_calls": tool_calls, "assistant_message": assistant_message}


def build_tool_result_messages(ai_config: dict, results: list[dict]) -> list[dict]:
    """`results` is [{"id": tool_call_id, "content": str}, ...] — the message(s)
    to append to `messages` after executing the requested tool calls."""
    if _provider(ai_config) == "qwen":
        return [{"role": "tool", "tool_call_id": r["id"], "content": r["content"]} for r in results]
    return [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": r["id"], "content": r["content"]} for r in results]}]
