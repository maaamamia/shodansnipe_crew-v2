"""
cached_llm.py — make sure Anthropic prompt caching is actually ON for every agent.

The important discovery: CrewAI 1.x does prompt caching for you. Its agent executor
marks cache breakpoints automatically (end-of-system = the agent's stable persona /
doctrine / rules; end-of-user = the task prefix, reused across the many turns of a
ReAct loop), and the NATIVE Anthropic provider translates those markers into Anthropic
`cache_control`. Cache reads bill at ~10% of input and skip recompute — a big win for
loops like recon (up to 55 iterations re-sending the same large prefix).

So there is nothing to add per-agent. You only need the native Anthropic provider to be
the thing handling the call. That requires:
  1. crewai >= 1.x          (has the auto-marking executor + native providers)
  2. pip install "crewai[anthropic]"   (installs the native provider)
  3. the LLM routed to it    (model "anthropic/claude-..." OR provider="anthropic")

`make_llm(**kwargs)` builds the LLM and, on older CrewAI that lacks the native path,
falls back to injecting cache_control through the LiteLLM message path. `cache_status()`
tells you which path is active so you can confirm caching is really on.

Toggle off with PROMPT_CACHE=0.
"""
from __future__ import annotations

import os


def _enabled() -> bool:
    return os.environ.get("PROMPT_CACHE", "1").lower() not in ("0", "false", "no", "off")


def cache_status() -> dict:
    """Report whether native Anthropic prompt caching is available in this install."""
    has_cache_api = native_provider = False
    try:
        from crewai.llms.cache import mark_cache_breakpoint  # noqa: F401  (1.x only)
        has_cache_api = True
    except Exception:
        pass
    try:
        from crewai.llms.providers.anthropic.completion import (  # noqa: F401
            AnthropicCompletion,
        )
        native_provider = True
    except Exception:
        pass
    return {
        "prompt_cache_enabled": _enabled(),
        "crewai_auto_breakpoints": has_cache_api,   # executor marks breakpoints
        "native_anthropic_provider": native_provider,  # translates them to cache_control
        "automatic": has_cache_api and native_provider,
    }


# ── Fallback for OLDER CrewAI (no native provider / no auto-marking) ──────────
# On crewai 1.x this class is never used (LLM.__new__ returns the native provider),
# so the brittle internals here only run on older litellm-based builds.
_CACHE_MIN_CHARS = int(os.environ.get("PROMPT_CACHE_MIN_CHARS", "4000"))


def _make_litellm_cached_cls():
    from crewai import LLM

    class _LiteLLMCached(LLM):
        def _is_anthropic(self) -> bool:
            m = (getattr(self, "model", "") or "").lower()
            return "anthropic" in m or "claude" in m

        def _prepare_completion_params(self, messages, tools=None, **kw):
            params = super()._prepare_completion_params(messages, tools, **kw)
            try:
                if _enabled() and self._is_anthropic():
                    msgs = params.get("messages")
                    if isinstance(msgs, list):
                        sys_i = next((i for i in range(len(msgs) - 1, -1, -1)
                                      if msgs[i].get("role") == "system"), None)
                        usr_i = next((i for i, m in enumerate(msgs)
                                      if m.get("role") == "user"), None)
                        for i in (sys_i, usr_i):
                            if i is None:
                                continue
                            c = msgs[i].get("content")
                            if isinstance(c, str) and len(c) >= _CACHE_MIN_CHARS:
                                msgs[i]["content"] = [{"type": "text", "text": c,
                                                       "cache_control": {"type": "ephemeral"}}]
            except Exception:
                pass
            return params

    return _LiteLLMCached


def make_llm(**kwargs):
    """Build an LLM with prompt caching active wherever possible."""
    from crewai import LLM
    model = (kwargs.get("model") or "").lower()
    is_anthropic = ("anthropic" in model or "claude" in model
                    or kwargs.get("provider") == "anthropic")
    st = cache_status()
    # crewai 1.x: native provider + auto-marking handle caching. Plain LLM is correct.
    if st["crewai_auto_breakpoints"] or not is_anthropic or not _enabled():
        return LLM(**kwargs)
    # older crewai, anthropic, caching wanted: inject via litellm path.
    try:
        return _make_litellm_cached_cls()(**kwargs)
    except Exception:
        return LLM(**kwargs)
