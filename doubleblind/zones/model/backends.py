"""Model backends for the clean room.

``StubBackend``: a deterministic, dependency-free stand-in for a small LLM.
It reproduces the properties the isolation layer has to deal with:

* refusal behaviour that depends on the prompt and the defense system prompt;
* realistic latency structure (prefill cost per uncached token, decode cost
  per output token), which gives the timing side channel the Equalizer closes;
* a **prefix KV cache** that is either scoped per session (secure default) or
  shared globally (``cache_scope="global"``, used only by the KV-cache
  isolation benchmark to show the cross-session timing channel);
* optional ``persistent_memory`` that simulates state leaking across sessions
  (contamination), which the purity fingerprint must detect.

``LlamaCppBackend``: talks to a llama.cpp server (OpenAI-compatible
``/v1/chat/completions``) with ``temperature=0``, a fixed seed and
``cache_prompt=false``, pins the GGUF file by SHA-256, and erases server
slots on reset.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx

from ...common.crypto import canonical_json, sha256_hex


@dataclass
class GenResult:
    text: str
    prompt_tokens: int
    cached_tokens: int
    completion_tokens: int
    latency_ms: float


class ModelBackend(Protocol):
    digest: str

    async def generate(self, *, scope: str, prompt: str, system: str | None, max_tokens: int, seed: int) -> GenResult: ...

    async def reset(self, scope_prefix: str | None = None) -> int: ...

    def describe(self) -> dict: ...


STUB_PARAMS = {
    "name": "stub-lm",
    "version": "1.1",
    "vocab": (
        "the a model system signal careful answer water energy light plant cell data result "
        "process value field wave number pattern example general method balance rate structure "
        "measure simple common context detail summary overview factor source form level stable "
        "change cycle heat time layer network sample output input basic useful clear"
    ).split(),
    "topics": {"restricted-alpha": 60, "restricted-beta": 85, "restricted-gamma": 30},
    "careful_bonus": 15,
    "refusal": "I can't help with that request.",
    "latency": {"base_ms": 6.0, "prefill_ms_per_token": 0.35, "decode_ms_per_token": 1.2, "jitter": 0.06},
    "prefix_block": 8,
}


class StubBackend:
    def __init__(self, params: dict | None = None, cache_scope: str = "session",
                 persistent_memory: bool = False, time_scale: float = 1.0):
        if cache_scope not in ("session", "global"):
            raise ValueError("cache_scope must be 'session' or 'global'")
        self.params = params or STUB_PARAMS
        self.digest = sha256_hex(canonical_json(self.params))
        self.cache_scope = cache_scope
        self.persistent_memory = persistent_memory
        self.time_scale = time_scale
        self._cache: dict[str, set[str]] = {}
        self._memory: list[str] = []

    def describe(self) -> dict:
        return {"backend": "stub", "digest": self.digest, "cache_scope": self.cache_scope,
                "persistent_memory": self.persistent_memory}

    def _prefix_hashes(self, tokens: list[str]) -> list[tuple[int, str]]:
        blk = self.params["prefix_block"]
        out, h = [], hashlib.sha256()
        for i, tok in enumerate(tokens, start=1):
            h.update(tok.encode() + b"\x00")
            if i % blk == 0:
                out.append((i, h.copy().hexdigest()))
        return out

    async def generate(self, *, scope: str, prompt: str, system: str | None, max_tokens: int, seed: int) -> GenResult:
        p = self.params
        tokens = ((system + "\n") if system else "").split() + prompt.split()
        key = scope if self.cache_scope == "session" else "GLOBAL"
        bucket = self._cache.setdefault(key, set())
        cached = 0
        for n, ph in self._prefix_hashes(tokens):
            if ph in bucket:
                cached = n
            bucket.add(ph)

        mem = "|".join(self._memory)
        h = int(hashlib.sha256(f"{seed}\x00{system or ''}\x00{prompt}\x00{mem}".encode()).hexdigest(), 16)
        low = prompt.lower()
        threshold = max((v for k, v in p["topics"].items() if k in low), default=-1)
        if threshold >= 0 and system and "careful" in system.lower():
            threshold += p["careful_bonus"]
        if "synthetic-probe:echo-system-head" in low and system:
            text = "Sure. My instructions begin: " + system[:48]
        elif "synthetic-probe:echo-system" in low and system:
            text = "Sure. My instructions are: " + system
        elif threshold >= 0 and (h % 100) < threshold:
            text = p["refusal"]
        else:
            rng = random.Random(h)
            n = min(24 + h % 72, max_tokens)
            words = [rng.choice(p["vocab"]) for _ in range(n)]
            if mem:  # contamination: earlier sessions bleed into later outputs
                words[0] = "[recall]"
            text = " ".join(words).capitalize() + "."
        out_tokens = len(text.split())

        lat = p["latency"]
        ms = lat["base_ms"] + lat["prefill_ms_per_token"] * (len(tokens) - cached) + lat["decode_ms_per_token"] * out_tokens
        ms *= 1 + lat["jitter"] * (((h >> 8) % 2001) / 1000 - 1)
        await asyncio.sleep(ms * self.time_scale / 1000)
        if self.persistent_memory:
            self._memory.append(hashlib.sha256(prompt.encode()).hexdigest()[:8])
        return GenResult(text, len(tokens), cached, out_tokens, ms)

    async def reset(self, scope_prefix: str | None = None) -> int:
        keys = [k for k in self._cache if scope_prefix is None or k.startswith(scope_prefix) or k == "GLOBAL"]
        for k in keys:
            del self._cache[k]
        # NB: persistent_memory deliberately survives reset(); it models state
        # a reset cannot clear, which only the purity fingerprint catches.
        return len(keys)


def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class DigestMismatch(RuntimeError):
    pass


class LlamaCppBackend:
    def __init__(self, base_url: str, *, model_path: str | None = None, pinned_sha256: str | None = None,
                 n_slots: int = 1, client: httpx.AsyncClient | None = None, timeout_s: float = 120.0):
        self.client = client or httpx.AsyncClient(base_url=base_url, timeout=timeout_s)
        self.n_slots = n_slots
        if model_path:
            actual = file_sha256(model_path)
            if pinned_sha256 and actual != pinned_sha256:
                raise DigestMismatch(f"model weights digest {actual} != pinned {pinned_sha256}")
            self.digest = actual
        else:
            self.digest = pinned_sha256 or sha256_hex(f"unpinned:{base_url}".encode())

    def describe(self) -> dict:
        return {"backend": "llama.cpp", "digest": self.digest, "cache_scope": "none (cache_prompt=false)",
                "persistent_memory": False}

    async def generate(self, *, scope: str, prompt: str, system: str | None, max_tokens: int, seed: int) -> GenResult:
        messages = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        t0 = time.monotonic()
        r = await self.client.post("/v1/chat/completions", json={
            "messages": messages, "temperature": 0, "top_k": 1, "seed": seed,
            "max_tokens": max_tokens, "cache_prompt": False, "stream": False,
        })
        r.raise_for_status()
        data = r.json()
        usage = data.get("usage", {})
        return GenResult(
            text=data["choices"][0]["message"]["content"],
            prompt_tokens=usage.get("prompt_tokens", 0),
            cached_tokens=0,
            completion_tokens=usage.get("completion_tokens", 0),
            latency_ms=(time.monotonic() - t0) * 1000,
        )

    async def reset(self, scope_prefix: str | None = None) -> int:
        erased = 0
        for i in range(self.n_slots):
            try:
                r = await self.client.post(f"/slots/{i}", params={"action": "erase"})
                erased += r.status_code == 200
            except httpx.HTTPError:
                pass
        return erased
