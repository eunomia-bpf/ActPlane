"""OpenAI-compatible transport for the official RepoGuardBench agent interface.

Defaults mirror upstream OllamaBackend generation options where the protocols
overlap. Ollama's num_ctx/repeat_penalty cannot be represented portably here.
No model response is cached across independent experiment cells.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Any
import urllib.error
import urllib.request

from repoguard.agents.ollama_backend import GenResponse


class ModelBackend:
    def __init__(self, model: str, raw_dir: str | Path):
        self.model = model
        self.raw_dir = Path(raw_dir)
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        if model == "qwen3.8-27b-nvfp4":
            self.base = "http://qwen38-vllm.models.svc.cluster.local:8000/v1"
            self.key = None
        else:
            self.base = os.environ["LITELLM_BASE_URL"].rstrip("/")
            self.key = os.environ["LITELLM_API_KEY"]
        self.n = 0
        self.replies: list[dict[str, Any]] = []
        self.prefix: list[dict[str, str]] = []
        self.workspace = None

    def chat(self, messages, options=None, stop=None):
        opts = {"temperature": 0.0, "top_p": 0.95,
                "num_predict": 1536, "seed": 7}
        opts.update(options or {})
        # Self-policy generation and subsequent actions are one logical
        # conversation. The official agent loop otherwise owns its history.
        if self.prefix:
            # prefix already contains the original first user message.
            messages = messages[:1] + self.prefix + [{"role": "user", "content":
                "Continue the original developer task. Output exactly one JSON action."}] + messages[2:]
        payload = {"model": self.model, "messages": messages,
                   "temperature": opts["temperature"], "top_p": opts["top_p"],
                   "max_tokens": opts["num_predict"], "seed": opts["seed"],
                   "stream": False}
        if stop:
            payload["stop"] = stop
        self.n += 1
        stem = self.raw_dir / f"{self.n:03d}"
        stem.with_suffix(".request.json").write_text(json.dumps(payload, ensure_ascii=False))
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = "Bearer " + self.key
        request = urllib.request.Request(self.base + "/chat/completions",
                                         data=json.dumps(payload).encode(), headers=headers)
        start = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=240) as response:
                raw = response.read().decode()
            stem.with_suffix(".response.json").write_text(raw)
            obj = json.loads(raw)
            content = obj["choices"][0]["message"].get("content") or ""
            if isinstance(content, list):
                content = "\n".join(p.get("text", "") for p in content)
            usage = obj.get("usage") or {}
            result = GenResponse(text=content,
                                 prompt_tokens=int(usage.get("prompt_tokens") or 0),
                                 completion_tokens=int(usage.get("completion_tokens") or 0),
                                 duration_s=time.monotonic() - start, cached=False, raw=obj)
            self.replies.append({"index": self.n, "text": result.text,
                                 "prompt_tokens": result.prompt_tokens,
                                 "completion_tokens": result.completion_tokens,
                                 "duration_s": result.duration_s})
            if self.workspace is not None:
                self.workspace.reply_index = self.n
            return result
        except Exception as exc:
            detail = str(exc)
            if isinstance(exc, urllib.error.HTTPError):
                detail = exc.read().decode(errors="replace")
            stem.with_suffix(".error.json").write_text(json.dumps({
                "error": type(exc).__name__, "detail": detail,
                "duration_s": time.monotonic() - start}))
            raise
