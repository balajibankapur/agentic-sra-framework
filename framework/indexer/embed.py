"""OpenAI embeddings — batched, retried, with a cost estimate.

Uses `text-embedding-3-large` (3072 dims). One-time cost for the PMx-100
corpus is ~$0.13.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Sequence

from openai import OpenAI
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)


EMBED_MODEL = "text-embedding-3-large"
EMBED_DIMS = 3072
MAX_BATCH_TEXTS = 96        # OpenAI accepts up to 2048, but 96 keeps latency low + cost fine-grained
MAX_TEXT_CHARS = 24_000     # embed model input cap is 8191 tokens (~32k chars); we cap early
PRICE_PER_M_TOKENS = 0.13   # text-embedding-3-large as of 2026


@dataclass
class EmbedStats:
    calls: int = 0
    total_texts: int = 0
    total_chars: int = 0
    est_tokens: int = 0
    est_cost_usd: float = 0.0
    seconds: float = 0.0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "calls": self.calls,
            "total_texts": self.total_texts,
            "total_chars": self.total_chars,
            "est_tokens": self.est_tokens,
            "est_cost_usd": round(self.est_cost_usd, 4),
            "seconds": round(self.seconds, 1),
        }


class Embedder:
    """Thin wrapper over OpenAI embeddings with batching + retry + stats."""

    def __init__(self, model: str = EMBED_MODEL) -> None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Copy .env.example to .env and fill it in."
            )
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.stats = EmbedStats()

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Embed a list of texts. Returns a list of vectors in the same order."""
        out: list[list[float]] = []
        for start in range(0, len(texts), MAX_BATCH_TEXTS):
            batch = [t[:MAX_TEXT_CHARS] for t in texts[start:start + MAX_BATCH_TEXTS]]
            vectors = self._embed_batch(batch)
            out.extend(vectors)
        return out

    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(min=2, max=30),
        retry=retry_if_exception_type(Exception),
    )
    def _embed_batch(self, batch: list[str]) -> list[list[float]]:
        t0 = time.perf_counter()
        resp = self.client.embeddings.create(model=self.model, input=batch)
        elapsed = time.perf_counter() - t0

        vectors = [d.embedding for d in resp.data]
        self.stats.calls += 1
        self.stats.total_texts += len(batch)
        total_chars = sum(len(t) for t in batch)
        self.stats.total_chars += total_chars
        # OpenAI billing is per token; usage is returned in resp.usage
        tokens = getattr(resp.usage, "total_tokens", total_chars // 4)
        self.stats.est_tokens += tokens
        self.stats.est_cost_usd += (tokens / 1_000_000) * PRICE_PER_M_TOKENS
        self.stats.seconds += elapsed
        return vectors
