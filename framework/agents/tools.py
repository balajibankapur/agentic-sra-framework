"""In-process wrappers around the MCP tool functions.

The MCP servers (framework/mcp_servers/*) expose these same tools over
stdio for external clients (Claude Code, Cursor). Internally, the
LangGraph agents call the underlying functions directly to avoid the
subprocess overhead — the tool contract stays identical either way.

Every call is buffered into a per-turn log that the calling agent
attaches to the LLM Router's prompts.jsonl record.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

# Re-use the MCP server tool functions directly. Set SRA_DEVICE first so
# any lazy env-var lookups inside the servers pick up the right device.
def _ensure_device(device: str) -> None:
    if os.environ.get("SRA_DEVICE") != device:
        os.environ["SRA_DEVICE"] = device


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]
    result_summary: str
    result_size: int


@dataclass
class ToolLog:
    """Per-agent-turn call log. Attached to each prompts.jsonl record."""

    device: str
    calls: list[ToolCall] = field(default_factory=list)

    def _record(self, tool: str, args: dict, result: Any) -> None:
        summary = ""
        size = 0
        if isinstance(result, list):
            size = len(result)
            summary = f"{size} rows"
        elif isinstance(result, dict):
            size = len(result)
            summary = f"dict[{size}]"
        elif result is None:
            summary = "None"
        else:
            summary = f"{type(result).__name__}"
        self.calls.append(ToolCall(tool=tool, args=args, result_summary=summary, result_size=size))

    # -- Vector -----------------------------------------------------------------
    def vector_search(
        self,
        query: str,
        k: int = 6,
        filters: dict | None = None,
        collection: str = "device_docs",
    ) -> list[dict]:
        _ensure_device(self.device)
        from framework.mcp_servers.corpus_vector_server import search
        result = search(query=query, k=k, filters=filters, collection=collection)
        self._record("vector.search", {"query": query, "k": k, "filters": filters,
                                       "collection": collection}, result)
        return result

    def vector_get_chunk(self, chunk_id: str, collection: str = "device_docs") -> dict | None:
        _ensure_device(self.device)
        from framework.mcp_servers.corpus_vector_server import get_chunk
        result = get_chunk(chunk_id=chunk_id, collection=collection)
        self._record("vector.get_chunk", {"chunk_id": chunk_id, "collection": collection}, result)
        return result

    # -- Graph ------------------------------------------------------------------
    def graph_cypher(self, query: str, params: dict | None = None) -> list[dict]:
        _ensure_device(self.device)
        from framework.mcp_servers.corpus_graph_server import cypher
        result = cypher(query=query, params=params)
        self._record("graph.cypher", {"query": query, "params": params}, result)
        return result

    def graph_neighbors(
        self,
        node_id: str,
        edge_type: str | None = None,
        direction: str = "out",
        depth: int = 1,
        limit: int = 50,
    ) -> list[dict]:
        _ensure_device(self.device)
        from framework.mcp_servers.corpus_graph_server import neighbors
        result = neighbors(node_id=node_id, edge_type=edge_type,
                           direction=direction, depth=depth, limit=limit)
        self._record("graph.neighbors", {"node_id": node_id, "edge_type": edge_type,
                                         "direction": direction, "depth": depth,
                                         "limit": limit}, result)
        return result

    # -- Files ------------------------------------------------------------------
    def files_read(self, path: str) -> dict:
        _ensure_device(self.device)
        from framework.mcp_servers.corpus_files_server import read
        result = read(path=path)
        self._record("files.read", {"path": path}, result)
        return result

    def files_grep(self, pattern: str, glob: str = "**/*", max_hits: int = 100,
                   case_insensitive: bool = False, context: int = 0) -> list[dict]:
        _ensure_device(self.device)
        from framework.mcp_servers.corpus_files_server import grep
        result = grep(pattern=pattern, glob=glob, max_hits=max_hits,
                      case_insensitive=case_insensitive, context=context)
        self._record("files.grep", {"pattern": pattern, "glob": glob,
                                    "max_hits": max_hits}, result)
        return result

    # -- Serialization for prompts.jsonl ----------------------------------------
    def as_records(self) -> list[dict]:
        return [{"tool": c.tool, "args": c.args, "result_summary": c.result_summary,
                 "result_size": c.result_size} for c in self.calls]
