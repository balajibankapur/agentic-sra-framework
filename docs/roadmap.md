# Roadmap

| # | Step | Command it lights up | Deliverable |
|---|---|---|---|
| 0 | Scaffold repo | — | Directory tree, `pyproject.toml`, `.gitignore`, `.env.example`, empty CLI |
| 1 | CLI + `sra init` | `sra init --repo <URL> --device pmx100` | Clones corpus into `input/pmx100/`, writes `.manifest.json` |
| 2 | Vector indexer | `sra index vectors` | Chunks docs + firmware into `stores/chroma/` |
| 3 | Graph extractor | `sra index extract` | 7 JSON extract files (nodes + edges) under `stores/extracts/` |
| 4 | Graph loader | `sra index graph` | Loads JSON into `stores/kuzu/`, prints node/edge counts |
| 5 | MCP servers | (launched by `sra draft`) | `corpus-vector`, `corpus-graph`, `corpus-files` |
| 6 | LangGraph skeleton | `sra draft` returns dummy SRA | State machine + 5 empty agent nodes |
| 7 | Ingestion agent | — | Enumerates threats from graph, batches them |
| 8 | Compliance Mapper | — | Per-clause verdict per threat |
| 9 | Code Analysis | — | SAST + graph-guided grep confirms control presence |
| 10 | Threat/Control/Risk | — | 12-field SRA entry with CVSS v3.1, proposed control, code+doc changes |
| 11 | Report Generator | `sra draft` produces real draft | `output/<device>_sra_draft.md` + `.json` |
| 12 | Streamlit review UI | `sra review` | Approve/Edit/Reject each entry → `output/<device>_sra_final.md` |
| 13 | Regulatory corpus | — | FDA 2023 / IEC 62443 / AAMI TIR57 / NIST 800-193 in vector + graph |

## SRA entry schema (locked in Step 10)

Every threat in the output SRA carries these 12 fields:

1. `threat_id` — matches threat model (e.g., `T-OTA-P01-T`)
2. `title` — short human-readable
3. `stride` — one of S/T/R/I/D/E
4. `assets_affected` — list from graph
5. `existing_controls` — from graph + code confirmation
6. `gap_analysis` — clause-by-clause: FDA §V.B.3, IEC CR 3.10, AAMI TIR57 §X, NIST 800-193 §Y
7. `cvss_v31` — vector string + base + temporal + environmental
8. `residual_risk` — H/M/L after existing controls
9. `proposed_controls` — modern controls to close the gap
10. `proposed_doc_changes` — file:section edits (SRS-OTA-XXXX add/modify)
11. `proposed_code_changes` — file:line edits with rationale
12. `priority + effort` — P0/P1/P2 + engineer-weeks estimate

## Locked decisions

- Framework name: `agentic-sra-framework`
- Vector DB: **Chroma** (embedded, file-backed)
- Graph DB: **Kuzu** (embedded, Cypher-like)
- Agent orchestration: **LangGraph**
- Regulatory corpus: same Chroma DB, `collection=regulatory`
- Embeddings: **OpenAI text-embedding-3-large**
- Tool transport to agents: **MCP** (Model Context Protocol)
- LLM router: **LiteLLM** (reuse existing Groq/Gemini/Mistral keys)
