# Agentic SRA Framework

An agentic AI framework that drafts an FDA cybersecurity **Security Risk Assessment (SRA)** for a connected embedded medical device.

Point it at the device's GitHub repo of legacy artifacts (SAD, SRS, SDD, SDS, threat model, firmware source, manuals). The framework indexes everything into a **vector DB (Chroma)** for semantic retrieval plus a **graph DB (Kuzu)** for requirements + threat + control traceability, then runs **five specialized agents through the Model Context Protocol (MCP)** to produce a per-threat SRA entry with CVSS scoring, gap analysis against FDA 2023 / IEC 62443 / AAMI TIR57 / NIST 800-193, and concrete proposed changes to documents and code — reviewed by a human before submission.

Reference device: **[PMx-100 Connected Patient Monitor](https://github.com/balajibankapur/agentic-ai-sra-capstone)** — 225 threats, 34 seeded VULN ground-truth entries across firmware.

## Capstone presentation

- **[Slide deck (.pptx)](output/capstone_deck.pptx)** — 14 slides · full narrative from problem to results
- **[Demo script](docs/demo_script.md)** — 10-min live walkthrough with timestamps + fallbacks
- **[Architecture diagram](docs/architecture_diagram.svg)** — one-page five-tier view

## Empirical result headline

On a 25-threat pilot (hybrid profile: OpenAI gpt-4o for the reasoning-heavy agent, Groq + Gemini free tier for the rest):

| Metric | Value |
|---|---|
| Entries drafted | 25 / 25 (0 parse errors) |
| File-level VULN recall vs seeded ground truth | **50 %** (17 / 34) |
| Recall on Semgrep-"no" band (regulatory-intent — the framework's distinctive value vs plain SAST) | **57 %** (4 / 7) |
| Cost | $0.42 total (~$0.017 per SRA entry) |
| Wall time | ~12 minutes |

## Four-command workflow

```bash
# 1. Point the framework at any device's legacy corpus
sra init --repo https://github.com/balajibankapur/agentic-ai-sra-capstone --device pmx100

# 2. Build the two indices (one-shot, ~35 s, ~$0.05 embeddings)
sra index --device pmx100

# 3. Run the agents → produces output/pmx100_sra_draft.{md,json}
sra draft --device pmx100

# 4. Open the review UI → engineer approves / edits / rejects each entry
sra review --device pmx100
```

Additionally: `sra status`, `sra reset`, `sra export`, `sra eval`, `sra mcp {vector|graph|files}`.

## Architecture at a glance

**Five tiers, all backends behind an MCP boundary:**

```
INPUT       Legacy corpus (GitHub) · Regulatory corpus (in-tree JSON) · LLM providers · Reviewer
                                                    │
INDICES     Chroma vector DB (2555 chunks) · Kuzu graph (2181 nodes / 1636 edges) · Filesystem
                                                    │
MCP LAYER   corpus-vector · corpus-graph (read-only) · corpus-files (path-traversal safe)
                                                    │
AGENTS      LangGraph state machine:
            ingestion → compliance_mapper → code_analysis → threat_control_risk ⭐ → report_generator
            (loop over threat queue until empty)                                       │
                                                                          + 10 guardrails
                                                                                       │
OUTPUT      Draft SRA (MD + JSON) → Streamlit review UI → Final SRA (MD + PDF + DOCX + JSON)
                                                                          + provenance.json
```

Full one-page SVG: **[docs/architecture_diagram.svg](docs/architecture_diagram.svg)**

## The five agents

| Agent | Purpose | Backend(s) | Model | LLM? |
|---|---|---|---|---|
| Ingestion | Enumerate + order threats for the run | Kuzu (one Cypher) | — | — |
| Compliance Mapper | Per-clause verdict (present / partial / missing) with quotes | Kuzu + Chroma `regulatory` | `gemini-2.5-flash` (free) | ✅ |
| Code Analysis (2 turns) | Planner proposes greps → Python greps → interpreter decides | Kuzu + filesystem | `groq/gpt-oss-120b` (free) | ✅ |
| **Threat / Control / Risk ⭐** | Compose the 12-field SRA entry: CVSS, gap analysis, proposed fixes | Kuzu + Chroma | **`openai/gpt-4o`** | ✅ |
| Report Generator | Upsert entry into draft.{md,json} (crash-safe) | Local disk | — | — |

Every LLM output goes through **10 guardrails**:
- **Hard-fail (4):** schema validation, CVSS vector+score verification, citation-in-graph check, quote-substring verification
- **Soft-warn (6):** banned crypto in proposals, legacy/proposed taxonomy, scope check, file-line verification, prompt-injection delimiting, per-entry token cap

## Design docs (V-model, formally phase-gated)

| Phase | Doc | Size |
|---|---|---|
| Phase 1 | [Use Cases](docs/use_cases.md) — 7 UCs across 6 actor roles | 2 KLoC |
| Phase 2 | [Requirements (SRS)](docs/requirements.md) — 72 requirements (56 functional + 16 non-functional) | 3 KLoC |
| Phase 3 | [Architecture (SAD)](docs/architecture.md) — 33 items across 7 subsystems | 3 KLoC |
| Phase 4 | [Detail Design (SDD)](docs/detail_design.md) — 5 agent specs + 10 guardrail specs + Pydantic schemas | 4 KLoC |
| Roadmap | [Build roadmap](docs/roadmap.md) — 13-step implementation plan | — |

PDF + DOCX renders of each are in `output/`.

## Setup

```bash
git clone https://github.com/balajibankapur/agentic-sra-framework
cd agentic-sra-framework
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env    # fill in OPENAI_API_KEY at minimum
                         # for the hybrid profile, also GROQ_API_KEY + GEMINI_API_KEY
```

Then follow the four-command workflow above.

## Three drafting profiles

| Profile | Star agent (TCR) | Other 3 agents | Cost per SRA entry | When to use |
|---|---|---|---|---|
| `free` | groq/gpt-oss-120b | groq + gemini (free tier) | ~$0 (+ spillover to gpt-4o-mini on 503) | free-tier friendly evaluation |
| `hybrid` (default) | **openai/gpt-4o** | groq + gemini (free tier) | ~$0.017 | best cost / quality balance |
| `openai` | openai/gpt-4o | openai/gpt-4o-mini | ~$0.06 | OpenAI-only environments |

## Testing

```bash
pip install -e '.[dev]'
pytest tests/                       # 34 guardrail unit tests (~0.02 s, no LLM)
sra eval --device pmx100            # score current draft vs seeded VULN ground truth
```

## Directory layout

```
framework/
  cli.py                Typer entry point (init, index, draft, review, export, eval, reset, status, mcp)
  agents/               LangGraph pipeline + 5 agent nodes + prompt YAMLs + 10 guardrails + LLM router
  mcp_servers/          corpus-vector, corpus-graph, corpus-files
  indexer/              Chroma vector index + Kuzu graph loader + regulatory corpus loader
  eval/                 VULN-recall harness
  regulatory/           24 clauses across FDA 2023 / IEC 62443-4-2 / AAMI TIR57 / NIST 800-193
  sra/                  SRAEntry Pydantic + Provenance + export renderer
review_ui/              Streamlit review UI + job manager
docs/                   Use cases · SRS · SAD · SDD · demo script · architecture diagram
tests/                  Guardrail unit tests
output/                 Draft/final SRAs · provenance · deck · rendered design PDFs
```

## Related repos

- **[balajibankapur/agentic-ai-sra-capstone](https://github.com/balajibankapur/agentic-ai-sra-capstone)** — the reference device corpus (PMx-100 legacy artifacts) used as input to this framework

## License

MIT — see `pyproject.toml`.

## Author

Balaji Bankapur · 2026 · Capstone project
