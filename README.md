# Agentic SRA Framework

An agentic AI framework that drafts an FDA cybersecurity **Security Risk Assessment (SRA)** for a connected embedded medical device. Point it at the device's GitHub repo of legacy artifacts (SAD, SRS, SDD, SDS, threat model, firmware source, manuals). The framework indexes everything into a vector DB (semantic retrieval) plus a graph DB (requirements + threat + control traceability), then runs five specialized agents that consume both indices to produce a per-threat SRA entry with CVSS scores, gap analysis against FDA 2023 / IEC 62443 / AAMI TIR57 / NIST 800-193, and concrete proposed changes to documents and code.

## Four-command workflow

```bash
# 1. Point the framework at any device's legacy corpus
sra init --repo https://github.com/balajibankapur/agentic-ai-sra-capstone --device pmx100

# 2. Build the two indices (one-shot)
sra index

# 3. Run the agents → produces output/pmx100_sra_draft.md
sra draft --device pmx100

# 4. Open the review UI → engineer approves / edits / rejects each entry
sra review
```

## Architecture

```
Legacy corpus repo  ──clone──▶  input/          (read-only mirror)
                                    │
                                    ▼
                              indexer/         (one-shot)
                              ├── vector.py    → Chroma (docs, threats, clauses, code)
                              └── graph.py     → Kuzu   (14 node types, 15 edge types)
                                    │
                                    ▼
                              stores/          (chroma/ + kuzu/)
                                    ▲
                                    │ (queried via MCP)
                              mcp_servers/
                              ├── corpus-vector    search, get_chunk
                              ├── corpus-graph     cypher, neighbors, path
                              └── corpus-files     read, list, grep
                                    ▲
                                    │
                              agents/          (LangGraph, 5 agents)
                              ├── ingestion            walks threats
                              ├── compliance_mapper    clause verdicts
                              ├── code_analysis        SAST + graph
                              ├── threat_control_risk  12-field SRA entries
                              └── report_generator     draft markdown
                                    │
                                    ▼
                              output/pmx100_sra_draft.md
                                    │
                                    ▼
                              review_ui/       (Streamlit approve/edit/reject)
                                    │
                                    ▼
                              output/pmx100_sra_final.md
```

## Setup

```bash
git clone https://github.com/balajibankapur/agentic-sra-framework
cd agentic-sra-framework
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # fill in OPENAI_API_KEY at minimum
```

## Status

Work in progress. See `docs/roadmap.md` for the 13-step build plan.
