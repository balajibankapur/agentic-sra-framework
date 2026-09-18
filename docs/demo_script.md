# Live Demo Script

**Duration:** 10 minutes (target). Add 2 min buffer for cold-start.

## Pre-demo checklist (do 5 minutes before you're up)

| # | Check | Command / action |
|---|---|---|
| 1 | `.venv` active | `source /Users/balajibankapur/Reva/agentic-sra-framework/.venv/bin/activate` |
| 2 | `.env` populated | `sra status --device pmx100` — every row "ok" except draft/review/final |
| 3 | Streamlit running | `sra review --device pmx100` in a dedicated terminal; open `http://localhost:8501` |
| 4 | Browser ready | Zoom set so sidebar + first entry card both visible without scroll |
| 5 | Terminal side-by-side | Second terminal open at the framework repo, for the `sra reset` line at the start |
| 6 | Fallback file | Confirm `output/pmx100_sra_final.pdf` exists from an earlier successful run — you'll use it if the live pipeline fails |

## The 10-minute flow

### [00:00 – 00:30]  Terminal — clean slate

**Say:** *"First, a full reset so we start from a clean state and you can see the framework build from zero."*

```bash
sra reset --device pmx100 -y
sra status --device pmx100
```

**Point out on `sra status`:**
- `input` — cloned corpus commit SHA (traceability)
- `vector store (Chroma)` — 2555+ chunks across 3 collections
- `graph store (Kuzu)` — 2181 nodes across 11 tables
- `draft / prompts / review / final` — all `—` (clean slate)

---

### [00:30 – 01:15]  Browser — open the UI, show empty state

Navigate to **http://localhost:8501**

**Say:** *"The empty state page guides the reviewer through starting a new draft. Analysis Control is in the sidebar."*

**Show them:**
- Warning banner: "No draft yet"
- Sidebar → Analysis Control block

---

### [01:15 – 01:45]  Sidebar — configure the run

Fill in the form:

| Field | Value | Why say it |
|---|---|---|
| Profile | **hybrid** | *"OpenAI for the star agent, Gemini/Groq free tier for the rest"* |
| Threat limit | **5** | *"Five threats is enough to demonstrate — for a full 225-threat run this stays 0"* |
| Ingestion strategy | **code-linked** | *"Round-robins across VULN subsystems — better small-pilot recall"* |

Click **▶ Start draft**

---

### [01:45 – 05:00]  Watch the pipeline run (~3 min)

**Point out** while it runs:

- **Progress banner** at top auto-refreshes every 3 s (no clicking)
- **Sidebar status** also auto-refreshes: `entries: X / 5 · turns: T · $X.XXXX`
- **Reset section** grayed out — safety, can't wipe state mid-run
- **Cost tracking** live per-turn (the star agent uses gpt-4o, everything else is free tier)

**If it lands slower than expected**, chat about:
- Determinism: same commit + same models + temperature 0 → reproducible drafts (provenance file captures everything)
- Fallback chain: if Gemini rate-limits or 503s, LLM Router retries then spills to gpt-4o-mini

---

### [05:00 – 05:30]  Auto-completion

**Watch for:** banner turns green **"✅ Draft complete"** and page reloads to entry cards.

**Say:** *"No manual refresh. The Streamlit fragment detects the subprocess exited and does a full-page rerun."*

---

### [05:30 – 07:00]  Review tab — expand an entry

Click any entry (start with a P0 or P1 for impact).

**Point out on the card:**
- **CVSS 8.1 High** — with the full vector string
- **Existing controls** — cited by exact CTRL id from the graph (not invented)
- **Gap analysis table** — 5-6 clauses with verdicts (missing / partial / present), each with a quote from the clause body
- **Proposed controls** — modern control with clear description
- **Proposed doc changes** — refers to real SRS/SDD/SDS/SAD items
- **Proposed code changes** — real firmware path (e.g. `firmware/app_mcu/ble/ble_pairing.c:42`) with an action (modify / create_file)
- **🔍 Agent trace** — collapsed by default, expand it to show the LLM turns that produced this entry

---

### [07:00 – 08:30]  Agent Activity tab — the technical story

Switch to **🔍 Agent Activity** tab.

**Open** the **📐 Pipeline overview** expander at the top.

**Point out:**
- LangGraph state machine — 5 agents, loop over threats
- Which agent hits which backend (Kuzu / Chroma / filesystem)
- MCP boundary — same 3 servers can be launched standalone for Claude Code / Cursor

**Scroll down** to the turn log. Expand one **compliance_mapper** turn.

Click the **🛠 Tool calls** sub-tab.

**Point out:**
- 2 Cypher queries against Kuzu — one for the threat, one for its linked controls
- 1 vector search against Chroma `regulatory` collection with the threat description as the query
- Every call shows: MCP server → backend → query → result summary

Then click the **📤 Prompt** sub-tab.

**Point out:**
- Full system prompt (the guardrail rules the LLM sees)
- User message with `<CORPUS_UNTRUSTED>`-wrapped clause bodies — the delimiter is a prompt-injection guardrail

---

### [08:30 – 09:30]  Rerun with reviewer context

Back on the **📋 Review** tab.

Click **🔁 Rerun** on the entry you expanded.

**Type into the text area:**

> Please score CVSS with `AC:H` because attackers need physical proximity to the patient bedside, and `A:L` because the safety MCU enforces a hardware watchdog. Prefer modifying line 45 of the existing file over creating a new one.

Click **▶ Start rerun**.

**Wait ~30 seconds.** The banner runs again briefly.

**Point out when it completes:**
- CVSS moves from `AV:A/AC:L/…/A:N` → `AV:A/AC:H/…/A:L` — the reviewer's technical input actually shaped the output
- Code line changes from 42 → 45
- Total entry count stays the same (upsert, not append)
- Auto-refresh caught it — no manual reload

---

### [09:30 – 10:00]  Export

Click **📤 Export final artifacts** in the sidebar.

**Point out** in the success banner:
- MD (human-readable)
- PDF (styled, via pandoc + Chrome headless)
- DOCX (for reviewer markup)
- JSON (machine-readable)
- Provenance JSON — records model versions, prompt versions, token counts, cost, per-entry review decisions, timestamps

**End with:** *"Provenance is the FDA-relevant piece — every claim in the SRA traces back to a specific commit SHA, a specific prompt, a specific reviewer, at a specific time."*

## Fallback plans

**If the live draft fails or hangs:**
1. Kill the subprocess: `pkill -f "sra draft"`
2. In the UI sidebar → Reset with "Draft + review only"
3. Show `output/pmx100_sra_final.pdf` from a prior successful pilot
4. Show `output/pmx100_eval.json` for the recall numbers

**If Streamlit itself misbehaves:**
1. Kill Streamlit: `pkill -f "streamlit run"`
2. Restart: `sra review --device pmx100`
3. Give it 5 seconds to boot, then reload the browser

**If the panel wants deeper technical detail:**
- Open `framework/agents/nodes/threat_control_risk.py` to show the TCR agent implementation
- Open `framework/agents/prompts/threat_control_risk.yaml` for the exact system prompt
- Open `framework/agents/guardrails/cvss_check.py` for the CVSS reference formula

## After the demo — questions to anticipate

| Question | One-liner answer |
|---|---|
| "How do you prevent LLM hallucination?" | Ten guardrails; four hard-fail (schema / CVSS / citation / quote). Every doc-id, code-path and clause-quote is verified against the graph or the original chunk. |
| "What if the LLM refuses to reason about medical safety?" | The role framing in the system prompt + few-shot examples make refusal rare. Fallback: soft-warn, entry marked `parse_error`, reviewer sees the raw LLM output and fixes. |
| "Can this be reused for another device?" | Yes — `sra init --repo <URL> --device <name>`, then `sra index`. The framework is device-agnostic; PMx-100 is the reference. |
| "How much would a full 225-threat run cost?" | ~$3-5 on hybrid, ~$0 on free-tier profile with fallback spillover. |
| "How reproducible is the SRA?" | Temperature 0, prompt versions in provenance, commit SHA in provenance — same corpus + same models → equivalent draft. |
| "Why LangGraph over CrewAI?" | Explicit state machine, better tracing for FDA audit, industry standard for production LLM pipelines in 2026. |
