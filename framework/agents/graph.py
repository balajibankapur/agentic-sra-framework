"""LangGraph state machine — SDD §2 top-level diagram.

    START -> ingestion -> dequeue -> compliance_mapper -> code_analysis
                          ^                                    |
                          |                                    v
                          |                        threat_control_risk
                          |                                    |
                          |                                    v
                          |                          report_generator
                          |                                    |
                          +---------- loop / END --------------+
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from framework.agents.nodes.code_analysis import run_code_analysis
from framework.agents.nodes.compliance_mapper import run_compliance_mapper
from framework.agents.nodes.dequeue import run_dequeue
from framework.agents.nodes.ingestion import run_ingestion
from framework.agents.nodes.report_generator import run_report_generator
from framework.agents.nodes.threat_control_risk import run_threat_control_risk
from framework.agents.state import SRAState


def build_graph(
    *,
    category: str | None = None,
    threat: str | None = None,
    limit: int | None = None,
):
    """Compile the LangGraph state machine for one `sra draft` run."""
    g = StateGraph(SRAState)

    # Ingestion is closed over the CLI filter args
    def _ingestion(state: SRAState) -> dict:
        return run_ingestion(state, category=category, threat=threat, limit=limit)

    g.add_node("ingestion", _ingestion)
    g.add_node("dequeue", run_dequeue)
    g.add_node("compliance_mapper", run_compliance_mapper)
    g.add_node("code_analysis", run_code_analysis)
    g.add_node("threat_control_risk", run_threat_control_risk)
    g.add_node("report_generator", run_report_generator)

    g.set_entry_point("ingestion")
    g.add_edge("ingestion", "dequeue")

    # Route from dequeue: if current_threat is set, proceed; else END.
    def _dequeue_router(state: SRAState) -> str:
        return "compliance_mapper" if state.current_threat else END

    g.add_conditional_edges("dequeue", _dequeue_router)
    g.add_edge("compliance_mapper", "code_analysis")
    g.add_edge("code_analysis", "threat_control_risk")
    g.add_edge("threat_control_risk", "report_generator")
    g.add_edge("report_generator", "dequeue")

    return g.compile()
