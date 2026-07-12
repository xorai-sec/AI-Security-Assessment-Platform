from __future__ import annotations

from .models import Finding, ISOMapping

MAPPING_TEMPLATES = {
    "Prompt Injection": {
        "clause": "ISO/IEC 42001:2023 Clauses 6.1, 6.2, 8.1 and Annex A.6",
        "title": "AI risk treatment and AI system lifecycle control evidence",
        "required": ["AI risk assessment", "Risk treatment decision", "Security test transcript", "Monitoring record", "Corrective action record"],
    },
    "Indirect Prompt Injection": {
        "clause": "ISO/IEC 42001:2023 Clauses 6.1, 8.1 and Annex A.6, A.7",
        "title": "Untrusted content, data lifecycle and retrieval control evidence",
        "required": ["Data source inventory", "RAG threat model", "Retrieval access-control test", "Prompt assembly control design", "Retest evidence"],
    },
    "Unauthorized Retrieval": {
        "clause": "ISO/IEC 42001:2023 Clauses 6.1, 7.5, 8.1 and Annex A.7",
        "title": "AI data governance and restricted information control evidence",
        "required": ["Data classification", "Access-control policy", "Retrieval authorization logs", "Exception review", "Corrective action"],
    },
    "Unauthorized Tool Execution": {
        "clause": "ISO/IEC 42001:2023 Clauses 5.3, 6.1, 8.1 and Annex A.3, A.6",
        "title": "Role responsibility, AI operation and tool-use authorization evidence",
        "required": ["Tool inventory", "Role matrix", "Authorization logs", "Security event logs", "Owner approval"],
    },
    "Confirmation Bypass": {
        "clause": "ISO/IEC 42001:2023 Clauses 5.3, 8.1, 9.1 and Annex A.3, A.6",
        "title": "Human oversight, operational control and monitored action evidence",
        "required": ["Human oversight design", "Approval workflow record", "Action logs", "Bypass test evidence", "Retest result"],
    },
    "Memory Isolation": {
        "clause": "ISO/IEC 42001:2023 Clauses 6.1, 7.5, 8.1 and Annex A.7",
        "title": "AI data lifecycle, retention and session isolation evidence",
        "required": ["Memory design", "Session isolation test", "Data retention policy", "Access logs", "Deletion/retest evidence"],
    },
}


def map_finding_to_iso(finding: Finding) -> ISOMapping:
    template = MAPPING_TEMPLATES.get(
        finding.category,
        {
            "clause": "ISO/IEC 42001:2023 Clauses 6.1, 8.1, 9.1 and 10.1",
            "title": "AI management system evidence review",
            "required": ["Risk assessment", "Control evidence", "Human reviewer decision"],
        },
    )
    return ISOMapping(
        finding_id=finding.id,
        standard_version="ISO/IEC 42001:2023",
        clause_or_control_id=template["clause"],
        requirement_title=template["title"],
        mapping_rationale=(
            "The technical observation provides evidence for AI risk assessment, risk treatment, "
            "operational control, performance evaluation, documented information, and improvement review. "
            "The mapping is an audit-support candidate and is not a certification decision."
        ),
        relevance_type="Relevant",
        required_organizational_evidence=template["required"],
        available_evidence=finding.evidence_references,
        missing_evidence=["Management approval record", "Formal control owner attestation"],
        evidence_sufficiency="Partial",
        mapping_confidence=finding.confidence,
    )
