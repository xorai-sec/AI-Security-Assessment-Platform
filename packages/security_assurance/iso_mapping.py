from __future__ import annotations

from .models import Finding, ISOMapping


MAPPING_TEMPLATES = {
    "Prompt Injection": {
        "clause": "ISO/IEC 42001:2023 evidence placeholder - AI risk treatment and operational controls",
        "title": "AI system security risk treatment evidence",
        "required": ["AI risk assessment", "Risk treatment plan", "Security testing evidence", "Monitoring records", "Remediation decision log"],
    },
    "Indirect Prompt Injection": {
        "clause": "ISO/IEC 42001:2023 evidence placeholder - data and system lifecycle controls",
        "title": "RAG data handling and untrusted-content control evidence",
        "required": ["Data source inventory", "RAG threat model", "Retrieval access-control test", "Secure prompt assembly design", "Retest evidence"],
    },
    "Unauthorized Retrieval": {
        "clause": "ISO/IEC 42001:2023 evidence placeholder - data governance and access control",
        "title": "Restricted information access-control evidence",
        "required": ["Data classification", "Access-control policy", "Retrieval authorization logs", "Exception review", "Corrective action"],
    },
    "Unauthorized Tool Execution": {
        "clause": "ISO/IEC 42001:2023 evidence placeholder - AI system operation and human oversight",
        "title": "Tool-use authorization and oversight evidence",
        "required": ["Tool inventory", "Role matrix", "Authorization logs", "Security event logs", "Owner approval"],
    },
    "Confirmation Bypass": {
        "clause": "ISO/IEC 42001:2023 evidence placeholder - human oversight and operational control",
        "title": "External action confirmation evidence",
        "required": ["Human oversight design", "Approval workflow record", "Action logs", "Bypass test evidence", "Retest result"],
    },
    "Memory Isolation": {
        "clause": "ISO/IEC 42001:2023 evidence placeholder - data lifecycle and privacy controls",
        "title": "Conversation memory isolation evidence",
        "required": ["Memory design", "Session isolation test", "Data retention policy", "Access logs", "Deletion/retest evidence"],
    },
}


def map_finding_to_iso(finding: Finding) -> ISOMapping:
    template = MAPPING_TEMPLATES.get(
        finding.category,
        {
            "clause": "ISO/IEC 42001:2023 evidence placeholder - human review required",
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
            "Technical observation is relevant to AI risk treatment, operational monitoring, "
            "documented evidence, and human-review workflow. This is not a certification decision."
        ),
        relevance_type="Relevant",
        required_organizational_evidence=template["required"],
        available_evidence=finding.evidence_references,
        missing_evidence=["Management approval record", "Formal control owner attestation"],
        evidence_sufficiency="Partial",
        mapping_confidence=finding.confidence,
    )

