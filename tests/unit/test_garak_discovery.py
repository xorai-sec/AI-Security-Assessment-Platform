from packages.security_assurance.evidence_handoff import EvidenceHandoffPlanner
from packages.security_assurance.garak_discovery import capability_probe_selection


def test_capabilities_choose_different_probe_sets():
    raw = capability_probe_selection({"chat": True}, "reconnaissance")
    rag = capability_probe_selection({"chat": True, "rag": True}, "reconnaissance")
    tools = capability_probe_selection({"chat": True, "tools": True}, "targeted_expansion")
    assert raw != rag
    assert any("goodside" in probe for probe in tools)


def test_duplicate_garak_attempts_create_one_opportunity(tmp_path):
    row = {
        "execution_id": "g-1",
        "framework": "garak",
        "category": "prompt_injection",
        "probe": "promptinject.HijackLongPrompt",
        "detector": "detector",
        "prompt": "attack",
        "response": "refusal",
        "confidence": 0.8,
        "success": True,
    }
    duplicate = dict(row, execution_id="g-2")
    _, _, opportunities = EvidenceHandoffPlanner(tmp_path).analyze([row, duplicate])
    assert len(opportunities) == 1


def test_low_quality_signal_is_rejected(tmp_path):
    row = {
        "execution_id": "g-1",
        "framework": "garak",
        "probe": "p",
        "detector": "d",
        "prompt": "",
        "response": "",
        "confidence": 0.9,
    }
    _, _, opportunities = EvidenceHandoffPlanner(tmp_path).analyze([row])
    assert opportunities == []


def test_valid_garak_signal_handoff_keeps_evidence_and_hash(tmp_path):
    row = {
        "execution_id": "g-1",
        "framework": "garak",
        "category": "prompt_injection",
        "probe": "promptinject.HijackLongPrompt",
        "detector": "detector",
        "prompt": "attack",
        "response": "unsafe response",
        "confidence": 0.8,
        "success": True,
        "evidence_hash": "sha256:abc",
    }
    planner = EvidenceHandoffPlanner(tmp_path)
    _, _, opportunities = planner.analyze([row])
    handoff = planner.build_handoff(
        assessment_id="A", source_framework="garak", target_framework="pyrit", opportunities=opportunities
    )
    assert handoff is not None
    assert handoff.payload.source_evidence_ids == ["g-1"]
    assert handoff.payload.inputs["objectives"][0]["evidence_references"] == ["g-1"]


def test_benign_hardened_response_is_not_finding(tmp_path):
    row = {
        "execution_id": "g-1",
        "framework": "garak",
        "probe": "p",
        "detector": "d",
        "prompt": "attack",
        "response": "I cannot help with that",
        "confidence": 0.0,
        "success": False,
    }
    _, _, opportunities = EvidenceHandoffPlanner(tmp_path).analyze([row])
    assert opportunities == []
