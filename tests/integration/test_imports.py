def test_core_imports() -> None:
    import packages.security_assurance.orchestrator as orchestrator

    assert orchestrator.AssessmentOrchestrator is not None

