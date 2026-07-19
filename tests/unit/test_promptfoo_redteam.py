from pathlib import Path


WORKER = Path("workers/promptfoo-worker/server.js").read_text()


def test_local_attacker_provider_and_remote_disable_are_configured():
    assert "local-attacker-provider" in WORKER
    assert "PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION" in WORKER
    assert "redteam" in WORKER and "provider" in WORKER


def test_target_provider_remains_separate_and_handoff_changes_suite():
    assert "target-proxy-provider" in WORKER
    assert "handoff_consumed" in WORKER
    assert "handoff_payload" in WORKER


def test_generation_is_bounded_and_artifacts_are_persisted():
    assert "numTests" in WORKER
    assert "generatedPath" in WORKER
    assert "attacker-invocations" in WORKER
    assert "promptfoo-cli.json" in WORKER


def test_native_results_not_metadata_only():
    assert "resultRows" in WORKER
    assert "native_engine_invoked: true" in WORKER
    assert "promptfoo CLI returned" in WORKER
