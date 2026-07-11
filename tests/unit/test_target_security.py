from packages.security_assurance.target_security import NetworkPolicy, validate_target_url


def test_blocks_file_scheme() -> None:
    result = validate_target_url("file:///etc/passwd")
    assert not result.valid
    assert "Only http and https" in result.errors[0]


def test_blocks_cloud_metadata_ip() -> None:
    result = validate_target_url("http://169.254.169.254/latest/meta-data")
    assert not result.valid
    assert any("metadata" in error for error in result.errors)


def test_allows_configured_local_lab_host() -> None:
    policy = NetworkPolicy(allow_local_targets=True, allowed_local_hosts={"localhost"}, allowed_ports={8090})
    result = validate_target_url("http://localhost:8090/health", policy)
    assert result.valid
    assert any("Local laboratory" in decision for decision in result.decisions)

