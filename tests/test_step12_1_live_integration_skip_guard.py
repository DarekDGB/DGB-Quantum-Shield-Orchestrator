from pathlib import Path


def test_live_integration_test_fails_instead_of_import_skipping() -> None:
    content = Path("tests/live/test_step11_2_real_component_integration.py").read_text(
        encoding="utf-8"
    )

    assert "importorskip(" not in content
    assert "importlib.import_module" in content
    assert "Do not use skip-on-import helpers" in content


def test_live_integration_workflow_asserts_zero_skips() -> None:
    workflow = Path(".github/workflows/live-shield-integration.yml").read_text(
        encoding="utf-8"
    )

    assert "--junitxml=live-shield-integration-results.xml" in workflow
    assert "Assert live proof was not skipped" in workflow
    assert "if skipped:" in workflow
    assert "live integration proof skipped" in workflow
    assert "if not testcases:" in workflow
