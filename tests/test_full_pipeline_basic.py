import pytest

from shield_orchestrator.bridges.adn_bridge import ADNBridge
from shield_orchestrator.bridges.base_layer import BaseLayer
from shield_orchestrator.bridges.dqsn_bridge import DQSNBridge
from shield_orchestrator.bridges.guardian_wallet_bridge import GuardianWalletBridge
from shield_orchestrator.bridges.qwg_bridge import QWGBridge
from shield_orchestrator.bridges.sentinel_bridge import SentinelBridge
from shield_orchestrator.pipeline import FullShieldPipeline


_EXPECTED_MESSAGE = "Legacy BaseLayer"


def test_full_shield_pipeline_process_event_is_disabled() -> None:
    pipeline = FullShieldPipeline.from_default_config()

    with pytest.raises(RuntimeError, match=_EXPECTED_MESSAGE):
        pipeline.process_event({"type": "test"})


def test_base_layer_process_is_disabled_instead_of_all_pass() -> None:
    layer = BaseLayer()

    with pytest.raises(RuntimeError, match=_EXPECTED_MESSAGE):
        layer.process({"type": "test"})


def test_component_bridge_legacy_process_paths_are_disabled() -> None:
    for bridge in (
        SentinelBridge(),
        DQSNBridge(),
        ADNBridge(),
        GuardianWalletBridge(),
        QWGBridge(),
    ):
        with pytest.raises(RuntimeError, match=_EXPECTED_MESSAGE):
            bridge.process({"type": "test"})
