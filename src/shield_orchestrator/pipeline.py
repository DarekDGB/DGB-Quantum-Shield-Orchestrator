from .config import ShieldConfig
from .context import ShieldContext
from .bridges.sentinel_bridge import SentinelBridge
from .bridges.dqsn_bridge import DQSNBridge
from .bridges.adn_bridge import ADNBridge
from .bridges.guardian_wallet_bridge import GuardianWalletBridge
from .bridges.qwg_bridge import QWGBridge
from .bridges.adaptive_core_bridge import AdaptiveCoreBridge

class FullShieldPipeline:
    def __init__(self, config=None):
        self.config = config or ShieldConfig()
        self.ctx = ShieldContext(self.config)

        self.sentinel = SentinelBridge()
        self.dqsn = DQSNBridge()
        self.adn = ADNBridge()
        self.guardian = GuardianWalletBridge()
        self.qwg = QWGBridge()
        self.adaptive = AdaptiveCoreBridge()

    @staticmethod
    def from_default_config():
        return FullShieldPipeline()

    def process_event(self, event: dict) -> dict:
        flow = []

        flow.append(self.sentinel.process(event))
        flow.append(self.dqsn.process(event))
        flow.append(self.adn.process(event))
        flow.append(self.guardian.process(event))
        flow.append(self.qwg.process(event))

        immune = self.adaptive.process(event)

        return {"flow": flow, "immune": immune}
