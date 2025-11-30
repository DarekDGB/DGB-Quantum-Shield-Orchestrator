class ShieldContext:
    def __init__(self, config: "ShieldConfig"):
        self.config = config
        self.events = []

    def log(self, message):
        if self.config.enable_logging:
            print(f"[Shield] {message}")
