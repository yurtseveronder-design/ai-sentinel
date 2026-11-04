from sentinel_core.shield import BioImmuneShield

class APISecurityRunner:
    def __init__(self):
        self.shield = BioImmuneShield()

    def validate_endpoint(self, payload: str) -> dict:
        return self.shield.scan(payload)