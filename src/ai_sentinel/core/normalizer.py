class InputNormalizer:
    """
    Normalizes input text for security scanning and threat detection.
    """
    def __init__(self):
        pass

    def normalize(self, text: str) -> str:
        if not text:
            return ""
        # Strip excessive whitespace and normalize characters
        return " ".join(text.strip().split())