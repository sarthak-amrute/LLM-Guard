from pathlib import Path


PROTECTED_FILE = Path(__file__).parent.parent / "internal" / "protected_data.txt"


def load_protected_data():
    return PROTECTED_FILE.read_text(encoding="utf-8")