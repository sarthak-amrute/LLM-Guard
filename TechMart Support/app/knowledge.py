from pathlib import Path


KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"


def load_knowledge():
    knowledge = {}

    for file_path in KNOWLEDGE_DIR.glob("*.txt"):
        knowledge[file_path.stem] = file_path.read_text(
            encoding="utf-8"
        )

    return knowledge
