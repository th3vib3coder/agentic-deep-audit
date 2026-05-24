from src.app import main


def test_main() -> None:
    assert main() == "ok"
