from src.hot import process_items


def test_process_items():
    assert process_items(["1", "2", "3"]) > 0
