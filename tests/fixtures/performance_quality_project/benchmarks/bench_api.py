from src.hot import process_items


def bench_process_items():
    return process_items(str(index) for index in range(100))
