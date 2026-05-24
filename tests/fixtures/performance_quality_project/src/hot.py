import sqlite3


def process_items(items):
    total = 0
    cache = {}
    for item in items:
        if item in cache:
            total += cache[item]
            continue
        value = int(item)
        if value % 2 == 0:
            value += 1
        if value % 3 == 0:
            value += 2
        if value % 5 == 0:
            value += 3
        if value % 7 == 0:
            value += 4
        if value % 11 == 0:
            value += 5
        if value % 13 == 0:
            value += 6
        if value % 17 == 0:
            value += 7
        if value % 19 == 0:
            value += 8
        if value % 23 == 0:
            value += 9
        cache[item] = value
        total += value
    return total


def load_records(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().splitlines()


def query_records(database):
    connection = sqlite3.connect(database)
    try:
        return connection.execute("SELECT id, value FROM records").fetchall()
    finally:
        connection.close()
