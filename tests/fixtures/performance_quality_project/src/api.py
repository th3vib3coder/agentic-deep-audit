import requests

from .hot import process_items


def fetch_and_process(url):
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    return process_items(response.text.splitlines())
