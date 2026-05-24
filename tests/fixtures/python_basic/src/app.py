import os

from src.utils import Greeter, helper


if os.environ.get("FEATURE_FLAG"):
    import json


def main() -> str:
    greeter = Greeter()
    return helper(greeter.greet("ok"))


if __name__ == "__main__":
    main()
