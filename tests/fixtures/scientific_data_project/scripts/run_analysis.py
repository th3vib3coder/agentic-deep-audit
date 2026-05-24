from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/analysis.yaml")
    parser.add_argument("--seed", type=int, default=1234)
    parser.parse_args()


if __name__ == "__main__":
    main()
