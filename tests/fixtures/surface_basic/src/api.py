import os

from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": os.environ.get("APP_STATUS", "ok")}


def main() -> None:
    print("surface")


if __name__ == "__main__":
    main()
