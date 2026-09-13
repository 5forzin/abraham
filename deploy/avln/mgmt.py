"""One mgmt request against the avln teamserver over Azure Run Command.

The teamserver mgmt port (9200) speaks newline-delimited JSON over raw
TCP — not HTTP — and RunShellScript executes via dash (no /dev/tcp), so
the request travels base64-encoded through python3 on the VM.

Usage:
    python mgmt.py '{"cmd":"sessions"}'
    python mgmt.py '{"cmd":"results","session":1,"limit":5}'
"""

import base64
import json
import os
import subprocess
import sys
import tempfile

RG, VM = "rg-avln", "vm-avln"
# az.cmd misbehaves under subprocess on Windows; the CLI's own python works.
AZ = [r"C:\Program Files\Microsoft SDKs\Azure\CLI2\python.exe", "-m", "azure.cli"]

PY_ONE = (
    "import socket,base64,sys;"
    "s=socket.create_connection(('127.0.0.1',9200),3);"
    "s.sendall(base64.b64decode(sys.argv[1])+b'\\n');"
    "s.settimeout(5);"
    "print(s.recv(65536).decode().strip())"
)


def mgmt(request):
    payload = base64.b64encode(json.dumps(request).encode()).decode()
    with tempfile.NamedTemporaryFile(
        "w", suffix=".sh", delete=False, newline="\n"
    ) as handle:
        handle.write(f'python3 -c "{PY_ONE}" "{payload}"\n')
        path = handle.name
    try:
        result = subprocess.run(
            AZ
            + [
                "vm",
                "run-command",
                "invoke",
                "-g",
                RG,
                "-n",
                VM,
                "--command-id",
                "RunShellScript",
                "--scripts",
                "@" + path.replace("\\", "/"),
                "--query",
                "value[0].message",
                "-o",
                "tsv",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
    finally:
        os.unlink(path)
    if result.returncode != 0:
        raise RuntimeError(f"az failed: {(result.stderr or '')[:300]}")
    # The message carries "[stdout]\n...\n[stderr]\n" with real newlines.
    message = result.stdout or ""
    if "[stdout]" not in message:
        raise RuntimeError(f"unexpected run-command output: {message[:300]}")
    return message[message.find("[stdout]") + 9 : message.find("[stderr]")].strip()


if __name__ == "__main__":
    req = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {"cmd": "sessions"}
    print(mgmt(req))
