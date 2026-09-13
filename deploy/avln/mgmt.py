"""One mgmt request against the avln teamserver over Azure Run Command.

The teamserver mgmt port (9200) speaks newline-delimited JSON over raw
TCP — not HTTP — and RunShellScript executes via dash (no /dev/tcp), so
the request travels base64-encoded through python3 on the VM.

When the teamserver runs with --mgmt-token, the token is read from the
file the deploy wrote (/opt/avln/mgmt.token, overridable with
ABRAHAM_MGMT_TOKEN_FILE) and sent as the required {"auth": ...} first
line.

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

TOKEN_FILE = os.environ.get("ABRAHAM_MGMT_TOKEN_FILE", "/opt/avln/mgmt.token")

def mgmt(request):
    return _mgmt_two_stage(request)


def _vm_script(script: str) -> str:
    with tempfile.NamedTemporaryFile(
        "w", suffix=".sh", delete=False, newline="\n"
    ) as handle:
        handle.write(script)
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
    message = result.stdout or ""
    if "[stdout]" not in message:
        raise RuntimeError(f"unexpected run-command output: {message[:300]}")
    return message[message.find("[stdout]") + 9 : message.find("[stderr]")].strip()


def _mgmt_two_stage(request):
    # Stage 1: fetch the auth line (empty when no token file exists, so
    # the same script works against open and gated teamserver ports).
    # Stage 2: send [auth?, request] and print the last response line —
    # reading until a 1s quiet gap so the ack and the reply both land.
    fetch = (
        "if [ -f " + TOKEN_FILE + " ]; then python3 -c \"import base64,json;"
        "print(base64.b64encode(json.dumps({'auth':open('" + TOKEN_FILE
        + "').read().strip()}).encode()).decode())\"; fi"
    )
    auth_b64 = _vm_script(fetch)
    request_b64 = base64.b64encode(json.dumps(request).encode()).decode()

    sender = (
        "import socket,base64,sys\n"
        "s=socket.create_connection(('127.0.0.1',9200),3)\n"
        "lines=[base64.b64decode(a) for a in sys.argv[1:] if a]\n"
        "s.sendall(b'\\n'.join(lines)+b'\\n')\n"
        "s.settimeout(1)\n"
        "out=[]\n"
        "while True:\n"
        "    try:\n"
        "        d=s.recv(65536)\n"
        "        if not d: break\n"
        "        out.append(d)\n"
        "    except socket.timeout: break\n"
        "reply=b''.join(out).decode().strip()\n"
        "print(reply.splitlines()[-1] if reply else '')\n"
    )
    sender_b64 = base64.b64encode(sender.encode()).decode()
    send = (
        f"python3 -c \"import base64;exec(base64.b64decode('{sender_b64}'))\" "
        f"\"{auth_b64}\" \"{request_b64}\""
    )
    return _vm_script(send)


if __name__ == "__main__":
    req = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {"cmd": "sessions"}
    print(mgmt(req))
