"""One mgmt request against the avln teamserver over plain SSH (Contabo).

The teamserver mgmt port (9200) speaks newline-delimited JSON over raw
TCP — not HTTP. This helper ships a small python sender to the VM via
ssh stdin (sudo reads the token file, chmod 600 root) and prints the
last response line, mirroring deploy/avln/mgmt.py.

Usage:
    python mgmt.py '{"cmd":"sessions"}'
    python mgmt.py '{"cmd":"results","session":1,"limit":5}'
    python mgmt.py '{"cmd":"cfg","action":"list"}'
"""

import base64
import json
import os
import subprocess
import sys

SSH_DEST = "lilithops@13.140.191.31"
SSH_KEY = os.path.expanduser("~/.ssh/id_rsa")
# The operator network blocks outbound 22; SSH rides the ETL SOCKS5
# proxy by default. ABLN_SOCKS="" falls back to a direct connection.
SOCKS = os.environ.get("ABLN_SOCKS", "127.0.0.1:1080")
PROXY = (
    ["-o", f"ProxyCommand=connect -S {SOCKS} %h %p"] if SOCKS else []
)
SSH = [
    "ssh", *PROXY, "-i", SSH_KEY,
    "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
    SSH_DEST, "sudo -n python3 -",
]
TOKEN_FILE = os.environ.get("ABRAHAM_MGMT_TOKEN_FILE", "/opt/avln/mgmt.token")

# Runs ON the VM: auth line + request over raw TCP, read until a 1s
# quiet gap so the ack and the reply both land. The request rides as a
# base64 literal so no quoting survives the ssh hop.
SENDER = """import base64, json, socket
tok = open("{token_file}").read().strip()
req = json.loads(base64.b64decode("{req_b64}"))
s = socket.create_connection(("127.0.0.1", 9200), 3)
s.sendall((json.dumps({{"auth": tok}}) + "\\n" + json.dumps(req) + "\\n").encode())
s.settimeout(1)
out = []
while True:
    try:
        d = s.recv(65536)
        if not d:
            break
        out.append(d)
    except socket.timeout:
        break
reply = b"".join(out).decode().strip()
print(reply.splitlines()[-1] if reply else "")
"""


def mgmt(request):
    sender = SENDER.format(
        token_file=TOKEN_FILE,
        req_b64=base64.b64encode(json.dumps(request).encode()).decode(),
    )
    result = subprocess.run(
        SSH, input=sender, capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        raise RuntimeError(f"ssh failed: {(result.stderr or '')[:300]}")
    if not result.stdout.strip():
        raise RuntimeError("empty mgmt reply")
    return result.stdout.strip()


if __name__ == "__main__":
    req = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {"cmd": "sessions"}
    print(mgmt(req))
