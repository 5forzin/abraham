"""Chunked file upload to the avln VM over Azure Run Command.

The VM's only admin channel is RunShellScript (no usable SSH from the
lab network), and one run-command script is capped at ~64 KB — so a file
travels gzip+base64 in chunks that append to a staging file on the VM,
and a final script decodes, unpacks and installs it.

Usage:
    python upload_chunked.py LOCAL REMOTE
"""

import base64
import gzip
import hashlib
import os
import subprocess
import sys
import tempfile
import time

RG, VM = "rg-avln", "vm-avln"
# az.cmd misbehaves under subprocess on Windows; the CLI's own python works.
AZ = [r"C:\Program Files\Microsoft SDKs\Azure\CLI2\python.exe", "-m", "azure.cli"]
CHUNK = 60_000


def run_vm(script_text, timeout=900):
    with tempfile.NamedTemporaryFile(
        "w", suffix=".sh", delete=False, newline="\n"
    ) as handle:
        handle.write(script_text)
        path = handle.name
    try:
        return subprocess.run(
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
            timeout=timeout,
        )
    finally:
        os.unlink(path)


def out_of(result):
    message = result.stdout or ""
    if result.returncode != 0 or "[stdout]" not in message:
        raise RuntimeError(
            f"run-command failed: {(result.stderr or message)[:300]}"
        )
    return message[message.find("[stdout]") + 9 : message.find("[stderr]")].strip()


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    local, remote = sys.argv[1], sys.argv[2]
    data = open(local, "rb").read()
    payload = base64.b64encode(gzip.compress(data)).decode()
    chunks = [payload[i : i + CHUNK] for i in range(0, len(payload), CHUNK)]
    print(f"upload: {local} -> {remote} ({len(data)} bytes, {len(chunks)} chunks)", flush=True)
    staging = remote + ".b64"
    out_of(run_vm(f"rm -f {staging}"))
    for i, chunk in enumerate(chunks, 1):
        script = f"printf '%s' '{chunk}' >> {staging}\nwc -c < {staging}"
        for _ in range(3):
            try:
                result = run_vm(script)
            except subprocess.TimeoutExpired:
                continue
            if result.returncode == 0 and "[stdout]" in (result.stdout or ""):
                break
            time.sleep(10)
        else:
            sys.exit(f"chunk {i} failed after 3 attempts")
        if i % 5 == 0 or i == len(chunks):
            print(f"  chunk {i}/{len(chunks)}", flush=True)
    install = (
        f"base64 -d {staging} | gunzip > {remote} && "
        f"chmod 644 {remote} && rm -f {staging} && "
        f"sha256sum {remote} && wc -c < {remote}"
    )
    print(out_of(run_vm(install)))
    print(f"local sha256: {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
