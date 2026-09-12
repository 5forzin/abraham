"""Mgmt helper for VM lab runs (avoids bash/JSON escaping issues).

usage:
  vm_mgmt.py sessions
  vm_mgmt.py shell <session> <command...>
  vm_mgmt.py upload <session> <local> <remote>
  vm_mgmt.py download <session> <path>
  vm_mgmt.py results <session>
"""

import json
import socket
import sys


def call(request, port=9200):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall((json.dumps(request) + "\n").encode())
        with sock.makefile() as rf:
            return json.loads(rf.readline())


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    cmd, rest = args[0], args[1:]
    if cmd == "sessions":
        out = call({"cmd": "sessions"})
    elif cmd == "shell":
        out = call({
            "cmd": "shell",
            "session": int(rest[0]),
            "command": " ".join(rest[1:]),
        })
    elif cmd == "module":
        out = call({
            "cmd": "module",
            "session": int(rest[0]),
            "name": rest[1],
            "args": " ".join(rest[2:]),
        })
    elif cmd == "upload":
        out = call({
            "cmd": "upload",
            "session": int(rest[0]),
            "local": rest[1],
            "remote": rest[2],
        })
    elif cmd == "download":
        out = call({"cmd": "download", "session": int(rest[0]), "path": rest[1]})
    elif cmd == "driver":
        # driver <session> load <service> <source> <drop_path>
        # driver <session> unload <service> [drop_path]
        # driver <session> probe [depth]
        # driver <session> map [payload.sys]
        action = rest[1]
        if action in (
            "probe",
            "elevate",
            "gate",
            "hide",
            "unhide",
            "call-preflight",
            "call",
            "map",
            "modhide",
            "modshow",
            "protect",
            "chan",
        ):
            depth = rest[2] if action in ("probe", "map", "modhide", "modshow", "protect", "chan") and len(rest) > 2 else ""
            out = call({"cmd": "driver", "session": int(rest[0]), "action": action,
                        "service": "", "source": depth, "drop_path": ""})
        elif action == "load":
            out = call({
                "cmd": "driver",
                "session": int(rest[0]),
                "action": action,
                "service": rest[2],
                "source": rest[3],
                "drop_path": rest[4],
            })
        else:
            out = call({
                "cmd": "driver",
                "session": int(rest[0]),
                "action": action,
                "service": rest[2],
                "source": "",
                "drop_path": rest[3] if len(rest) > 3 else "",
            })
    elif cmd == "results":
        out = call({"cmd": "results", "session": int(rest[0])})
    else:
        print(__doc__)
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
