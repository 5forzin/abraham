import json
import socket
import sys


def main():
    if len(sys.argv) < 2:
        print("usage: mgmt_client.py '<json>' [port]")
        return 1
    request = json.loads(sys.argv[1])
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9000
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall((json.dumps(request) + "\n").encode())
        with sock.makefile() as rf:
            line = rf.readline()
    print(line.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
