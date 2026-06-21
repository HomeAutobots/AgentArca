#!/usr/bin/env python3
"""
src/scripts/push-proxy-reject.py

Always-reject push proxy (SPEC-05 section 8, ADR-005 D5 sub-component ii).

Listens on localhost:9999 and rejects ALL git push Smart HTTP requests with a
human-readable error message. The devcontainer's git pushurl points here, so
any git push from inside the container fails with a clear explanation.

This is the simplest production-ready pattern per SPEC-05 section 8:
"reject all automated pushes with an error message; the developer reviews the
agent's commits and pushes manually from outside the container."

HONEST LIMIT (R-b, never claimed solved):
  This breaks the AUTONOMOUS push path. A human who reviews and pushes manually
  CAN carry a low-bandwidth exfil payload in a commit. R-b stays accepted +
  partially mitigated. R-g (approval-fatigue rubber-stamping) compounds R-b.

UPGRADE PATH: replace this with a proper approval-gating proxy that:
  (a) Requires a human-approved token or explicit human interaction before forwarding.
  (b) Logs all push attempts to the item 13 detection sink.
  (c) Scopes to a single branch and single repo (ADR-003 D6 fine-grained PAT).
  (d) Sends a webhook to Slack/email for human review of the agent's commits.
"""

import socket
import sys
import datetime

BIND_ADDR = "127.0.0.1"
BIND_PORT = 9999

REJECT_RESPONSE = (
    b"HTTP/1.1 403 Forbidden\r\n"
    b"Content-Type: text/plain\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"PUSH REJECTED: git push from the dev container requires human review.\n"
    b"\n"
    b"The Copilot agent has staged and committed changes. To push:\n"
    b"  1. Review the agent's commits: git log --oneline\n"
    b"  2. Inspect the changes: git diff HEAD~N..HEAD\n"
    b"  3. Push manually from OUTSIDE the container.\n"
    b"\n"
    b"This gate is LOAD-BEARING (ADR-005 D5, R-c/R-b mitigation).\n"
    b"Bypassing it defeats the write-path control.\n"
)


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((BIND_ADDR, BIND_PORT))
    except OSError as e:
        print(f"[push-proxy] ERROR: cannot bind {BIND_ADDR}:{BIND_PORT}: {e}", file=sys.stderr)
        sys.exit(1)
    server.listen(5)
    print(f"[push-proxy] Listening on {BIND_ADDR}:{BIND_PORT} - rejecting all pushes (human gate required)", file=sys.stderr)
    print(f"[push-proxy] ADR-005 D5 write-path control active.", file=sys.stderr)

    while True:
        try:
            conn, addr = server.accept()
            ts = datetime.datetime.utcnow().isoformat() + "Z"
            # Log the attempt (detection sink; item 13 may redirect this to the external sink).
            print(f'[push-proxy] {{"timestamp":"{ts}","event":"push_attempt","remote_addr":"{addr[0]}:{addr[1]}","decision":"reject"}}', file=sys.stderr)
            try:
                conn.recv(4096)  # consume request bytes
            except Exception:
                pass
            try:
                conn.send(REJECT_RESPONSE)
            except Exception:
                pass
            conn.close()
        except KeyboardInterrupt:
            print("[push-proxy] Shutting down.", file=sys.stderr)
            break
        except Exception as e:
            print(f"[push-proxy] ERROR: {e}", file=sys.stderr)

    server.close()
    sys.exit(0)


if __name__ == "__main__":
    main()
