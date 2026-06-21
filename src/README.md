# src

The actual hardened dev container artifacts, built by implementer to spec: docker-compose, .devcontainer (devcontainer.json + Dockerfile), gateway sidecar (firewall, proxy, DNS, allowlist), .vscode settings, mcp.json, hooks, caches. Pinned by digest, least-privilege, no NET_ADMIN in the dev container, no docker.sock.
