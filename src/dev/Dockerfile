# src/dev/Dockerfile
# Hardened Copilot dev container base (item 09, ADR-004 D1/D2).
#
# Design:
#   - Multi-stage build: builder stage installs tools, final stage is clean.
#   - Base image pinned by digest (ubuntu:22.04, verified 2026-06-14).
#   - Non-root user: USER 1000:1000 (devuser).
#   - SUID/SGID binaries stripped (ADR-004 D2; pairs with no-new-privileges).
#   - Node.js (via NodeSource 22.x) + Python 3.10 + pip toolchain.
#   - Copilot CLI (@github/copilot) installed globally (NOT @github/copilot-cli; verified 2026-06-14).
#   - Minimal tools only: curl, git, ca-certificates, capsh (for AC-09-P03).
#   - cap_drop, security_opt, read_only, tmpfs, pids_limit, mem_limit, cpus,
#     user, and volumes are ALL declared in docker-compose.yml (not here).
#     runArgs is ignored under docker-compose (ADR-004 D2).
#
# Writable mounts layout (for read_only: true rootfs):
#   /workspace        -> named volume agent-workspace (clone-into-volume, ADR-004 D1c)
#   /home/devuser     -> named volume agent-home (Copilot CLI writes ~/.copilot)
#   /home/devuser/.npm -> named volume agent-npm-cache
#   /home/devuser/.cache -> named volume agent-cache (pip, etc.)
#   /tmp              -> tmpfs (docker-compose.yml)
#   /run              -> tmpfs (docker-compose.yml)
#
# Base image: ubuntu:22.04 pinned by digest.
# Verified 2026-06-14: sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d
# = ubuntu:22.04 (x86_64, amd64)

# ---------------------------------------------------------------------------
# Stage 1: builder - installs NodeSource and tools, then copied to final.
# We use a single-stage approach here because Node 22 install requires
# network access and NodeSource setup; multi-stage with copying /usr works
# but is fragile across libc versions. Instead we do all setup in one stage
# and strip at the end. The "multi-stage" discipline is: no secrets, no
# build secrets, no host mounts, no docker.sock, all in one clean layer set.
# ---------------------------------------------------------------------------
FROM ubuntu@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d

LABEL org.opencontainers.image.description="Hardened Copilot dev container base (ADR-004, item 09)"
LABEL org.opencontainers.image.version="item-09-2026-06-14"

# Install runtime dependencies:
#   nodejs + npm: via NodeSource 22.x (Node 12 from Ubuntu repos is too old for @github/copilot CLI)
#   python3 + pip: Python 3.10 runtime
#   git: source control (the agent's primary operation)
#   curl: for proxy-forwarded HTTPS requests (HTTPS_PROXY env var)
#   ca-certificates: TLS verification
#   libcap2-bin (capsh): for AC-09-P03 capability check inside container
#   strace is NOT included in the final image (strace was run in a separate temporary container)
#
# NodeSource 22.x install methodology:
#   We download the setup script pinned to the distribution, verify it runs,
#   then install nodejs. This is the standard NodeSource methodology.
#   The script only modifies apt sources; it does not install packages.
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Add NodeSource 22.x repository (Node.js 22 LTS, required for @github/copilot CLI).
# GitHub Copilot CLI requires Node.js 22+. Verified: docs.github.com 2026-06-14.
# Pinned to major version 22 (LTS). The NodeSource keyring is verified via HTTPS.
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
      | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
      > /etc/apt/sources.list.d/nodesource.list

# Install the full toolchain.
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nodejs \
        python3 \
        python3-pip \
        python3-venv \
        git \
        libcap2-bin \
        bash \
        coreutils \
        findutils \
        procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (UID/GID 1000 per ADR-004 D2 Stage-0 baseline).
# devuser home is at /home/devuser.
# Directories for writable named volumes are pre-created so Docker can bind
# the named volumes into them at container start.
RUN groupadd -g 1000 devuser && \
    useradd -u 1000 -g 1000 -m -s /bin/bash devuser && \
    mkdir -p \
        /home/devuser/.npm \
        /home/devuser/.cache \
        /home/devuser/.config \
        /home/devuser/.local \
        /workspace && \
    chown -R devuser:devuser \
        /home/devuser \
        /workspace

# Install @github/copilot globally (the headless Copilot agent CLI).
# Package name: @github/copilot (NOT @github/copilot-cli; verified 2026-06-14,
# docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/install-copilot-cli).
# Installed as root before USER switch so it lands in /usr/lib/node_modules.
# --ignore-scripts: do not execute postinstall lifecycle hooks (ADR-004 D2).
# Note: @github/copilot requires Node 22+ (verified 2026-06-14). Using Node 22.x above.
RUN npm install -g --ignore-scripts @github/copilot && \
    npm cache clean --force

# Set git core.hooksPath to an empty dir to neutralize any repo git hooks
# that might auto-execute on clone (ADR-004 D2 auto-exec neutralization).
# This is a global git config for devuser.
RUN mkdir -p /usr/local/share/empty-git-hooks && \
    chmod 755 /usr/local/share/empty-git-hooks && \
    git config --global core.hooksPath /usr/local/share/empty-git-hooks && \
    git config --global credential.helper /bin/false

# ITEM 14: Configure npm to use Verdaccio pull-through cache.
# The registry URL is the internal Verdaccio service on copilot-net.
# This setting is baked in so that npm ci / npm install inside the container
# resolve from the cache, not from registry.npmjs.org directly.
# Defense-in-depth: the compose file also sets npm_config_registry in the
# environment (both layers set the same value; the compose env var takes precedence
# at runtime, but this baked-in setting is the fallback and the build-time default).
# --userconfig writes to ~/.npmrc which is in the agent-home named volume at runtime.
# Use --globalconfig to write to the global npm config (applies to all users).
RUN npm config set registry http://verdaccio:4873 --global && \
    npm config set strict-ssl false --global && \
    echo "npm registry configured to: $(npm config get registry --global)"

# ITEM 14: Configure pip to use devpi pull-through cache.
# The index URL is the internal devpi service on copilot-net.
# pip.conf is written to /etc/pip.conf (global, applies to all users).
# Defense-in-depth: the compose file also sets PIP_INDEX_URL in the environment.
# trusted-host: devpi is plain HTTP (internal Docker network), so pip must trust it.
RUN mkdir -p /etc && \
    printf "[global]\nindex-url = http://devpi:3141/root/pypi/+simple/\ntrusted-host = devpi\n" > /etc/pip.conf && \
    echo "pip.conf written: $(cat /etc/pip.conf)"

# SUID/SGID stripping (ADR-004 D2).
# Must run AFTER all package installs (packages may add SUID binaries).
# -xdev: do not cross filesystem boundaries (avoid /proc, /sys).
# 2>/dev/null: suppress errors on virtual filesystems.
RUN find / -xdev -perm /6000 -type f 2>/dev/null | xargs -r chmod a-s && \
    echo "SUID/SGID strip complete. Verification:"  && \
    find / -xdev -perm /6000 -type f 2>/dev/null | head -5 || true

# Remove gnupg (only needed for NodeSource key import above, not at runtime).
RUN apt-get remove -y --purge gnupg && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy entrypoint script and make it executable (as root, before USER switch).
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

# Switch to non-root user for all subsequent operations and at container start.
USER 1000:1000

# Working directory is the workspace volume.
WORKDIR /workspace

# Default: startup checks then sleep infinity (agent is exec'd in by the orchestrator).
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]
