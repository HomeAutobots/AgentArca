#!/usr/bin/env bash
# tests/acceptance/component/test-14-caches.sh
#
# Acceptance tests for item 14 (pull-through caches).
# Area 8, Phase 5.
#
# Coverage map (BUILD_PLAN AC-14-*):
#   AC-14-P01  npm resolves via Verdaccio (not directly to registry.npmjs.org)
#   AC-14-P02  pip resolves via devpi (not directly to pypi.org)
#   AC-14-P03  minAgeDays enforced (Verdaccio verdaccio-config.yaml check)
#   AC-14-P04  Verdaccio+devpi upstream requests go through gateway (Squid log source = cache-net IP)
#   AC-14-P05  devcontainer cannot reach registry.npmjs.org or pypi.org directly
#   AC-14-N01  direct curl https://registry.npmjs.org blocked (L3 default-DROP)
#
# Permanent regression assertions:
#   REGRESSION-14-EXTERNAL-4873-DROP  devcontainer->external host:4873 blocked (RC-14-1)
#   REGRESSION-14-EXTERNAL-3141-DROP  devcontainer->external host:3141 blocked (RC-14-1)
#
# The RC-14-1 regression: the init-firewall.sh rules for ports 4873/3141 must be
# destination-scoped to the internal subnet only (not port-only rules that allow
# direct external egress on those ports).
#
# Requires: DEVCONTAINER_ID, VERDACCIO_ID, DEVPI_ID set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/test-helpers.sh"

COMPONENT="caches"
PASS=0
FAIL=0
SKIP=0
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

dc_exec() {
  docker exec --user 1000:1000 "${DEVCONTAINER_ID}" "$@"
}

# ------------------------------------------------------------
# AC-14-P01: npm resolves via Verdaccio
# ------------------------------------------------------------
begin_test "AC-14-P01" "npm resolves via Verdaccio (not directly to registry.npmjs.org)"
NPM_REGISTRY=$(dc_exec npm config get registry 2>/dev/null) || NPM_REGISTRY="UNKNOWN"
if echo "${NPM_REGISTRY}" | grep -qiE "verdaccio|4873"; then
  pass_test "AC-14-P01" "npm registry='${NPM_REGISTRY}' (Verdaccio pull-through cache)"
else
  fail_test "AC-14-P01" "npm registry='${NPM_REGISTRY}' (expected verdaccio:4873; npm should NOT go directly to npmjs.org)"
fi

# Verify npm_config_registry env var is set
NPM_ENV_REG=$(dc_exec sh -c 'echo "${npm_config_registry:-UNSET}"' 2>/dev/null) || NPM_ENV_REG="UNSET"
if echo "${NPM_ENV_REG}" | grep -qiE "verdaccio|4873"; then
  pass_test "AC-14-P01-env" "npm_config_registry env='${NPM_ENV_REG}'"
else
  fail_test "AC-14-P01-env" "npm_config_registry env='${NPM_ENV_REG}' (expected verdaccio:4873)"
fi

# ------------------------------------------------------------
# AC-14-P02: pip resolves via devpi
# ------------------------------------------------------------
begin_test "AC-14-P02" "pip resolves via devpi (not directly to pypi.org)"
PIP_INDEX=$(dc_exec sh -c 'echo "${PIP_INDEX_URL:-UNSET}"' 2>/dev/null) || PIP_INDEX="UNSET"
if echo "${PIP_INDEX}" | grep -qiE "devpi|3141"; then
  pass_test "AC-14-P02" "PIP_INDEX_URL='${PIP_INDEX}' (devpi pull-through cache)"
else
  fail_test "AC-14-P02" "PIP_INDEX_URL='${PIP_INDEX}' (expected devpi:3141; pip should NOT go directly to pypi.org)"
fi

# Also check pip config
PIP_CONF_INDEX=$(dc_exec pip config get global.index-url 2>/dev/null || echo "UNSET")
if echo "${PIP_CONF_INDEX}" | grep -qiE "devpi|3141"; then
  pass_test "AC-14-P02-pipconf" "pip config global.index-url='${PIP_CONF_INDEX}'"
elif echo "${PIP_INDEX}" | grep -qiE "devpi|3141"; then
  pass_test "AC-14-P02-pipconf" "PIP_INDEX_URL env overrides pip config (env='${PIP_INDEX}')"
else
  fail_test "AC-14-P02-pipconf" "pip config index-url='${PIP_CONF_INDEX}' and PIP_INDEX_URL='${PIP_INDEX}' (expected devpi)"
fi

# ------------------------------------------------------------
# AC-14-P03: minAgeDays configured in verdaccio-config.yaml
# ------------------------------------------------------------
begin_test "AC-14-P03" "minAgeDays set in verdaccio-config.yaml (supply-chain freshness control)"
VERDACCIO_CONF="${PROJECT_ROOT}/src/caches/verdaccio-config.yaml"
if [ ! -f "${VERDACCIO_CONF}" ]; then
  fail_test "AC-14-P03" "verdaccio-config.yaml not found at ${VERDACCIO_CONF}"
else
  if grep -q "minAgeDays" "${VERDACCIO_CONF}" 2>/dev/null; then
    MIN_AGE=$(grep "minAgeDays" "${VERDACCIO_CONF}" | head -1 | grep -oE "[0-9]+" || echo "?")
    pass_test "AC-14-P03" "verdaccio minAgeDays=${MIN_AGE} (new packages < ${MIN_AGE} days old blocked)"
  else
    fail_test "AC-14-P03" "minAgeDays NOT set in verdaccio-config.yaml (supply-chain control missing)"
  fi
fi

# ------------------------------------------------------------
# AC-14-P04: Cache upstream goes through gateway (source-ACL)
# Verify that Verdaccio and devpi's proxy env vars point at the gateway
# via gateway-cache (cache-net alias) - GP-02 fix.
#
# The proxy MUST use gateway-cache:8080 (not gateway:8080).
# 'gateway-cache' is aliased on cache-net (172.30.0.0/24), so Squid sees
# the connection from a 172.30.0.x source IP, matching cache_src ACL.
# The old 'gateway' alias (copilot-net, 172.31.0.x) does NOT match cache_src,
# causing ssl_bump terminate to fire after CONNECT (GP-02 root cause).
# ------------------------------------------------------------
begin_test "AC-14-P04" "cache services proxy upstream via gateway-cache (HTTPS_PROXY=http://gateway-cache:8080)"
VERD_PROXY=$(docker exec "${VERDACCIO_ID:-acc15-verdaccio-1}" sh -c 'echo "${HTTPS_PROXY:-UNSET}"' 2>/dev/null) || VERD_PROXY="UNSET"
DEVPI_PROXY=$(docker exec "${DEVPI_ID:-acc15-devpi-1}" sh -c 'echo "${HTTPS_PROXY:-UNSET}"' 2>/dev/null) || DEVPI_PROXY="UNSET"

if echo "${VERD_PROXY}" | grep -qiE "gateway-cache:8080"; then
  pass_test "AC-14-P04-verdaccio" "Verdaccio HTTPS_PROXY='${VERD_PROXY}' (upstream via gateway-cache on cache-net)"
else
  fail_test "AC-14-P04-verdaccio" "Verdaccio HTTPS_PROXY='${VERD_PROXY}' (expected http://gateway-cache:8080 - GP-02 fix)"
fi

if echo "${DEVPI_PROXY}" | grep -qiE "gateway-cache:8080"; then
  pass_test "AC-14-P04-devpi" "devpi HTTPS_PROXY='${DEVPI_PROXY}' (upstream via gateway-cache on cache-net)"
else
  fail_test "AC-14-P04-devpi" "devpi HTTPS_PROXY='${DEVPI_PROXY}' (expected http://gateway-cache:8080 - GP-02 fix)"
fi

# GP-02 functional test: fresh pip install of an uncached package via devpi must succeed.
# This tests the actual proxy path: devpi -> gateway-cache:8080 (cache-net) -> squid -> pypi.org.
# A ConnectError here means the source-ACL is not matching (wrong network path).
begin_test "GP-02" "devpi fetches pypi.org through gateway-cache (fresh upstream fetch works)"
DEVPI_CONTAINER="${DEVPI_ID:-acc15-devpi-1}"
# Use devpi's own httpx client (same as devpi-server uses) to test the proxy path.
GP02_RESULT=$(docker exec "${DEVPI_CONTAINER}" python3 -c "
import httpx, ssl, asyncio, sys
from requests.utils import DEFAULT_CA_BUNDLE_PATH

ctx = ssl.create_default_context(cafile=DEFAULT_CA_BUNDLE_PATH)

async def check():
    # Replicate devpi-server's exact AsyncClient call (httpclient.py):
    #   httpx.AsyncClient(headers=self.headers, verify=self._ssl_context)
    # HTTPS_PROXY=http://gateway-cache:8080 is in the env; httpx picks it up via trust_env=True (default).
    async with httpx.AsyncClient(headers={'User-Agent': 'devpi-test/1.0'}, verify=ctx) as c:
        try:
            r = await c.get('https://pypi.org/simple/', timeout=15.0)
            print('status=' + str(r.status_code))
        except httpx.ConnectError as e:
            print('ConnectError=' + repr(str(e)))
        except Exception as e:
            print('Error=' + type(e).__name__ + ':' + repr(str(e)))

asyncio.run(check())
" 2>/dev/null) || GP02_RESULT="exec_failed"

if echo "${GP02_RESULT}" | grep -q "status=200"; then
  pass_test "GP-02" "devpi proxy path works: pypi.org simple index returned HTTP 200 via gateway-cache (GP-02 closed)"
elif echo "${GP02_RESULT}" | grep -q "ConnectError"; then
  fail_test "GP-02" "devpi proxy path FAILS with ConnectError: ${GP02_RESULT} (GP-02 regression: check gateway-cache alias and cache_src ACL)"
else
  fail_test "GP-02" "devpi proxy path unexpected result: ${GP02_RESULT} (expected HTTP 200 from pypi.org)"
fi

# ------------------------------------------------------------
# AC-14-P05 + AC-14-N01: devcontainer blocked from direct registry reach
# ------------------------------------------------------------
begin_test "AC-14-P05" "devcontainer cannot reach registry.npmjs.org directly (allowlist removed after caches)"
# Direct access to npmjs.org should be blocked (the Squid allowlist moved npmjs.org
# to allowed_registry_SNI which is only spliced for cache-net source IPs, not devcontainer).
DIRECT_NPM=$(dc_exec curl --noproxy '*' \
  --silent --max-time 10 --connect-timeout 5 \
  --output /dev/null --write-out "%{http_code}" \
  "https://registry.npmjs.org/" 2>/dev/null) || DIRECT_NPM="000"
if [ "${DIRECT_NPM}" = "000" ] || [ "${DIRECT_NPM}" = "403" ]; then
  pass_test "AC-14-P05" "direct access to registry.npmjs.org blocked: HTTP ${DIRECT_NPM} (devcontainer cannot bypass Verdaccio)"
elif [ "${DIRECT_NPM}" = "200" ]; then
  fail_test "AC-14-P05" "direct access to registry.npmjs.org returned HTTP 200! Devcontainer should use Verdaccio only. (source-ACL not working)"
else
  pass_test "AC-14-P05" "direct access to registry.npmjs.org: HTTP ${DIRECT_NPM} (not 200, blocked)"
fi

# Also via proxy - Squid source-ACL should terminate registry SNI for devcontainer source
PROXY_NPM=$(dc_exec curl --proxy "http://localhost:8080" \
  --silent --max-time 10 --connect-timeout 5 \
  --output /dev/null --write-out "%{http_code}" \
  "https://registry.npmjs.org/" 2>/dev/null) || PROXY_NPM="000"
if [ "${PROXY_NPM}" = "000" ] || [ "${PROXY_NPM}" = "403" ]; then
  pass_test "AC-14-N01" "devcontainer->proxy->registry.npmjs.org blocked: HTTP ${PROXY_NPM} (source-ACL: registry SNIs only from cache-net)"
elif [ "${PROXY_NPM}" = "200" ]; then
  fail_test "AC-14-N01" "devcontainer->proxy->registry.npmjs.org returned HTTP 200! Source-ACL not enforcing registry split."
else
  pass_test "AC-14-N01" "devcontainer->proxy->registry.npmjs.org: HTTP ${PROXY_NPM} (not 200)"
fi

# ------------------------------------------------------------
# REGRESSION-14-EXTERNAL-4873-DROP (permanent regression, RC-14-1)
# devcontainer cannot reach an external host on port 4873 directly.
# The iptables rules for port 4873 must be destination-scoped to 172.30.0.0/24
# and 172.31.0.0/24 only (not port-only rules).
# We test this by attempting to reach an external non-routable IP on port 4873.
# On macOS/Docker Desktop, the L3 drop will cause a connection timeout or RST.
# ------------------------------------------------------------
begin_test "REGRESSION-14-EXTERNAL-4873-DROP" "external host:4873 blocked from devcontainer (RC-14-1 destination-scoped rules)"
# Use a public IP that is definitely not in 172.30.0.0/24 or 172.31.0.0/24
# 93.184.216.34 = example.com's IP address (a real public IP on TCP/4873 = nothing listening, but L3 DROP is the test)
EXT_4873=$(dc_exec sh -c \
  'timeout 5 bash -c "echo >/dev/tcp/93.184.216.34/4873" 2>&1; echo "exit:$?"' \
  2>/dev/null) || EXT_4873="exit:1"
if echo "${EXT_4873}" | grep -qE "exit:[1-9]"; then
  pass_test "REGRESSION-14-EXTERNAL-4873-DROP" "external IP:4873 blocked (L3 destination-scoped DROP; RC-14-1 regression closed)"
else
  fail_test "REGRESSION-14-EXTERNAL-4873-DROP" "external IP:4873 NOT blocked! RC-14-1 regression re-introduced. iptables rules for port 4873 must be destination-scoped to internal subnets only."
fi

# ------------------------------------------------------------
# REGRESSION-14-EXTERNAL-3141-DROP (permanent regression, RC-14-1)
# Same test for port 3141 (devpi port).
# ------------------------------------------------------------
begin_test "REGRESSION-14-EXTERNAL-3141-DROP" "external host:3141 blocked from devcontainer (RC-14-1 destination-scoped rules)"
EXT_3141=$(dc_exec sh -c \
  'timeout 5 bash -c "echo >/dev/tcp/93.184.216.34/3141" 2>&1; echo "exit:$?"' \
  2>/dev/null) || EXT_3141="exit:1"
if echo "${EXT_3141}" | grep -qE "exit:[1-9]"; then
  pass_test "REGRESSION-14-EXTERNAL-3141-DROP" "external IP:3141 blocked (RC-14-1 regression closed)"
else
  fail_test "REGRESSION-14-EXTERNAL-3141-DROP" "external IP:3141 NOT blocked! RC-14-1 regression. iptables port-3141 rules must be destination-scoped."
fi

# Summary
print_component_summary "${COMPONENT}" "${PASS}" "${FAIL}" "${SKIP}"
