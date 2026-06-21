# macOS pf vs iptables Finding

**OI-08-B | Verified: 2026-06-14 | Environment: Docker Desktop 25.0.2 on macOS 22.6.0 (Darwin)**

## Summary

The gateway sidecar uses Linux iptables (nf_tables backend) inside Docker Desktop's LinuxKit VM. On macOS, Docker Desktop runs a lightweight Linux VM (LinuxKit), so all container networking uses Linux iptables, not macOS pf. The developer's host-level firewall (macOS pf) is irrelevant to the container egress controls.

## iptables Backend: nf_tables + iptables-legacy Coexistence

Two iptables subsystems are present inside the gateway container:

1. **iptables-nft (our rules):** Uses the nf_tables kernel subsystem. This is the default `iptables` command on Ubuntu 22.04. Our `init-firewall.sh` programs rules here. OUTPUT policy is DROP. All deny-by-default egress controls live here.

2. **iptables-legacy (Docker rules):** Uses the xt_tables/netfilter kernel subsystem. Docker's embedded DNS uses `iptables-legacy` to install DNAT rules (DOCKER_OUTPUT chain) for redirecting port-53 traffic to the embedded resolver. This chain is in the `nat` table.

These two subsystems are separate and do not interfere with each other's filter rules. Our nf_tables OUTPUT DROP does not affect Docker's iptables-legacy nat rules and vice versa.

**Verified rule state at test time (2026-06-14):**

```
iptables (nf_tables) OUTPUT chain:
num   pkts bytes target  prot  destination
1     4529   43M ACCEPT  all   loopback
2       64  3834 ACCEPT  udp   192.168.65.7 dpt:53
3        0     0 ACCEPT  tcp   192.168.65.7 dpt:53
4        0     0 ACCEPT  all   127.0.0.11
5       21  1680 DROP    udp   any dpt:53
6        0     0 DROP    tcp   any dpt:53
7     4662  266K ACCEPT  all   ctstate RELATED,ESTABLISHED
8       27  1620 ACCEPT  tcp   dpt:443 owner UID=13 (proxy)
9        0     0 ACCEPT  tcp   dpt:80  owner UID=13 (proxy)
10       6   380 DROP    icmp  any
Policy: DROP (110 packets blocked)

ip6tables OUTPUT: Policy DROP (IPv6 backstop active)
```

## Docker Desktop Embedded DNS: Conntrack DNAT/SNAT Failure

Docker's embedded DNS at 127.0.0.11 relies on conntrack-based DNAT/SNAT:
- `iptables-legacy nat DOCKER_OUTPUT`: DNAT redirects 127.0.0.11:53 to 127.0.0.11:<random-high-port>
- `iptables-legacy nat DOCKER_POSTROUTING`: SNAT rewrites replies back to source port 53

**Failure observed:** DOCKER_OUTPUT showed 23 UDP DNAT packets processed, but DOCKER_POSTROUTING SNAT showed 0 packets. The `/proc/net/nf_conntrack` file was empty. Conntrack is not tracking connections in this Docker Desktop LinuxKit environment for custom bridge networks. Without conntrack tracking, the SNAT rule never fires, DNS replies have the wrong source port, and the client drops them.

**Result:** DNS queries to 127.0.0.11 return SERVFAIL in 1ms (no network trip, immediate drop).

**Resolution:** Use 192.168.65.7 (Docker Desktop's LinuxKit VM host resolver). This is an internal address not accessible from the public internet. Set via `dns: [192.168.65.7]` in docker-compose.yml and `dns_nameservers 192.168.65.7` in squid.conf.

**Native Linux note (RC-1, host-conditional):** On a native Linux Docker host (not Docker Desktop), the embedded DNS at 127.0.0.11 functions correctly because conntrack works. Replace 192.168.65.7 with 127.0.0.11 in docker-compose.yml, init-firewall.sh, and squid.conf when deploying to a native Linux host. The 192.168.65.7 address is specific to Docker Desktop's LinuxKit VM and does not exist on native Linux Docker hosts.

## DNS Tunneling Residual: AC-08-N03 Does NOT Close DNS Tunneling (RC-1 annotation)

**Important:** AC-08-N03 proves that arbitrary external DNS resolvers (e.g. 8.8.8.8) are unreachable from the devcontainer. This closes the "direct query to attacker-controlled nameserver" vector.

AC-08-N03 does NOT close subdomain-encoded DNS tunneling through the single permitted recursive resolver (192.168.65.7 on Docker Desktop, or 127.0.0.11 on native Linux). Both resolvers are recursive forwarders that will forward queries like `<encoded-data>.attacker.example` upstream to the attacker's authoritative nameserver if the attacker controls that domain's NS records.

This residual is unchanged from ADR-002 D5's baseline: the ADR pinned DNS to a single resolver (127.0.0.11) with the same recursive-forward property. Switching from 127.0.0.11 to 192.168.65.7 changes which recursive resolver is used, but both have the same fundamental property. The DNS-tunneling-through-permitted-recursive-resolver class is named in residual-risk-register.md as part of R-b.

Do not read AC-08-N03 as proving DNS tunneling is closed. It proves arbitrary-resolver access is closed, which is a different (narrower) property.

## iptables Processing Order: DNAT Before Filter

Docker's DNAT runs in the `nat OUTPUT` chain, which processes packets BEFORE the `filter OUTPUT` chain. By the time our filter OUTPUT rules see a DNS packet destined for 127.0.0.11, Docker has already rewritten the destination port from 53 to a high port (e.g., 36017). A rule matching `dport 53 -d 127.0.0.11` therefore never fires.

**Resolution:** Allow all traffic to 127.0.0.11 with `iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT` (no port match). This is safe because 127.0.0.11 is an internal loopback address used only by Docker's embedded DNS.

## Owner-Match for TCP/443 and TCP/80

To prevent devcontainer processes from bypassing the proxy via direct TCP/443 connections (since devcontainer shares the gateway netns), the TCP/443 and TCP/80 ACCEPT rules use the iptables owner match module:

```
-p tcp --dport 443 -m owner --uid-owner proxy -j ACCEPT
-p tcp --dport 80  -m owner --uid-owner proxy -j ACCEPT
```

Squid workers run as uid `proxy` (uid 13 in Ubuntu 22.04). Only these processes can make outbound TCP/443 and TCP/80 connections. Root (uid 0) and devcontainer processes (uid 1000) get DROP from the OUTPUT default policy.

**Verified at test time:** `curl --noproxy '*' https://example.com` from the gateway container as root returns HTTP 000 (connection timed out), confirming the owner match blocks non-proxy processes.

## macOS pf: Not Relevant

macOS pf operates at the macOS host network layer, outside Docker Desktop's LinuxKit VM. It does not intercept or inspect traffic between containers or between the LinuxKit VM and the outside world at the iptables layer. Container egress is entirely controlled by the Linux iptables rules inside the LinuxKit VM.

If host-level macOS egress controls are desired, macOS pf rules targeting the Docker Desktop VM's IP range (typically 192.168.65.0/24) could be added as a defense-in-depth layer at the host. This is outside the scope of the gateway sidecar design (ADR-002) and would not replace the container-level controls.
