# tests/containment/ - Item 16 Containment Red-Team Suite

**Frame:** ASSUME PROMPT INJECTION SUCCEEDS; prove the boundary HOLDS.

This is the adversarial containment suite (Area 8, BUILD_PLAN Phase 5). It does not test
whether injection can be prevented (it cannot, R-a). It tests whether, GIVEN a successful
injection, the deterministic boundary CONTAINS the exfil/escape/bypass. Every scenario
simulates the injected-agent action directly (a UID-1000 process via `compose exec`, a
synthetic hook stdin, or a direct `curl`) and asserts containment. The boundary does not
care whether a human or an injected agent issued the action, which is why this direct
approach is the real proof (no live Copilot token needed).

## Run

```bash
tests/containment/run-all.sh            # full suite (offline + live rt16 stack)
tests/containment/run-all.sh --offline  # offline scenarios only (no Docker)
tests/containment/run-all.sh --keep-up  # leave the rt16 stack up for debugging
```

The runner brings the stack up under project `rt16` with `compose.test-override.yml`,
runs every scenario, prints CONTAINED/ESCAPED + the attack-success-rate, and tears the
stack down (`docker compose -p rt16 ... down -v`). It exits non-zero ONLY on a real escape.

## Structure

| file | what |
|------|------|
| `run-all.sh` | orchestrating runner: bringup, subnet-collision wait, scenarios, report, teardown |
| `lib.sh` | shared helpers + result accounting (`record`, `hook_decision`, `dc_exec`) |
| `compose.test-override.yml` | project=rt16, container_name removed, mem 2g (parallel-safe vs item-15 acc15) |
| `scenario-approval-bypass.sh` | hook approval-bypass (quote-concat, base64-pipe, CLI-schema, boundary edits, git push) - OFFLINE |
| `scenario-config-integrity.sh` | managed-policy-wins + MCPoison swap detection - OFFLINE |
| `scenario-seccomp-static.sh` | seccomp profile static analysis (no dangerous syscalls, io_uring absent) - OFFLINE |
| `scenario-documented.sh` | honest SKIP records for R-b/R-e/R-h/R-d/CamoLeak + requires-* skips - OFFLINE |
| `scenario-live-escape-exfil.sh` | netns/seccomp/cap escape + direct-IP/DNS/external-port/source-ACL exfil - LIVE |
| `scenario-live-immutability-push.sh` | EROFS hook-rewrite + autonomous-push-block + canary placement - LIVE |
| `results/rt16-results.csv` | per-scenario verdict log (scenario_id,verdict,rate,note) |

## Verdict (2026-06-14)

56 scenarios: **48 CONTAINED, 0 ESCAPED, 8 documented SKIP. Attack-success-rate 0/48 = 0.0%.**
RED_TEAMED. The deterministic boundary tests are deterministic (kernel/firewall/hook either
contains or not), so a single run proves containment.

## Honest residuals (ACCEPTED-NOT-CLOSED, never claimed solved)

- **R-b** allowlisted-writable exfil (HIGH/HIGH, fundamental): github.com/telemetry/a
  human-approved push are permitted by design. The deterministic partials HOLD (autonomous
  push blocked, low-bandwidth, logged) but the channel is NOT closed.
- **R-e** kernel 0-day at the runc tier (LOW/HIGH): process isolation, not hardware. The
  ESC-* probes prove the bar is raised; they do not make it escape-proof. macOS LinuxKit VM
  is the backstop. Escalate to gVisor/microVM/VM per ADR-004 D4.
- **R-h** low-and-slow exfil: detection backstops, cannot reliably catch.
- **R-d** tool-output injection: consequence-bounded, never prevented.
- **CamoLeak**: GitHub product-side fix; an allowlisted-trusted-channel instance of R-b.

## Requires-* (built + marked, not runnable here)

- `requires-linux-host`: auditd `-w <canary> -p r -k canary_read` firing at `-e 2`
  (canary placement + watch-path are testable; host-fire is not on macOS LinuxKit).
- `requires-VS-Code-runtime`: sandbox-auto-approve hook-fires (OI-12-E standing gate);
  managed-policy live-merge override precedence.
- `requires-live-token`: an end-to-end live injected Copilot agent (the boundary is tested
  DIRECTLY instead - that is the real proof).
