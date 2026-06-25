/**
 * isolation.js - Isolation posture view frontend.
 *
 * Calls GET /api/v1/isolation and renders a read-only posture display.
 * No edit affordances. No form inputs. No submit buttons.
 * D5.4 violations (if any) are shown as a red alert banner.
 */

(function () {
  "use strict";

  async function loadIsolation() {
    const container = document.getElementById("posture-container");
    try {
      const resp = await fetch("/api/v1/isolation", {
        method: "GET",
        credentials: "include",
      });
      if (!resp.ok) {
        if (resp.status === 401) {
          container.innerHTML = 'Session expired. <a href="/index.html" style="color:#4fc3f7;">Log in</a>.';
          return;
        }
        container.innerHTML = `Error loading isolation posture: ${resp.status}`;
        return;
      }
      const data = await resp.json();
      renderPosture(data);
    } catch (err) {
      container.innerHTML = "Network error: " + escapeHtml(err.message);
    }
  }

  function renderPosture(data) {
    const container = document.getElementById("posture-container");
    const violationsBanner = document.getElementById("violations-banner");

    // Show violations banner if any D5.4 violations are found in current config.
    if (data.d5_4_violations && data.d5_4_violations.length > 0) {
      violationsBanner.className = "alert-banner";
      violationsBanner.style.display = "block";
      violationsBanner.innerHTML =
        "<strong>WARNING: The current configuration has D5.4 violations.</strong><ul>" +
        data.d5_4_violations.map(function (v) {
          return "<li>" + escapeHtml(v) + "</li>";
        }).join("") +
        "</ul>";
    }

    const posture = data.posture || {};
    const profile = data.profile || "unknown";

    container.innerHTML = `
      <h3>Profile: <code>${escapeHtml(profile)}</code></h3>
      <table>
        <thead><tr><th>Property</th><th>Value</th></tr></thead>
        <tbody>
          <tr>
            <td>cap_drop</td>
            <td><code>${escapeHtml(JSON.stringify(posture.cap_drop))}</code></td>
          </tr>
          <tr>
            <td>cap_add (devcontainer)</td>
            <td><code>${escapeHtml(JSON.stringify(posture.cap_add))}</code></td>
          </tr>
          <tr>
            <td>no_new_privileges</td>
            <td class="${posture.no_new_privileges ? 'value-true' : 'value-false'}">
              ${posture.no_new_privileges ? 'true' : 'false'}
            </td>
          </tr>
          <tr>
            <td>seccomp_profile</td>
            <td><code>${escapeHtml(posture.seccomp_profile || "(none)")}</code></td>
          </tr>
          <tr>
            <td>read_only_rootfs</td>
            <td class="${posture.read_only_rootfs ? 'value-true' : 'value-false'}">
              ${posture.read_only_rootfs ? 'true' : 'false'}
            </td>
          </tr>
          <tr>
            <td>pids_limit</td>
            <td><code>${escapeHtml(String(posture.pids_limit))}</code></td>
          </tr>
          <tr>
            <td>mem_limit</td>
            <td><code>${escapeHtml(posture.mem_limit || "(not set)")}</code></td>
          </tr>
          <tr>
            <td>cpus</td>
            <td><code>${escapeHtml(posture.cpus || "(not set)")}</code></td>
          </tr>
          <tr>
            <td>network_mode</td>
            <td><code>${escapeHtml(posture.network_mode || "(not set)")}</code></td>
          </tr>
          <tr>
            <td>docker_sock_mounted</td>
            <td class="${posture.docker_sock_mounted ? 'value-false' : 'value-true'}">
              ${posture.docker_sock_mounted
                ? '<strong>YES - D5.4 VIOLATION</strong>'
                : 'false (correct)'}
            </td>
          </tr>
          <tr>
            <td>privileged</td>
            <td class="${posture.privileged ? 'value-false' : 'value-true'}">
              ${posture.privileged
                ? '<strong>YES - D5.4 VIOLATION</strong>'
                : 'false (correct)'}
            </td>
          </tr>
          <tr>
            <td>
              gateway_cap_add
              <div class="gateway-note">Gateway only: these capabilities are on the
              gateway sidecar, NOT the devcontainer.</div>
            </td>
            <td><code>${escapeHtml(JSON.stringify(posture.gateway_cap_add))}</code></td>
          </tr>
        </tbody>
      </table>
      <p style="color:#78909c; font-size:0.85em; margin-top:1rem;">
        ${escapeHtml(data.edit_note || "")}
      </p>
    `;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  document.addEventListener("DOMContentLoaded", function () {
    loadIsolation();
  });

})();
