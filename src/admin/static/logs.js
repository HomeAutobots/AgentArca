/**
 * logs.js - UI logic for the logs/observability view.
 *
 * Polls read-only endpoints and renders audit, egress, and health data.
 * No state-changing requests are made from this file.
 */

"use strict";

let _auditOffset = 0;
const _auditLimit = 100;

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function showMsg(id, text, type) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = "msg " + (type || "");
  el.textContent = text;
}

function clearMsg(id) {
  const el = document.getElementById(id);
  if (el) { el.textContent = ""; el.className = ""; }
}

// Tab switching.
function initTabs() {
  const btns = document.querySelectorAll(".tab-btn");
  btns.forEach(function(btn) {
    btn.addEventListener("click", function() {
      btns.forEach(function(b) { b.classList.remove("active"); });
      btn.classList.add("active");
      document.querySelectorAll(".tab-panel").forEach(function(p) { p.classList.remove("active"); });
      const target = document.getElementById("tab-" + btn.dataset.tab);
      if (target) target.classList.add("active");
    });
  });
}

// Audit log.
async function loadAudit(offset) {
  offset = offset || 0;
  _auditOffset = offset;
  clearMsg("audit-msg");
  try {
    const url = "/api/v1/logs/audit?limit=" + _auditLimit + "&offset=" + offset;
    const resp = await fetch(url, { credentials: "include" });
    if (resp.status === 401) { showMsg("audit-msg", "Not authenticated.", "err"); return; }
    if (!resp.ok) { showMsg("audit-msg", "Error: " + resp.status, "err"); return; }
    const data = await resp.json();

    const totalEl = document.getElementById("audit-total");
    if (totalEl) totalEl.textContent = "Total records: " + (data.total_lines || 0);

    const tbody = document.getElementById("audit-body");
    if (!tbody) return;
    tbody.innerHTML = "";

    const entries = data.entries || [];
    if (entries.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="color:#888">No records.</td></tr>';
    } else {
      for (const e of entries) {
        if (e._parse_error) {
          const tr = document.createElement("tr");
          tr.innerHTML = '<td colspan="6" style="color:#888"><em>Malformed line: ' + escapeHtml(e._raw) + '</em></td>';
          tbody.appendChild(tr);
          continue;
        }
        const outcomeClass = (e.outcome === "applied") ? "status-ok"
          : (e.outcome && e.outcome.startsWith("rejected")) ? "status-warn"
          : (e.outcome === "error") ? "status-err" : "";
        const tr = document.createElement("tr");
        tr.innerHTML =
          '<td><code>' + escapeHtml(e.timestamp_utc || "") + '</code></td>' +
          '<td><code>' + escapeHtml((e.session_id || "").substring(0, 8)) + '</code></td>' +
          '<td>' + escapeHtml(e.action || "") + '</td>' +
          '<td>' + escapeHtml(e.target || "") + '</td>' +
          '<td class="' + outcomeClass + '">' + escapeHtml(e.outcome || "") + '</td>' +
          '<td>' + escapeHtml(e.detail || "") + '</td>';
        tbody.appendChild(tr);
      }
    }

    renderAuditPagination(data.total_lines || 0);
  } catch (e) {
    showMsg("audit-msg", "Error: " + e.message, "err");
  }
}

function renderAuditPagination(total) {
  const pag = document.getElementById("audit-pagination");
  if (!pag) return;
  pag.innerHTML = "";
  const showing = _auditOffset + _auditLimit;
  const info = document.createElement("span");
  info.textContent = "Showing " + (_auditOffset + 1) + "-" + Math.min(showing, total) + " of " + total;
  pag.appendChild(info);

  if (_auditOffset > 0) {
    const prev = document.createElement("button");
    prev.textContent = "Prev";
    prev.addEventListener("click", function() { loadAudit(Math.max(0, _auditOffset - _auditLimit)); });
    pag.appendChild(prev);
  }
  if (showing < total) {
    const next = document.createElement("button");
    next.textContent = "Next";
    next.addEventListener("click", function() { loadAudit(_auditOffset + _auditLimit); });
    pag.appendChild(next);
  }
}

// Egress log.
async function loadEgress() {
  clearMsg("egress-msg");
  try {
    const resp = await fetch("/api/v1/logs/egress?limit=50", { credentials: "include" });
    if (resp.status === 401) { showMsg("egress-msg", "Not authenticated.", "err"); return; }
    if (!resp.ok) { showMsg("egress-msg", "Error: " + resp.status, "err"); return; }
    const data = await resp.json();

    const statusEl = document.getElementById("egress-status");
    if (statusEl) {
      statusEl.textContent = "Status: " + (data.status || "?") +
        (data.gateway ? " | Gateway: " + data.gateway : "");
    }

    if (data.status !== "ok") {
      showMsg("egress-msg", "Egress log unavailable: " + data.status +
        ". This is best-effort (requires a running gateway with access.log).", "warn");
    }

    const tbody = document.getElementById("egress-body");
    if (!tbody) return;
    tbody.innerHTML = "";

    const entries = data.entries || [];
    if (entries.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="color:#888">No entries. ' +
        (data.status !== "ok" ? "(" + (data.status || "") + ")" : "") + '</td></tr>';
      return;
    }

    for (const e of entries) {
      const ts = e.timestamp_epoch
        ? new Date(e.timestamp_epoch * 1000).toISOString()
        : "";
      const tr = document.createElement("tr");
      tr.innerHTML =
        '<td><code>' + escapeHtml(ts) + '</code></td>' +
        '<td>' + escapeHtml(e.client_ip || "") + '</td>' +
        '<td>' + escapeHtml(e.result_code || "") + '</td>' +
        '<td>' + escapeHtml(e.method || "") + '</td>' +
        '<td>' + escapeHtml(e.url || "") + '</td>' +
        '<td>' + escapeHtml(e.bytes || "0") + '</td>';
      tbody.appendChild(tr);
    }
  } catch (e) {
    showMsg("egress-msg", "Error: " + e.message, "err");
  }
}

// Health.
async function loadHealth() {
  clearMsg("health-msg");
  try {
    const resp = await fetch("/api/v1/logs/health", { credentials: "include" });
    if (resp.status === 401) { showMsg("health-msg", "Not authenticated.", "err"); return; }
    if (!resp.ok) { showMsg("health-msg", "Error: " + resp.status, "err"); return; }
    const data = await resp.json();

    const profileEl = document.getElementById("health-profile");
    if (profileEl) {
      profileEl.textContent = data.active_profile
        ? "Active profile: " + data.active_profile
        : "No active profile (no gateway running)";
    }

    const tbody = document.getElementById("health-body");
    if (!tbody) return;
    tbody.innerHTML = "";

    const services = data.services || [];
    if (services.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="color:#888">No services running' +
        (data.status ? " (" + data.status + ")" : "") + '.</td></tr>';
      return;
    }

    for (const svc of services) {
      const statusClass = svc.status === "running" ? "svc-running" : "";
      const healthClass = svc.health === "healthy" ? "svc-healthy"
        : svc.health === "unhealthy" ? "svc-unhealthy" : "";
      const ports = Array.isArray(svc.ports) ? svc.ports.join(", ") : String(svc.ports || "");
      const tr = document.createElement("tr");
      tr.innerHTML =
        '<td>' + escapeHtml(svc.name || "") + '</td>' +
        '<td class="' + statusClass + '">' + escapeHtml(svc.status || "") + '</td>' +
        '<td class="' + healthClass + '">' + escapeHtml(svc.health || "-") + '</td>' +
        '<td>' + escapeHtml(ports) + '</td>';
      tbody.appendChild(tr);
    }
  } catch (e) {
    showMsg("health-msg", "Error: " + e.message, "err");
  }
}

document.addEventListener("DOMContentLoaded", function() {
  initTabs();

  loadAudit(0);

  const auditRefresh = document.getElementById("audit-refresh");
  if (auditRefresh) auditRefresh.addEventListener("click", function() { loadAudit(_auditOffset); });

  const egressRefresh = document.getElementById("egress-refresh");
  if (egressRefresh) egressRefresh.addEventListener("click", loadEgress);

  const healthRefresh = document.getElementById("health-refresh");
  if (healthRefresh) healthRefresh.addEventListener("click", loadHealth);

  // Load all tabs in the background on page load.
  loadEgress();
  loadHealth();
});
