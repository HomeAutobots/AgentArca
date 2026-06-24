/**
 * allowlist.js - UI logic for the egress allowlist management view.
 *
 * Calls the API, renders entries, confirms add (single-operator review step,
 * ADR-010 D6, SPEC-27-P1 section 13).
 *
 * All state-changing requests include X-CSRF-Token from the session.
 */

"use strict";

let _csrfToken = "";
let _pendingHost = "";

// Fetch the CSRF token from the health endpoint on load.
async function fetchCsrfToken() {
  try {
    const resp = await fetch("/api/v1/health", { credentials: "include" });
    if (resp.ok) {
      const data = await resp.json();
      if (data.csrf_token) {
        _csrfToken = data.csrf_token;
      }
    }
  } catch (e) {
    console.error("Could not fetch CSRF token:", e);
  }
}

function showMsg(elementId, text, type) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.className = "msg " + (type || "");
  el.textContent = text;
}

function clearMsg(elementId) {
  const el = document.getElementById(elementId);
  if (el) { el.textContent = ""; el.className = ""; }
}

// Load and render the current allowlist.
async function loadAllowlist() {
  clearMsg("list-msg");
  try {
    const resp = await fetch("/api/v1/allowlist", { credentials: "include" });
    if (resp.status === 401) {
      showMsg("list-msg", "Not authenticated. Please log in.", "err");
      return;
    }
    if (!resp.ok) {
      showMsg("list-msg", "Failed to load allowlist: " + resp.status, "err");
      return;
    }
    const data = await resp.json();

    const gwEl = document.getElementById("gateway-status");
    if (gwEl) {
      gwEl.textContent = data.active_gateway
        ? "Active gateway: " + data.active_gateway
        : "No active gateway running (changes will apply on next compose up).";
    }

    const tbody = document.getElementById("allowlist-body");
    if (!tbody) return;
    tbody.innerHTML = "";

    const allEntries = (data.base_entries || []).concat(data.overlay_entries || []);
    if (allEntries.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = '<td colspan="4" style="color:#888">No entries.</td>';
      tbody.appendChild(tr);
      return;
    }

    for (const entry of allEntries) {
      const tr = document.createElement("tr");
      const sourceClass = entry.source === "base" ? "badge-base" : "badge-overlay";
      const lockedText = entry.locked ? '<span class="badge-locked">(locked)</span>' : "";
      const actionCell = entry.source === "overlay"
        ? '<button class="danger remove-btn" data-host="' + escapeAttr(entry.host) + '">Remove</button>'
        : '<span style="color:#666">-</span>';
      tr.innerHTML =
        '<td>' + escapeHtml(entry.host) + '</td>' +
        '<td><span class="' + sourceClass + '">' + escapeHtml(entry.source) + '</span></td>' +
        '<td>' + lockedText + (entry.locked ? "yes" : "no") + '</td>' +
        '<td>' + actionCell + '</td>';
      tbody.appendChild(tr);
    }

    // Attach remove handlers.
    tbody.querySelectorAll(".remove-btn").forEach(function(btn) {
      btn.addEventListener("click", function() {
        removeHost(btn.dataset.host);
      });
    });

  } catch (e) {
    showMsg("list-msg", "Error loading allowlist: " + e.message, "err");
  }
}

// Show the confirmation modal before submitting add.
function showConfirmModal(host) {
  _pendingHost = host;
  const hostEl = document.getElementById("modal-host");
  if (hostEl) hostEl.textContent = host;
  const overlay = document.getElementById("modal-overlay");
  if (overlay) overlay.classList.add("visible");
}

function hideConfirmModal() {
  _pendingHost = "";
  const overlay = document.getElementById("modal-overlay");
  if (overlay) overlay.classList.remove("visible");
}

// Submit the add after confirmation.
async function confirmAdd() {
  const host = _pendingHost;
  hideConfirmModal();
  if (!host) return;

  const btn = document.getElementById("add-btn");
  if (btn) btn.disabled = true;
  clearMsg("add-msg");

  try {
    const resp = await fetch("/api/v1/allowlist/entries", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": _csrfToken,
      },
      body: JSON.stringify({ host: host }),
    });

    let data;
    try { data = await resp.json(); } catch (_) { data = {}; }

    if (resp.status === 201) {
      showMsg("add-msg", "Added: " + host + (data.risk_notice ? " | " + data.risk_notice : ""), "ok");
      document.getElementById("new-host").value = "";
      loadAllowlist();
    } else if (resp.status === 200 && data.idempotent) {
      showMsg("add-msg", host + " was already present (no change).", "warn");
    } else if (resp.status === 400) {
      showMsg("add-msg", "Invalid host: " + (data.detail || "validation failed"), "err");
    } else if (resp.status === 422) {
      const d = (data.detail || {});
      showMsg("add-msg", "Parse gate failed: " + (d.detail || JSON.stringify(d)), "err");
    } else if (resp.status === 401) {
      showMsg("add-msg", "Not authenticated.", "err");
    } else if (resp.status === 403) {
      showMsg("add-msg", "Forbidden (CSRF or Host header mismatch).", "err");
    } else {
      showMsg("add-msg", "Error: " + resp.status, "err");
    }
  } catch (e) {
    showMsg("add-msg", "Request failed: " + e.message, "err");
  } finally {
    if (btn) btn.disabled = false;
  }
}

// Remove a host.
async function removeHost(host) {
  clearMsg("list-msg");
  try {
    const resp = await fetch("/api/v1/allowlist/entries/" + encodeURIComponent(host), {
      method: "DELETE",
      credentials: "include",
      headers: { "X-CSRF-Token": _csrfToken },
    });

    let data;
    try { data = await resp.json(); } catch (_) { data = {}; }

    if (resp.ok) {
      showMsg("list-msg", "Removed: " + host + (data.idempotent ? " (was not present)" : ""), "ok");
      loadAllowlist();
    } else if (resp.status === 400) {
      showMsg("list-msg", "Invalid host: " + (data.detail || ""), "err");
    } else if (resp.status === 401) {
      showMsg("list-msg", "Not authenticated.", "err");
    } else if (resp.status === 403) {
      showMsg("list-msg", "Forbidden.", "err");
    } else {
      showMsg("list-msg", "Error removing " + host + ": " + resp.status, "err");
    }
  } catch (e) {
    showMsg("list-msg", "Request failed: " + e.message, "err");
  }
}

// Reload gateway.
async function reloadGateway() {
  const btn = document.getElementById("reload-btn");
  if (btn) btn.disabled = true;
  clearMsg("reload-msg");

  try {
    const resp = await fetch("/api/v1/allowlist/reload", {
      method: "POST",
      credentials: "include",
      headers: { "X-CSRF-Token": _csrfToken },
    });

    let data;
    try { data = await resp.json(); } catch (_) { data = {}; }

    if (resp.ok) {
      showMsg("reload-msg", "Reload ok" + (data.gateway ? " (gateway: " + data.gateway + ")" : "") + ". " + (data.detail || ""), "ok");
    } else if (resp.status === 422) {
      const d = (data.detail || {});
      showMsg("reload-msg", "Parse gate failed: " + (d.detail || JSON.stringify(d)), "err");
    } else if (resp.status === 401) {
      showMsg("reload-msg", "Not authenticated.", "err");
    } else if (resp.status === 403) {
      showMsg("reload-msg", "Forbidden.", "err");
    } else {
      showMsg("reload-msg", "Error: " + resp.status, "err");
    }
  } catch (e) {
    showMsg("reload-msg", "Request failed: " + e.message, "err");
  } finally {
    if (btn) btn.disabled = false;
  }
}

function escapeHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function escapeAttr(s) {
  return String(s).replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

// Wire up events on DOMContentLoaded.
document.addEventListener("DOMContentLoaded", function() {
  fetchCsrfToken().then(loadAllowlist);

  const addBtn = document.getElementById("add-btn");
  if (addBtn) {
    addBtn.addEventListener("click", function() {
      const host = (document.getElementById("new-host") || {}).value || "";
      if (!host.trim()) {
        showMsg("add-msg", "Please enter a hostname.", "warn");
        return;
      }
      showConfirmModal(host.trim());
    });
  }

  const newHostInput = document.getElementById("new-host");
  if (newHostInput) {
    newHostInput.addEventListener("keydown", function(e) {
      if (e.key === "Enter") {
        const host = newHostInput.value.trim();
        if (host) showConfirmModal(host);
      }
    });
  }

  const confirmBtn = document.getElementById("modal-confirm");
  if (confirmBtn) confirmBtn.addEventListener("click", confirmAdd);

  const cancelBtn = document.getElementById("modal-cancel");
  if (cancelBtn) cancelBtn.addEventListener("click", hideConfirmModal);

  const refreshBtn = document.getElementById("refresh-btn");
  if (refreshBtn) refreshBtn.addEventListener("click", loadAllowlist);

  const reloadBtn = document.getElementById("reload-btn");
  if (reloadBtn) reloadBtn.addEventListener("click", reloadGateway);

  // Close modal on Escape.
  document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") hideConfirmModal();
  });
});
