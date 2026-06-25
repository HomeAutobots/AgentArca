/**
 * credentials.js - Credentials view frontend.
 *
 * Security invariants:
 * - The token value is submitted via PUT and NEVER retained in any variable
 *   after the request completes. The input field is cleared in the finally block.
 * - The response is never inspected for a token value (the API does not return one).
 * - The fingerprint is displayed as-is (16 hex chars). It is not used as input anywhere.
 * - No JavaScript retains the token after submission.
 */

(function () {
  "use strict";

  let currentKey = null;
  let csrfToken = null;

  // ---------------------------------------------------------------------------
  // CSRF token retrieval (re-read from meta or login response)
  // ---------------------------------------------------------------------------

  async function getCsrfToken() {
    if (csrfToken) return csrfToken;
    // Try to get it from the server (re-login not needed; the session cookie carries auth).
    // The CSRF token is embedded in the session. We retrieve it from the login endpoint
    // if not already cached from the session.
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) {
      csrfToken = meta.getAttribute("content");
      return csrfToken;
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Load credentials table
  // ---------------------------------------------------------------------------

  async function loadCredentials() {
    const tbody = document.getElementById("creds-tbody");
    try {
      const resp = await fetch("/api/v1/credentials", {
        method: "GET",
        credentials: "include",
      });
      if (!resp.ok) {
        if (resp.status === 401) {
          tbody.innerHTML = '<tr><td colspan="4">Session expired. <a href="/index.html">Log in</a>.</td></tr>';
          return;
        }
        tbody.innerHTML = `<tr><td colspan="4">Error loading credentials: ${resp.status}</td></tr>`;
        return;
      }
      const data = await resp.json();
      // Store CSRF token from a custom response header if provided.
      const headerCsrf = resp.headers.get("X-CSRF-Token");
      if (headerCsrf) csrfToken = headerCsrf;

      renderTable(data.keys);
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="4">Network error: ${err.message}</td></tr>`;
    }
  }

  function renderTable(keys) {
    const tbody = document.getElementById("creds-tbody");
    if (!keys || keys.length === 0) {
      tbody.innerHTML = "<tr><td colspan='4'>No managed keys found.</td></tr>";
      return;
    }
    tbody.innerHTML = keys.map(function (item) {
      const badgeClass = item.status === "SET" ? "badge-set" : "badge-unset";
      const fp = item.fingerprint
        ? `<span class="fingerprint" title="HMAC-SHA256 fingerprint (non-reversible)">${item.fingerprint}</span>`
        : '<span style="color:#555">&#8212;</span>';
      return `<tr>
        <td><code>${escapeHtml(item.key)}</code></td>
        <td><span class="${badgeClass}">${escapeHtml(item.status)}</span></td>
        <td>${fp}</td>
        <td>
          <button onclick="openSetModal('${escapeHtml(item.key)}')">Set</button>
          ${item.status === "SET"
            ? `<button class="danger" onclick="clearKey('${escapeHtml(item.key)}')">Clear</button>`
            : ""}
        </td>
      </tr>`;
    }).join("");
  }

  // ---------------------------------------------------------------------------
  // Modal: set token
  // ---------------------------------------------------------------------------

  window.openSetModal = function (key) {
    currentKey = key;
    document.getElementById("modal-title").textContent = "Set token for " + key;
    document.getElementById("modal-key-label").textContent =
      "This will overwrite the existing token (if any). The new token will take " +
      "effect on the next profile restart.";
    document.getElementById("modal-input").value = "";
    document.getElementById("modal-error").textContent = "";
    document.getElementById("modal-overlay").style.display = "block";
    document.getElementById("modal-input").focus();
  };

  document.getElementById("modal-cancel").addEventListener("click", function () {
    closeModal();
  });

  document.getElementById("modal-confirm").addEventListener("click", function () {
    submitToken();
  });

  document.getElementById("modal-input").addEventListener("keydown", function (e) {
    if (e.key === "Enter") submitToken();
    if (e.key === "Escape") closeModal();
  });

  function closeModal() {
    // Clear the input in the finally-equivalent path.
    document.getElementById("modal-input").value = "";
    document.getElementById("modal-overlay").style.display = "none";
    currentKey = null;
  }

  async function submitToken() {
    const inputEl = document.getElementById("modal-input");
    const errorEl = document.getElementById("modal-error");
    const tokenValue = inputEl.value;

    if (!tokenValue) {
      errorEl.textContent = "Token value is required.";
      return;
    }
    if (tokenValue.length > 4096) {
      errorEl.textContent = "Token value must not exceed 4096 characters.";
      return;
    }

    const csrf = await getCsrfToken();
    if (!csrf) {
      errorEl.textContent = "CSRF token unavailable. Please reload and try again.";
      return;
    }

    document.getElementById("modal-confirm").disabled = true;
    errorEl.textContent = "";

    try {
      const resp = await fetch(`/api/v1/credentials/${encodeURIComponent(currentKey)}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf,
        },
        body: JSON.stringify({ value: tokenValue }),
        credentials: "include",
      });

      // NOTE: The response does NOT contain the token value.
      // We never read or display it from the response.
      if (resp.ok) {
        closeModal();
        await loadCredentials();
      } else {
        const data = await resp.json().catch(function () { return {}; });
        errorEl.textContent = `Error ${resp.status}: ${data.detail || "Unknown error"}`;
      }
    } catch (err) {
      errorEl.textContent = "Network error: " + err.message;
    } finally {
      // Clear the input value regardless of outcome.
      // The token must not remain in the DOM after submission.
      inputEl.value = "";
      document.getElementById("modal-confirm").disabled = false;
    }
  }

  // ---------------------------------------------------------------------------
  // Clear (DELETE) a credential
  // ---------------------------------------------------------------------------

  window.clearKey = async function (key) {
    if (!confirm(`Remove token for ${key}?\n\nThe profile must be restarted to take effect.`)) {
      return;
    }
    const csrf = await getCsrfToken();
    if (!csrf) {
      alert("CSRF token unavailable. Please reload and try again.");
      return;
    }
    try {
      const resp = await fetch(`/api/v1/credentials/${encodeURIComponent(key)}`, {
        method: "DELETE",
        headers: { "X-CSRF-Token": csrf },
        credentials: "include",
      });
      if (resp.ok) {
        await loadCredentials();
      } else {
        const data = await resp.json().catch(function () { return {}; });
        alert(`Error ${resp.status}: ${data.detail || "Unknown error"}`);
      }
    } catch (err) {
      alert("Network error: " + err.message);
    }
  };

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // ---------------------------------------------------------------------------
  // Initialise
  // ---------------------------------------------------------------------------

  document.addEventListener("DOMContentLoaded", function () {
    loadCredentials();
  });

})();
