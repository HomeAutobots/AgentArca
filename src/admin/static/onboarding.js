/**
 * onboarding.js - Per-agent onboarding wizard logic.
 *
 * Security invariants:
 * - The portal NEVER calls any external URL.
 * - The portal does NOT run any CLI command itself.
 * - Token values are submitted via PUT /api/v1/credentials/{key} and immediately
 *   cleared from input fields. They are NEVER retained in any variable after the PUT.
 * - No token value appears in any response field (the credentials API does not return one).
 * - This file NEVER writes to any squid allowlist file or reads ~/.codex (B8).
 * - Polling uses GET /api/v1/onboarding/{profile}/status every 3 seconds.
 */

'use strict';

// CSRF token in memory (not localStorage).
let _csrfToken = '';

// Per-profile polling interval handles.
const _pollingIntervals = {};

// Read CSRF token from sessionStorage if the login page stored it there.
(function init() {
  const stored = sessionStorage.getItem('csrf_token');
  if (stored) _csrfToken = stored;
})();

// ---------------------------------------------------------------------------
// CSRF token retrieval
// ---------------------------------------------------------------------------

async function ensureCsrfToken() {
  if (_csrfToken) return _csrfToken;
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) {
    _csrfToken = meta.getAttribute('content') || '';
  }
  return _csrfToken;
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------

function showTab(profile) {
  ['copilot', 'claude', 'codex'].forEach(function(p) {
    document.getElementById('tab-' + p).classList.remove('active');
  });
  document.querySelectorAll('.tab-btn').forEach(function(btn, i) {
    btn.classList.remove('active');
  });
  document.getElementById('tab-' + profile).classList.add('active');
  // Activate matching tab button.
  document.querySelectorAll('.tab-btn').forEach(function(btn) {
    if (btn.textContent.trim().toLowerCase() === profile) {
      btn.classList.add('active');
    }
  });
  // Ensure polling is running for the selected profile.
  startPolling(profile);
}

// ---------------------------------------------------------------------------
// Status polling (GET /api/v1/onboarding/{profile}/status every 3s)
// ---------------------------------------------------------------------------

function startPolling(profile) {
  if (_pollingIntervals[profile]) return;
  _pollingIntervals[profile] = setInterval(function() {
    fetchStatus(profile);
  }, 3000);
  // Immediate first check.
  fetchStatus(profile);
}

async function fetchStatus(profile) {
  try {
    const resp = await fetch('/api/v1/onboarding/' + profile + '/status', {
      credentials: 'include',
    });
    if (resp.status === 401) {
      setStatusBadge(profile, 'Session expired. Log in again.', 'badge-not-ready');
      return;
    }
    if (!resp.ok) {
      setStatusBadge(profile, 'Status check failed (HTTP ' + resp.status + ').', 'badge-not-ready');
      return;
    }
    const data = await resp.json();
    if (data.ready_to_start) {
      setStatusBadge(profile, 'Ready: credential present for ' + data.required_key, 'badge-ready');
      enableStartButton(profile, true);
    } else {
      setStatusBadge(profile, 'Not ready: ' + data.required_key + ' not set.', 'badge-not-ready');
      enableStartButton(profile, false);
    }
  } catch (e) {
    setStatusBadge(profile, 'Network error: ' + e.message, 'badge-not-ready');
  }
}

function setStatusBadge(profile, text, cls) {
  const badge = document.getElementById(profile + '-status-badge');
  if (!badge) return;
  badge.className = 'status-badge ' + cls;
  badge.textContent = text;
}

function enableStartButton(profile, enabled) {
  const btn = document.getElementById(profile + '-start-btn');
  if (!btn) return;
  btn.disabled = !enabled;
}

// ---------------------------------------------------------------------------
// Submit token (PUT /api/v1/credentials/{key})
// ---------------------------------------------------------------------------

async function submitToken(profile, key, inputId, errorId) {
  const inputEl = document.getElementById(inputId);
  const errorEl = document.getElementById(errorId);
  const tokenValue = inputEl.value;

  errorEl.textContent = '';

  if (!tokenValue) {
    errorEl.textContent = 'Token value is required.';
    return;
  }
  if (tokenValue.length > 4096) {
    errorEl.textContent = 'Token value must not exceed 4096 characters.';
    return;
  }

  const csrf = await ensureCsrfToken();
  if (!csrf) {
    errorEl.textContent = 'CSRF token unavailable. Please reload and log in again.';
    return;
  }

  const submitBtn = document.getElementById(profile + '-submit');
  if (submitBtn) submitBtn.disabled = true;

  try {
    const resp = await fetch('/api/v1/credentials/' + encodeURIComponent(key), {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
      },
      body: JSON.stringify({ value: tokenValue }),
      credentials: 'include',
    });

    // The response does NOT contain the token value. We never read or log it.
    if (resp.ok) {
      errorEl.className = 'success';
      errorEl.textContent = 'Token saved. Checking status...';
      // Immediately re-check status.
      await fetchStatus(profile);
    } else {
      const data = await resp.json().catch(function() { return {}; });
      errorEl.className = 'error';
      errorEl.textContent = 'Error ' + resp.status + ': ' + (data.detail || 'Unknown error');
    }
  } catch (e) {
    errorEl.className = 'error';
    errorEl.textContent = 'Network error: ' + e.message;
  } finally {
    // Clear the input regardless of outcome. Token must not remain in the DOM.
    inputEl.value = '';
    if (submitBtn) submitBtn.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Start profile (POST /api/v1/onboarding/{profile}/start)
// ---------------------------------------------------------------------------

async function startProfile(profile) {
  const msgEl = document.getElementById(profile + '-start-msg');
  const startBtn = document.getElementById(profile + '-start-btn');

  msgEl.className = 'info';
  msgEl.textContent = 'Starting ' + profile + '...';
  if (startBtn) startBtn.disabled = true;

  const csrf = await ensureCsrfToken();
  if (!csrf) {
    msgEl.className = 'error';
    msgEl.textContent = 'CSRF token unavailable. Please reload and log in again.';
    if (startBtn) startBtn.disabled = false;
    return;
  }

  try {
    const resp = await fetch('/api/v1/onboarding/' + profile + '/start', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
      },
    });
    const data = await resp.json().catch(function() { return {}; });

    if (resp.status === 201 || (resp.status === 200 && data.idempotent)) {
      msgEl.className = 'success';
      const note = data.idempotent ? ' (already running)' : '';
      msgEl.textContent = 'Profile ' + profile + ' is up and healthy' + note + '.';
    } else if (resp.status === 409 && data.error === 'mutual_exclusion') {
      msgEl.className = 'error';
      msgEl.textContent = (
        'Cannot start ' + profile + ': profile "' + data.running_profile +
        '" is already running. Bring it down first.'
      );
    } else if (resp.status === 400 && data.error === 'credential_not_present') {
      msgEl.className = 'error';
      msgEl.textContent = 'Credential not present. Complete the token setup above before starting.';
    } else if (resp.status === 401) {
      msgEl.className = 'error';
      msgEl.textContent = 'Session expired. Please log in again.';
    } else {
      msgEl.className = 'error';
      msgEl.textContent = 'Error ' + resp.status + ': ' + (data.detail || data.error || 'Unknown error');
    }
  } catch (e) {
    msgEl.className = 'error';
    msgEl.textContent = 'Network error: ' + e.message;
  } finally {
    if (startBtn) {
      // Re-check status to update the button state.
      await fetchStatus(profile);
    }
  }
}

// ---------------------------------------------------------------------------
// Initialise: start polling for the default (active) tab
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', function() {
  startPolling('copilot');
});
