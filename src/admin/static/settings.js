/**
 * settings.js - Portal settings page logic.
 *
 * Manages the detection toggle bound to GET/PATCH /api/v1/portal-config.
 *
 * Security invariants (B7, B9):
 * - Toggle is labeled "Enable observability pipeline" (not "security monitoring").
 * - When OFF, the framing notice is shown: egress controls are unaffected.
 * - D5.4 isolation invariants are displayed read-only; no editable control exists.
 * - This file does NOT call any external URL and does NOT modify any allowlist.
 */

'use strict';

let _csrfToken = '';
let _applying = false;

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
// Load current config (GET /api/v1/portal-config)
// ---------------------------------------------------------------------------

async function loadConfig() {
  const statusEl = document.getElementById('toggle-status');
  const errorEl = document.getElementById('toggle-error');
  statusEl.textContent = 'Loading...';
  errorEl.style.display = 'none';

  try {
    const resp = await fetch('/api/v1/portal-config', {
      credentials: 'include',
    });
    if (resp.status === 401) {
      statusEl.textContent = 'Session expired. Please log in again.';
      return;
    }
    if (!resp.ok) {
      statusEl.textContent = 'Failed to load settings (HTTP ' + resp.status + ').';
      return;
    }
    const data = await resp.json();
    applyConfigToUI(data);
  } catch (e) {
    statusEl.textContent = 'Network error: ' + e.message;
  }
}

function applyConfigToUI(config) {
  const toggle = document.getElementById('detection-toggle');
  const offNotice = document.getElementById('detection-off-notice');
  const statusEl = document.getElementById('toggle-status');

  const enabled = config.detection_enabled === true;
  toggle.checked = enabled;

  if (enabled) {
    offNotice.style.display = 'none';
    statusEl.textContent = 'Observability pipeline: ON';
  } else {
    offNotice.style.display = 'block';
    statusEl.textContent = 'Observability pipeline: OFF';
  }
}

// ---------------------------------------------------------------------------
// Apply toggle change (PATCH /api/v1/portal-config)
// ---------------------------------------------------------------------------

async function applyDetectionToggle() {
  if (_applying) return;
  _applying = true;

  const toggle = document.getElementById('detection-toggle');
  const statusEl = document.getElementById('toggle-status');
  const errorEl = document.getElementById('toggle-error');

  const newValue = toggle.checked;
  statusEl.textContent = 'Saving...';
  errorEl.style.display = 'none';

  const csrf = await ensureCsrfToken();
  if (!csrf) {
    errorEl.textContent = 'CSRF token unavailable. Please reload and log in again.';
    errorEl.style.display = 'block';
    toggle.checked = !newValue; // revert
    _applying = false;
    return;
  }

  try {
    const resp = await fetch('/api/v1/portal-config', {
      method: 'PATCH',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
      },
      body: JSON.stringify({ detection_enabled: newValue }),
    });

    if (resp.status === 401) {
      errorEl.textContent = 'Session expired. Please log in again.';
      errorEl.style.display = 'block';
      toggle.checked = !newValue;
    } else if (!resp.ok) {
      const data = await resp.json().catch(function() { return {}; });
      errorEl.textContent = 'Save failed: ' + (data.detail || 'HTTP ' + resp.status);
      errorEl.style.display = 'block';
      toggle.checked = !newValue; // revert on failure
    } else {
      const data = await resp.json();
      applyConfigToUI(data);
    }
  } catch (e) {
    errorEl.textContent = 'Network error: ' + e.message;
    errorEl.style.display = 'block';
    toggle.checked = !newValue;
  } finally {
    _applying = false;
  }
}

// ---------------------------------------------------------------------------
// Initialise
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', function() {
  loadConfig();
});
