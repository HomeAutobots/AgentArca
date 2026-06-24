/**
 * profiles.js - Profile lifecycle UI logic.
 *
 * Design invariants (SPEC-27-P2 section 11):
 *   - Only one profile can run at a time. The mutex-notice is always visible.
 *   - The UI NEVER offers a "run both" or "force start anyway" affordance.
 *   - Every up/switch action requires a modal confirm step before the API call.
 *   - On a 409 (mutual_exclusion) response: display the running profile name and
 *     instruct the operator to bring it down first. No retry or override button.
 *   - On any error: display the error clearly. Never silently retry.
 *
 * No "run both" affordance exists anywhere in this file, in any code path, including
 * error recovery. The strings "run both", "both up", and "concurrent" do not appear
 * in any form submission or API call context.
 */

'use strict';

const PROFILES = ['copilot', 'claude', 'codex'];

// Pending modal callback. Set before opening the modal; called on confirm.
let _pendingAction = null;

// CSRF token loaded once after status fetch.
let _csrfToken = '';

// ---------------------------------------------------------------------------
// CSRF token acquisition
// ---------------------------------------------------------------------------

async function ensureCsrfToken() {
  if (_csrfToken) return _csrfToken;
  // The session cookie carries auth; the CSRF token is returned by /api/v1/login.
  // If we do not have one yet, read it from a meta tag injected at login time,
  // or prompt the user to log in. For the profile view, we rely on the session
  // already being established (same pattern as allowlist.js).
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) {
    _csrfToken = meta.getAttribute('content') || '';
  }
  return _csrfToken;
}

function setCsrfToken(token) {
  _csrfToken = token;
}

// ---------------------------------------------------------------------------
// Status fetch (reads GET /api/v1/logs/health, Phase 1 endpoint)
// ---------------------------------------------------------------------------

async function fetchStatus() {
  try {
    const resp = await fetch('/api/v1/logs/health', {credentials: 'same-origin'});
    if (resp.status === 401) {
      showActionMsg('Session expired. Please log in again.', 'warn');
      renderCards({});
      return;
    }
    if (!resp.ok) {
      showActionMsg('Failed to load profile status (HTTP ' + resp.status + ').', 'err');
      renderCards({});
      return;
    }
    const data = await resp.json();
    renderCards(data);
    // Pre-select the active profile in the switch dropdowns.
    const active = data.active_profile || '';
    if (active && PROFILES.includes(active)) {
      const fromSel = document.getElementById('switch-from');
      if (fromSel) fromSel.value = active;
    }
  } catch (e) {
    showActionMsg('Error loading status: ' + e.message, 'err');
    renderCards({});
  }
}

// ---------------------------------------------------------------------------
// Card rendering
// ---------------------------------------------------------------------------

function renderCards(data) {
  const grid = document.getElementById('profile-grid');
  const loader = document.getElementById('loading-cards');
  if (loader) loader.remove();

  // Remove existing cards (re-render on refresh).
  Array.from(grid.querySelectorAll('.profile-card')).forEach(el => el.remove());

  const profileStatuses = data.profiles || {};
  const active = data.active_profile || null;

  PROFILES.forEach(profile => {
    const card = document.createElement('div');
    card.className = 'profile-card';
    card.id = 'card-' + profile;

    const ps = profileStatuses[profile] || {};
    const isUp = ps.running === true;
    const isHealthy = ps.healthy === true;

    let badgeHtml = '';
    if (isUp) {
      badgeHtml += '<span class="badge badge-up">UP</span> ';
      if (isHealthy) {
        badgeHtml += '<span class="badge badge-healthy">HEALTHY</span> ';
      } else {
        badgeHtml += '<span class="badge badge-unhealthy">UNHEALTHY</span> ';
      }
    } else {
      badgeHtml += '<span class="badge badge-down">DOWN</span> ';
    }
    if (profile === active) {
      badgeHtml += '<span class="badge badge-active">ACTIVE</span>';
    }

    let buttonHtml = '';
    if (!isUp) {
      // UP button: the only affordance when the profile is down.
      // No "force" or "override" variant exists.
      buttonHtml = '<button onclick="initUp(\'' + profile + '\')">Up</button>';
    } else {
      // DOWN button: only shown when profile is up.
      buttonHtml = '<button class="danger" onclick="initDown(\'' + profile + '\')">Down</button>';
    }

    card.innerHTML =
      '<h3>' + profile + '</h3>' +
      '<div style="margin-bottom:0.5em;">' + badgeHtml + '</div>' +
      '<div class="card-actions">' + buttonHtml + '</div>' +
      '<div class="card-msg" id="card-msg-' + profile + '"></div>';

    grid.appendChild(card);
  });
}

function showCardMsg(profile, text, type) {
  const el = document.getElementById('card-msg-' + profile);
  if (el) {
    el.innerHTML = '<div class="msg ' + type + '">' + escHtml(text) + '</div>';
  }
}

function showActionMsg(text, type) {
  const el = document.getElementById('action-msg');
  if (el) {
    el.innerHTML = '<div class="msg ' + type + '">' + escHtml(text) + '</div>';
  }
}

function showSwitchMsg(text, type) {
  const el = document.getElementById('switch-msg');
  if (el) {
    el.innerHTML = '<div class="msg ' + type + '">' + escHtml(text) + '</div>';
  }
}

// ---------------------------------------------------------------------------
// Modal confirm (SPEC-27-P2 section 11 item 6)
// ---------------------------------------------------------------------------

function openModal(title, body, onConfirm) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').textContent = body;
  _pendingAction = onConfirm;
  const overlay = document.getElementById('modal-overlay');
  overlay.classList.add('visible');
  document.getElementById('modal-confirm-btn').focus();
}

function cancelModal() {
  _pendingAction = null;
  document.getElementById('modal-overlay').classList.remove('visible');
}

function confirmAction() {
  document.getElementById('modal-overlay').classList.remove('visible');
  const action = _pendingAction;
  _pendingAction = null;
  if (action) action();
}

// Close modal on overlay click (not on box click).
document.getElementById('modal-overlay').addEventListener('click', function(e) {
  if (e.target === this) cancelModal();
});

// ---------------------------------------------------------------------------
// Up action
// ---------------------------------------------------------------------------

function initUp(profile) {
  openModal(
    'Bring up profile: ' + profile,
    'This will start the ' + profile + ' agent profile. Only one profile can run at a time. Confirm?',
    () => executeUp(profile)
  );
}

async function executeUp(profile) {
  showCardMsg(profile, 'Starting...', 'info');
  await ensureCsrfToken();
  try {
    const resp = await fetch('/api/v1/profiles/' + profile + '/up', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': _csrfToken,
      },
    });
    const data = await resp.json();

    if (resp.status === 201 || (resp.status === 200 && data.idempotent)) {
      const note = data.idempotent ? ' (already running)' : '';
      showCardMsg(profile, 'Profile ' + profile + ' is up and healthy' + note + '.', 'ok');
    } else if (resp.status === 409 && data.error === 'mutual_exclusion') {
      // Mutual-exclusion: show the running profile, instruct to bring it down first.
      // NEVER offer a "run both" or "force" affordance here.
      showCardMsg(profile,
        'Cannot start ' + profile + ': profile "' + data.running_profile + '" is already running. ' +
        'Bring it down first.', 'warn');
    } else if (resp.status === 401) {
      showCardMsg(profile, 'Session expired. Please log in again.', 'err');
    } else {
      const detail = data.detail || data.error || 'Unknown error';
      showCardMsg(profile, 'Error: ' + detail, 'err');
    }
  } catch (e) {
    showCardMsg(profile, 'Network error: ' + e.message, 'err');
  }
  // Refresh status after action.
  await fetchStatus();
}

// ---------------------------------------------------------------------------
// Down action
// ---------------------------------------------------------------------------

function initDown(profile) {
  openModal(
    'Bring down profile: ' + profile,
    'This will stop the ' + profile + ' agent profile. The developer session will be terminated. Confirm?',
    () => executeDown(profile)
  );
}

async function executeDown(profile) {
  showCardMsg(profile, 'Stopping...', 'info');
  await ensureCsrfToken();
  try {
    const resp = await fetch('/api/v1/profiles/' + profile + '/down', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': _csrfToken,
      },
    });
    const data = await resp.json();
    if (resp.ok && data.ok) {
      const note = data.idempotent ? ' (was already down)' : '';
      showCardMsg(profile, 'Profile ' + profile + ' is down' + note + '.', 'ok');
    } else if (resp.status === 401) {
      showCardMsg(profile, 'Session expired. Please log in again.', 'err');
    } else {
      const detail = data.detail || data.error || 'Unknown error';
      showCardMsg(profile, 'Error: ' + detail, 'err');
    }
  } catch (e) {
    showCardMsg(profile, 'Network error: ' + e.message, 'err');
  }
  await fetchStatus();
}

// ---------------------------------------------------------------------------
// Switch action
// ---------------------------------------------------------------------------

function initSwitch() {
  const fromProfile = document.getElementById('switch-from').value;
  const toProfile = document.getElementById('switch-to').value;
  openModal(
    'Switch profile: ' + fromProfile + ' -> ' + toProfile,
    'This will bring down "' + fromProfile + '" and bring up "' + toProfile +
    '" in a single atomic operation. No two profiles will be live simultaneously. Confirm?',
    () => executeSwitch(fromProfile, toProfile)
  );
}

async function executeSwitch(fromProfile, toProfile) {
  showSwitchMsg('Switching from ' + fromProfile + ' to ' + toProfile + '...', 'info');
  document.getElementById('switch-btn').disabled = true;
  await ensureCsrfToken();
  try {
    const resp = await fetch('/api/v1/profiles/switch', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': _csrfToken,
      },
      body: JSON.stringify({'from': fromProfile, 'to': toProfile}),
    });
    const data = await resp.json();

    if (resp.ok && data.ok) {
      if (data.idempotent) {
        showSwitchMsg('No change: already on profile "' + toProfile + '".', 'ok');
      } else {
        showSwitchMsg('Switched from "' + fromProfile + '" to "' + toProfile + '". Gateway healthy.', 'ok');
      }
    } else if (resp.status === 409 && data.error === 'mutual_exclusion') {
      // Show which profile is actually running; operator must manually bring it down.
      // No silent retry. No concurrent-up affordance.
      showSwitchMsg(
        'Switch refused: profile "' + data.running_profile + '" is running (expected "' + fromProfile + '"). ' +
        'Bring it down first, then retry the switch.', 'warn');
    } else if (resp.status === 401) {
      showSwitchMsg('Session expired. Please log in again.', 'err');
    } else {
      const detail = data.detail || data.error || 'Unknown error';
      showSwitchMsg('Switch error: ' + detail, 'err');
    }
  } catch (e) {
    showSwitchMsg('Network error: ' + e.message, 'err');
  }
  document.getElementById('switch-btn').disabled = false;
  await fetchStatus();
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = String(str);
  return d.innerHTML;
}

// ---------------------------------------------------------------------------
// Initialise
// ---------------------------------------------------------------------------

// Read CSRF token from session storage if the login page stored it there.
(function init() {
  const stored = sessionStorage.getItem('csrf_token');
  if (stored) _csrfToken = stored;
  fetchStatus();
  // Refresh status every 30 seconds.
  setInterval(fetchStatus, 30000);
})();
