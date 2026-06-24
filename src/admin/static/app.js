/**
 * app.js - Navigation shell for the AgentArca Admin frontend.
 *
 * Responsibilities:
 *   - Handle the login form submission (POST /api/v1/login).
 *   - Store the CSRF token from the login response in memory (never in localStorage).
 *   - Include X-CSRF-Token on all subsequent state-changing requests.
 *   - Show the navigation skeleton after successful login.
 *
 * Security notes:
 *   - The session cookie is HttpOnly; JS cannot read it. That is intentional.
 *   - The CSRF token is kept in a module-scoped variable (memory only, not persisted).
 *   - No secret value is ever stored or logged by this script.
 */

(function () {
  "use strict";

  // Module-scoped CSRF token. Set after a successful login.
  let csrfToken = null;

  /**
   * Send a JSON POST request with the CSRF token header if available.
   */
  async function apiPost(path, body) {
    const headers = { "Content-Type": "application/json" };
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    const resp = await fetch(path, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      credentials: "same-origin",
    });
    return resp;
  }

  /**
   * Handle the login form submission.
   */
  async function handleLogin(event) {
    event.preventDefault();
    const form = event.target;
    const statusEl = document.getElementById("status");
    const secretInput = document.getElementById("secret");
    const secretValue = secretInput.value;

    statusEl.className = "";
    statusEl.textContent = "Signing in...";

    try {
      const resp = await apiPost("/api/v1/login", { secret: secretValue });

      // Clear the secret value from the input immediately after submission.
      secretInput.value = "";

      if (resp.ok) {
        const data = await resp.json();
        // Store CSRF token in memory only (not localStorage, not a cookie).
        if (data.csrf_token) {
          csrfToken = data.csrf_token;
        }
        statusEl.className = "ok";
        statusEl.textContent = "Signed in.";
        document.getElementById("login-form").style.display = "none";
        document.getElementById("nav").style.display = "block";
      } else {
        csrfToken = null;
        statusEl.textContent = resp.status === 401
          ? "Invalid secret. Please try again."
          : "Sign-in failed (" + resp.status + ").";
      }
    } catch (err) {
      secretInput.value = "";
      csrfToken = null;
      statusEl.textContent = "Network error. Is the admin server running?";
    }
  }

  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    loginForm.addEventListener("submit", handleLogin);
  }
})();
