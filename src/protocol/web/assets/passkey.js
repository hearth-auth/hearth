// Hearth passkey (WebAuthn) — eval-free vanilla JS module.
//
// Replaces Alpine.js passkeyLogin / passkeyManager / passkeyRow so the
// CSP can drop 'unsafe-eval' (HEA-849, parent: HEA-824).
//
// Dynamic config is read from data-* attributes on root elements;
// server-rendered text content is the default initial state.
// All authenticated POST calls include X-CSRF-Token from the layout
// <meta name="csrf"> tag.

(function () {
  'use strict';

  // ── Shared helpers ──────────────────────────────────────────────────

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf"]');
    return meta ? meta.content : '';
  }

  function b64urlEncode(buf) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64urlDecode(str) {
    var base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(base64), function (c) { return c.charCodeAt(0); });
  }

  // ── passkeyLogin ────────────────────────────────────────────────────
  //
  // Drives the "Sign in with passkey" button on login.html.
  // Reads config from data-* on #passkey-login-root; shows/hides
  // #passkey-section when PublicKeyCredential is available.

  function initPasskeyLogin() {
    var root = document.getElementById('passkey-login-root');
    if (!root) return;

    var ds = root.dataset;
    var beginUrl      = ds.beginUrl      || '';
    var completeUrl   = ds.completeUrl   || '';
    var unavailableMsg = ds.unavailableMsg || 'Passkey sign-in is not available on this device.';
    var cancelledMsg  = ds.cancelledMsg  || 'Sign-in cancelled.';
    var failedMsg     = ds.failedMsg     || 'Passkey sign-in failed.';
    var authenticatingText = ds.authenticatingLabel || 'Authenticating\u2026';
    var signInText         = ds.signInLabel         || 'Sign in with a passkey';

    var errorEl   = document.getElementById('passkey-error');
    var sectionEl = document.getElementById('passkey-section');
    var btn       = document.getElementById('passkey-btn');
    var spinner   = document.getElementById('passkey-spinner');
    var icon      = document.getElementById('passkey-icon');
    var labelEl   = document.getElementById('passkey-label');

    function showError(msg) {
      if (!errorEl) return;
      errorEl.textContent = msg;
      errorEl.hidden = false;
    }

    function clearError() {
      if (errorEl) { errorEl.textContent = ''; errorEl.hidden = true; }
    }

    function setAuthenticating(v) {
      if (btn)     btn.disabled = v;
      if (spinner) spinner.hidden = !v;
      if (icon)    icon.hidden = v;
      if (labelEl) labelEl.textContent = v ? authenticatingText : signInText;
    }

    function fetchBeginOptions() {
      if (!beginUrl) return Promise.resolve(null);
      return fetch(beginUrl, { credentials: 'same-origin' }).then(function (resp) {
        if (!resp.ok) return null;
        return resp.json().then(function (data) {
          return {
            challenge:        b64urlDecode(data.challenge),
            rpId:             data.rpId,
            userVerification: data.userVerification || 'preferred',
            timeout:          data.timeout || 300000,
          };
        });
      }).catch(function () { return null; });
    }

    function completeAuthentication(assertion) {
      var body = {
        credential_id:      b64urlEncode(assertion.rawId),
        client_data_json:   b64urlEncode(assertion.response.clientDataJSON),
        authenticator_data: b64urlEncode(assertion.response.authenticatorData),
        signature:          b64urlEncode(assertion.response.signature),
      };
      if (assertion.response.userHandle && assertion.response.userHandle.byteLength > 0) {
        body.user_handle = b64urlEncode(assertion.response.userHandle);
      }
      return fetch(completeUrl, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken(),
        },
        body: JSON.stringify(body),
      }).then(function (resp) {
        if (!resp.ok) {
          return resp.text().then(function (t) { throw new Error(t || 'Authentication failed'); });
        }
        return resp.json().then(function (result) {
          if (result.error) { showError(result.error); return; }
          if (result.redirect) window.location.href = result.redirect;
        });
      });
    }

    function tryConditionalMediation() {
      if (!PublicKeyCredential.isConditionalMediationAvailable) return;
      PublicKeyCredential.isConditionalMediationAvailable().then(function (available) {
        if (!available) return;
        fetchBeginOptions().then(function (opts) {
          if (!opts) return;
          return navigator.credentials.get({ publicKey: opts, mediation: 'conditional' });
        }).then(function (assertion) {
          if (assertion) return completeAuthentication(assertion);
        }).catch(function (e) {
          if (e.name !== 'NotAllowedError' && e.name !== 'AbortError') {
            console.debug('Conditional mediation unavailable:', e);
          }
        });
      }).catch(function () {});
    }

    if (!window.PublicKeyCredential) return;
    if (sectionEl) sectionEl.hidden = false;
    tryConditionalMediation();

    if (!btn) return;
    btn.addEventListener('click', function () {
      clearError();
      setAuthenticating(true);
      fetchBeginOptions().then(function (opts) {
        if (!opts) { showError(unavailableMsg); return; }
        return navigator.credentials.get({ publicKey: opts }).then(function (assertion) {
          if (!assertion) { showError(cancelledMsg); return; }
          return completeAuthentication(assertion);
        });
      }).catch(function (e) {
        if (e.name !== 'NotAllowedError') showError(e.message || failedMsg);
      }).then(function () {
        setAuthenticating(false);
      });
    });
  }

  // ── passkeyManager ──────────────────────────────────────────────────
  //
  // Drives the "Register a passkey" button on account/index.html.
  // Root element is #passkey-manager.

  function initPasskeyManager() {
    var root = document.getElementById('passkey-manager');
    if (!root) return;

    var btn      = document.getElementById('passkey-register-btn');
    var spinner  = document.getElementById('passkey-register-spinner');
    var labelEl  = document.getElementById('passkey-register-label');
    var errorEl  = document.getElementById('passkey-register-error');

    function setRegistering(v) {
      if (btn)     btn.disabled = v;
      if (spinner) spinner.hidden = !v;
      if (labelEl) labelEl.textContent = v ? 'Registering\u2026' : 'Register a passkey';
    }

    function showError(msg) {
      if (!errorEl) return;
      errorEl.textContent = msg;
      errorEl.hidden = false;
    }

    if (!btn) return;
    btn.addEventListener('click', function () {
      if (btn.disabled) return;
      setRegistering(true);
      if (errorEl) errorEl.hidden = true;

      fetch('/ui/account/passkeys/register-begin', { credentials: 'same-origin' })
        .then(function (resp) {
          if (!resp.ok) throw new Error('Failed to start registration');
          return resp.json();
        })
        .then(function (opts) {
          opts.challenge = b64urlDecode(opts.challenge);
          opts.user.id  = b64urlDecode(opts.user.id);
          return navigator.credentials.create({ publicKey: opts });
        })
        .then(function (cred) {
          if (!cred) throw new Error('Registration cancelled');
          var credName = prompt('Give this passkey a name (optional):', '') || '';
          return fetch('/ui/account/passkeys/register-complete', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': csrfToken(),
            },
            body: JSON.stringify({
              client_data_json:   b64urlEncode(cred.response.clientDataJSON),
              attestation_object: b64urlEncode(cred.response.attestationObject),
              name: credName.trim() || null,
            }),
          });
        })
        .then(function (resp) {
          if (!resp.ok) throw new Error('Registration failed');
          window.location.reload();
        })
        .catch(function (e) {
          if (e.name !== 'NotAllowedError') showError(e.message || 'Registration failed');
        })
        .then(function () {
          setRegistering(false);
        });
    });
  }

  // ── passkeyRow ──────────────────────────────────────────────────────
  //
  // Per-credential inline-edit on account/index.html.
  // Targets every <tr data-passkey-row="<credId>"> in the table.

  function initPasskeyRows() {
    var rows = document.querySelectorAll('tr[data-passkey-row]');
    for (var i = 0; i < rows.length; i++) {
      initRow(rows[i]);
    }
  }

  function initRow(row) {
    var credId = row.dataset.passkeyRow;
    var raw    = row.dataset.initialName || '';
    var _name  = raw || null;
    var displayName = raw || (credId.substring(0, 16) + '\u2026');

    var nameSpan    = row.querySelector('.passkey-name');
    var viewMode    = row.querySelector('.passkey-view-mode');
    var editMode    = row.querySelector('.passkey-edit-mode');
    var input       = row.querySelector('.passkey-edit-input');
    var startEditBtn = row.querySelector('.passkey-start-edit');
    var saveBtn     = row.querySelector('.passkey-save');
    var cancelBtn   = row.querySelector('.passkey-cancel');

    if (nameSpan) nameSpan.textContent = displayName;

    function showView() {
      if (viewMode) viewMode.hidden = false;
      if (editMode) editMode.hidden = true;
    }

    function showEdit() {
      if (input) input.value = _name || '';
      if (viewMode) viewMode.hidden = true;
      if (editMode) {
        editMode.hidden = false;
        if (input) setTimeout(function () { input.focus(); }, 0);
      }
    }

    function saveEdit() {
      var name = input ? input.value.trim() : '';
      fetch('/ui/account/passkeys/' + credId + '/rename', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken(),
        },
        body: JSON.stringify({ name: name }),
      }).then(function (resp) {
        if (!resp.ok) throw new Error('Rename failed');
        _name = name || null;
        displayName = name || (credId.substring(0, 16) + '\u2026');
        if (nameSpan) nameSpan.textContent = displayName;
        showView();
      }).catch(function (e) {
        alert(e.message || 'Rename failed');
      });
    }

    if (startEditBtn) startEditBtn.addEventListener('click', showEdit);
    if (saveBtn)      saveBtn.addEventListener('click', saveEdit);
    if (cancelBtn)    cancelBtn.addEventListener('click', showView);
    if (input) {
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter')  { e.preventDefault(); saveEdit(); }
        if (e.key === 'Escape') { showView(); }
      });
    }
  }

  // ── Boot ────────────────────────────────────────────────────────────

  function init() {
    initPasskeyLogin();
    initPasskeyManager();
    initPasskeyRows();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
