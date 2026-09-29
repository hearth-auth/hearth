// API token form: runs a passkey assertion as the second factor of the
// step-up, fills the hidden assertion_* fields, then submits the form.
//
// Configured by a form element with `data-api-token-form` and:
//   #api-token-passkey        — "Use a passkey" button
//   #api-token-passkey-error  — inline error text
//   #assertion_*              — hidden fields the server reads
//
// The challenge comes from /ui/account/passkeys/step-up-begin, which mints an
// authentication challenge for the signed-in account and issues no session.
(function () {
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

  function init() {
    var form = document.querySelector('form[data-api-token-form]');
    var btn = document.getElementById('api-token-passkey');
    if (!form || !btn) return;
    var errorEl = document.getElementById('api-token-passkey-error');

    function set(id, value) {
      var el = document.getElementById(id);
      if (el) el.value = value || '';
    }

    function showError(msg) {
      if (!errorEl) return;
      errorEl.textContent = msg;
      errorEl.hidden = false;
    }

    btn.addEventListener('click', function () {
      if (btn.disabled) return;
      if (!form.reportValidity()) return;
      btn.disabled = true;
      if (errorEl) errorEl.hidden = true;

      fetch('/ui/account/passkeys/step-up-begin', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-CSRF-Token': csrfToken() },
      })
        .then(function (resp) {
          if (!resp.ok) throw new Error('Could not start the passkey check.');
          return resp.json();
        })
        .then(function (opts) {
          return navigator.credentials.get({
            publicKey: {
              challenge: b64urlDecode(opts.challenge),
              rpId: opts.rpId,
              // A passkey counts as a second factor only when it verifies
              // the user, so always ask for it.
              userVerification: 'required',
              timeout: opts.timeout,
              allowCredentials: (opts.allowCredentials || []).map(function (c) {
                return { type: 'public-key', id: b64urlDecode(c.id) };
              }),
            },
          });
        })
        .then(function (cred) {
          if (!cred) throw new Error('Passkey check cancelled.');
          set('assertion_credential_id', b64urlEncode(cred.rawId));
          set('assertion_client_data_json', b64urlEncode(cred.response.clientDataJSON));
          set('assertion_authenticator_data', b64urlEncode(cred.response.authenticatorData));
          set('assertion_signature', b64urlEncode(cred.response.signature));
          set('assertion_user_handle',
            cred.response.userHandle ? b64urlEncode(cred.response.userHandle) : '');
          form.submit();
        })
        .catch(function (err) {
          btn.disabled = false;
          showError(err && err.message ? err.message : 'The passkey check failed.');
        });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
