// Permission-check tab bar + token-preview AJAX.
//
// Activated by presence of #tabs-container[data-rbac-debug]. The preview URL
// is read from #tab-token's data-preview-url attribute.
(function() {
  function init() {
    var container = document.querySelector('#tabs-container[data-rbac-debug]');
    if (!container) return;

    // Fix 4: use individual class names so classList.add/remove works regardless
    // of the order classes appear in the element's className string.
    var ACTIVE_CLASSES   = ['border-b-2', 'border-ht-content-brand', 'text-ht-content-primary'];
    var INACTIVE_CLASSES = ['text-ht-content-secondary', 'hover:text-ht-content-primary'];

    container.querySelectorAll('.tab-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var target = btn.dataset.tab;

        container.querySelectorAll('.tab-btn').forEach(function(b) {
          ACTIVE_CLASSES.forEach(function(c) { b.classList.remove(c); });
          INACTIVE_CLASSES.forEach(function(c) { b.classList.remove(c); });
          var classes = b.dataset.tab === target ? ACTIVE_CLASSES : INACTIVE_CLASSES;
          classes.forEach(function(c) { b.classList.add(c); });
        });

        container.querySelectorAll('.tab-panel').forEach(function(panel) {
          panel.classList.toggle('hidden', panel.id !== 'tab-' + target);
        });

        // Fix 3: pre-fill token-user-id when switching to the Token Preview tab
        if (target === 'token') {
          var userInput  = document.getElementById('user-id-input');
          var tokenInput = document.getElementById('token-user-id');
          if (userInput && tokenInput && userInput.value.trim()) {
            tokenInput.value = userInput.value.trim();
          }
        }
      });
    });

    // Fix 2: delegated click handler for the user-search dropdown.
    // Buttons carry data-value (UUID) and data-label (display name).
    var optionsEl = document.getElementById('user-id-options');
    var userInput = document.getElementById('user-id-input');
    if (optionsEl && userInput) {
      optionsEl.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-value]');
        if (!btn) return;

        var uuid  = btn.dataset.value;
        var label = btn.dataset.label;

        userInput.value = uuid;

        // Show the human-readable label below the input so the operator can
        // confirm who was selected before submitting.
        var hint = document.getElementById('user-id-selected-hint');
        if (!hint) {
          hint = document.createElement('span');
          hint.id = 'user-id-selected-hint';
          hint.className = 'block mt-1 text-xs text-ht-content-muted truncate';
          userInput.parentNode.appendChild(hint);
        }
        hint.textContent = label;

        optionsEl.classList.add('hidden');
      });
    }

    var previewBtn = document.getElementById('token-preview-btn');
    var userIdEl   = document.getElementById('token-user-id');
    var resultDiv  = document.getElementById('token-result');
    var resultPre  = document.getElementById('token-result-pre');
    var tokenTab   = document.getElementById('tab-token');
    var previewUrl = tokenTab ? tokenTab.dataset.previewUrl : '';

    if (!previewBtn || !userIdEl || !previewUrl) return;

    previewBtn.addEventListener('click', function() {
      var uid = userIdEl.value.trim();
      if (!uid) return;
      previewBtn.disabled = true;
      previewBtn.textContent = 'Loading\u2026';
      fetch(previewUrl + '?user_id=' + encodeURIComponent(uid))
        .then(function(r) { return r.text(); })
        .then(function(text) {
          if (resultPre) resultPre.textContent = text;
          if (resultDiv) resultDiv.classList.remove('hidden');
        })
        .catch(function(err) {
          if (resultPre) resultPre.textContent = 'Error: ' + err.message;
          if (resultDiv) resultDiv.classList.remove('hidden');
        })
        .finally(function() {
          previewBtn.disabled = false;
          previewBtn.textContent = 'Preview token';
        });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
