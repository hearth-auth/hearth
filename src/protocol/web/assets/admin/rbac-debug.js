// Permission-check tab bar + token-preview AJAX.
//
// Activated by presence of #tabs-container[data-rbac-debug]. The preview URL
// is read from #tab-token's data-preview-url attribute.
(function() {
  function init() {
    var container = document.querySelector('#tabs-container[data-rbac-debug]');
    if (!container) return;

    var ACTIVE   = 'border-b-2 border-ht-content-brand text-ht-content-primary';
    var INACTIVE = 'text-ht-content-secondary hover:text-ht-content-primary';

    container.querySelectorAll('.tab-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var target = btn.dataset.tab;
        container.querySelectorAll('.tab-btn').forEach(function(b) {
          b.className = b.className
            .replace('border-b-2 border-ht-content-brand text-ht-content-primary', '')
            .replace('text-ht-content-secondary hover:text-ht-content-primary', '')
            .trim();
          b.className += ' ' + (b.dataset.tab === target ? ACTIVE : INACTIVE);
        });
        container.querySelectorAll('.tab-panel').forEach(function(panel) {
          panel.classList.toggle('hidden', panel.id !== 'tab-' + target);
        });
      });
    });

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
