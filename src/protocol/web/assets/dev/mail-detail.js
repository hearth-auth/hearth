// Mailcatcher detail page: tab switching + delete-confirmation.
//
// Standalone for /dev/mail/{id} — does NOT use admin.js (different layout).
//
// Wire-up:
//   <button data-mail-tab="html">…</button>            ← role=tab buttons
//   <form data-mail-delete>…</form>                    ← confirm before submit
(function() {
  function init() {
    var TABS = ['html', 'text', 'headers'];

    document.querySelectorAll('[data-mail-tab]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var target = btn.dataset.mailTab;
        TABS.forEach(function(t) {
          var pane = document.getElementById('tab-' + t);
          var tabBtn = document.getElementById('btn-' + t);
          if (pane)   pane.classList.toggle('hidden', t !== target);
          if (tabBtn) tabBtn.setAttribute('aria-selected', t === target ? 'true' : 'false');
        });
      });
    });

    document.querySelectorAll('form[data-mail-delete]').forEach(function(form) {
      form.addEventListener('submit', function(e) {
        if (!window.confirm('Delete this email?')) {
          e.preventDefault();
        }
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
