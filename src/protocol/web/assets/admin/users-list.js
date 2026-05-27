// Bulk user actions: row checkbox state → toolbar count, two-step
// confirm for `deactivate`, submit form with `bulk_ids` joined.
//
// Configured by #bulk-form with data-total-users="<n>" — the SSR-rendered
// row count used as the idle label.
(function() {
  function init() {
    var form = document.getElementById('bulk-form');
    if (!form) return;

    var idsInput    = document.getElementById('bulk-ids');
    var actionInput = document.getElementById('bulk-action-input');
    var toolbar     = document.getElementById('bulk-toolbar');
    var countLabel  = document.getElementById('bulk-count-label');
    var actionSel   = document.getElementById('bulk-action-select');
    var applyBtn    = document.getElementById('bulk-apply-btn');
    var selectAll   = document.getElementById('select-all-check');
    var TOTAL       = parseInt(form.dataset.totalUsers, 10) || 0;
    var confirmPending = false;

    function getChecked() {
      return Array.from(form.querySelectorAll('input.row-check:checked'));
    }

    function updateCount() {
      var checked = getChecked();
      var n = checked.length;
      if (idsInput) idsInput.value = checked.map(function(c) { return c.value; }).join(',');
      if (countLabel) {
        countLabel.textContent = n === 0
          ? (TOTAL + ' user' + (TOTAL === 1 ? '' : 's'))
          : (n + ' selected');
      }
      if (toolbar) toolbar.classList.toggle('hidden', n === 0);
      confirmPending = false;
      resetApplyBtn();
    }

    function resetApplyBtn() {
      if (!applyBtn) return;
      applyBtn.className = 'rounded px-3 py-1 text-xs font-semibold transition-colors disabled:opacity-40 border border-strong bg-ht-surface-elevated text-ht-content-secondary hover-bg-divider';
      applyBtn.textContent = 'Apply';
    }

    actionSel?.addEventListener('change', function() {
      confirmPending = false;
      resetApplyBtn();
      if (applyBtn) applyBtn.classList.toggle('hidden', actionSel.value === '');
    });

    applyBtn?.addEventListener('click', function() {
      var action = actionSel ? actionSel.value : '';
      if (!action) return;
      if (action === 'deactivate' && !confirmPending) {
        confirmPending = true;
        applyBtn.className = 'rounded px-3 py-1 text-xs font-semibold transition-colors btn-danger text-graphite-950';
        applyBtn.textContent = 'Confirm deactivate';
        return;
      }
      if (actionInput) actionInput.value = action;
      form.submit();
    });

    selectAll?.addEventListener('change', function() {
      form.querySelectorAll('input.row-check').forEach(function(c) {
        c.checked = selectAll.checked;
      });
      updateCount();
    });

    form.addEventListener('change', function(e) {
      if (e.target.classList.contains('row-check')) {
        var all = form.querySelectorAll('input.row-check');
        var allChecked = Array.from(all).every(function(c) { return c.checked; });
        if (selectAll) {
          selectAll.checked = allChecked;
          selectAll.indeterminate = !allChecked && getChecked().length > 0;
        }
        updateCount();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
