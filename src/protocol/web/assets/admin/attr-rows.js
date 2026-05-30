// Hearth admin — dynamic attribute row add/remove for create/edit forms.
// CSP-safe (loaded as external script). Registers via event delegation so
// it works on both freshly-rendered and HTMX-swapped content.
(function () {
  document.addEventListener('click', function (e) {
    var addBtn = e.target.closest('[data-add-attr-row]');
    if (addBtn) {
      var container = addBtn.closest('[data-attr-rows]');
      if (!container) return;
      var rows = container.querySelector('#attr-rows');
      if (!rows) return;
      var row = document.createElement('div');
      row.className = 'flex gap-2 items-center attr-row';
      row.innerHTML =
        '<input type="text" name="attr_key" placeholder="key" class="input flex-1">' +
        '<input type="text" name="attr_val" placeholder="value" class="input flex-1">' +
        '<button type="button" data-remove-attr-row' +
        ' class="text-ht-content-muted hover:text-danger-fg text-sm px-2">\u2715</button>';
      rows.appendChild(row);
      return;
    }

    var removeBtn = e.target.closest('[data-remove-attr-row]');
    if (removeBtn) {
      removeBtn.closest('.attr-row')?.remove();
    }
  });
}());
