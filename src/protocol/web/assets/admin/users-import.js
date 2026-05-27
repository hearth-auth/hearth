// CSV user-import flow: drop-zone → header parse → column mapping.
//
// Activated by presence of #import-form. Reads no template variables —
// the form's action attribute already carries the realm-scoped URL.
(function() {
  function init() {
    var form = document.getElementById('import-form');
    if (!form) return;

    var fileInput  = document.getElementById('csv-file-input');
    var browseBtn  = document.getElementById('browse-btn');
    var dropZone   = document.getElementById('drop-zone');
    var stepUpload = document.getElementById('step-upload');
    var stepMap    = document.getElementById('step-map');
    var fileLabel  = document.getElementById('file-name-label');
    var changeBtn  = document.getElementById('change-file-btn');
    var emailSel   = document.getElementById('col-email');
    var nameSel    = document.getElementById('col-name');
    var roleSel    = document.getElementById('col-role');
    var submitBtn  = document.getElementById('import-submit-btn');

    if (!fileInput || !dropZone || !emailSel || !submitBtn) return;

    browseBtn?.addEventListener('click', function() { fileInput.click(); });

    dropZone.addEventListener('dragover', function(e) {
      e.preventDefault();
      dropZone.classList.add('border-ht-content-brand', 'bg-ht-surface-overlay');
      dropZone.classList.remove('hover:border-divider-strong');
    });
    dropZone.addEventListener('dragleave', function() {
      dropZone.classList.remove('border-ht-content-brand', 'bg-ht-surface-overlay');
      dropZone.classList.add('hover:border-divider-strong');
    });
    dropZone.addEventListener('drop', function(e) {
      e.preventDefault();
      dropZone.classList.remove('border-ht-content-brand', 'bg-ht-surface-overlay');
      var f = e.dataTransfer.files[0];
      if (f) handleFile(f);
    });

    fileInput.addEventListener('change', function() {
      if (fileInput.files[0]) handleFile(fileInput.files[0]);
    });

    changeBtn?.addEventListener('click', function() {
      fileInput.value = '';
      stepMap?.classList.add('hidden');
      stepUpload?.classList.remove('hidden');
    });

    emailSel.addEventListener('change', function() {
      submitBtn.disabled = emailSel.value === '';
    });

    function populateSelect(sel, headers, guess) {
      if (!sel) return;
      while (sel.options.length > 1) sel.remove(1);
      var guessed = '';
      headers.forEach(function(h) {
        var opt = document.createElement('option');
        opt.value = h;
        opt.textContent = h;
        sel.appendChild(opt);
        if (!guessed && h.toLowerCase().includes(guess)) guessed = h;
      });
      if (guessed) sel.value = guessed;
    }

    function handleFile(f) {
      if (fileLabel) fileLabel.textContent = f.name;
      var reader = new FileReader();
      reader.onload = function(e) {
        var firstLine = (e.target.result.split('\n')[0] || '');
        var headers = firstLine.split(',').map(function(h) {
          return h.trim().replace(/^['"]|['"]$/g, '');
        }).filter(Boolean);

        populateSelect(emailSel, headers, 'email');
        populateSelect(nameSel,  headers, 'name');
        populateSelect(roleSel,  headers, 'role');

        submitBtn.disabled = emailSel.value === '';
        stepUpload?.classList.add('hidden');
        stepMap?.classList.remove('hidden');
      };
      reader.readAsText(f);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
