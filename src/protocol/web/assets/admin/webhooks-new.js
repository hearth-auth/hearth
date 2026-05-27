// Webhook create form: reveal/hide signing secret, send synthetic test ping.
//
// Configured by a form element with `data-webhook-form` and:
//   data-test-ping-url   — endpoint for the synthetic ping
//   #url, #secret        — form fields
//   #toggle-secret, #secret-show-icon, #secret-hide-icon — secret toggle
//   #test-endpoint-btn, #test-play-icon, #test-spinner, #test-btn-label
//   #test-result, #test-result-inner, #test-success-icon, #test-failure-icon,
//   #test-result-label, #test-result-message
(function() {
  function init() {
    var form = document.querySelector('form[data-webhook-form]');
    if (!form) return;

    var secretEl  = document.getElementById('secret');
    var toggleBtn = document.getElementById('toggle-secret');
    var showIcon  = document.getElementById('secret-show-icon');
    var hideIcon  = document.getElementById('secret-hide-icon');

    if (toggleBtn && secretEl) {
      toggleBtn.addEventListener('click', function() {
        var visible = secretEl.type === 'text';
        secretEl.type = visible ? 'password' : 'text';
        toggleBtn.setAttribute('aria-label', visible ? 'Reveal secret' : 'Hide secret');
        if (showIcon) showIcon.classList.toggle('hidden', !visible);
        if (hideIcon) hideIcon.classList.toggle('hidden', visible);
      });
    }

    var testBtn     = document.getElementById('test-endpoint-btn');
    var playIcon    = document.getElementById('test-play-icon');
    var spinner     = document.getElementById('test-spinner');
    var btnLabel    = document.getElementById('test-btn-label');
    var resultDiv   = document.getElementById('test-result');
    var resultInner = document.getElementById('test-result-inner');
    var successIcon = document.getElementById('test-success-icon');
    var failIcon    = document.getElementById('test-failure-icon');
    var resultLabel = document.getElementById('test-result-label');
    var resultMsg   = document.getElementById('test-result-message');
    var pingUrl     = form.dataset.testPingUrl;

    if (!testBtn || !pingUrl) return;

    testBtn.addEventListener('click', function() {
      var url    = document.getElementById('url').value;
      var secret = secretEl ? secretEl.value : '';
      testBtn.disabled = true;
      if (playIcon) playIcon.classList.add('hidden');
      if (spinner)  spinner.classList.remove('hidden');
      if (btnLabel) btnLabel.textContent = 'Sending\u2026';
      if (resultDiv) resultDiv.classList.add('hidden');

      fetch(pingUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({ url: url, secret: secret })
      })
      .then(function(r) { return r.json(); })
      .then(showResult)
      .catch(function() { showResult({ success: false, message: 'Request failed' }); });
    });

    function showResult(d) {
      testBtn.disabled = false;
      if (spinner)  spinner.classList.add('hidden');
      if (playIcon) playIcon.classList.remove('hidden');
      if (btnLabel) btnLabel.textContent = 'Test endpoint';

      if (resultInner) {
        resultInner.className = 'flex items-start gap-2 rounded-sm px-4 py-3 text-sm ' +
          (d.success ? 'bg-success/[0.12] text-success-fg' : 'bg-danger/[0.12] text-danger-fg');
      }
      if (successIcon) successIcon.classList.toggle('hidden', !d.success);
      if (failIcon)    failIcon.classList.toggle('hidden', !!d.success);
      if (resultLabel) resultLabel.textContent = d.success ? 'Ping delivered' : 'Delivery failed';
      if (resultMsg)   resultMsg.textContent   = d.message || '';
      if (resultDiv)   resultDiv.classList.remove('hidden');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
