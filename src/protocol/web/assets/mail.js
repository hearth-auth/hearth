// Hearth dev mailcatcher — tab switcher for mail_detail.html.
// No inline scripts or event-handler attributes; CSP script-src 'self' safe.
document.addEventListener('DOMContentLoaded', function () {
  var tabs = ['html', 'text', 'headers'];

  function showTab(tab) {
    tabs.forEach(function (t) {
      var panel = document.getElementById('tab-' + t);
      var btn = document.getElementById('btn-' + t);
      if (panel) panel.classList.toggle('hidden', t !== tab);
      if (btn) btn.setAttribute('aria-selected', t === tab ? 'true' : 'false');
    });
  }

  tabs.forEach(function (t) {
    var btn = document.getElementById('btn-' + t);
    if (btn) btn.addEventListener('click', function () { showTab(t); });
  });
});
