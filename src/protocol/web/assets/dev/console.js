// Dev console (/dev): copy buttons and the live TOTP codes.
// Served as a static file because the page's CSP allows no inline script.
(function () {
  "use strict";

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy]");
    if (!button) return;
    var source = document.getElementById(button.getAttribute("data-copy"));
    if (!source || !navigator.clipboard) return;
    navigator.clipboard.writeText(source.textContent.trim()).then(function () {
      var label = button.textContent;
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = label; }, 1200);
    });
  });

  var codes = document.querySelectorAll("[data-code]");
  var countdowns = document.querySelectorAll("[data-seconds-left]");
  if (codes.length === 0) return;

  var secondsLeft = parseInt(countdowns.length ? countdowns[0].textContent : "30", 10) || 30;

  function refresh() {
    fetch("/dev/codes", { cache: "no-store", credentials: "same-origin" })
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (body) {
        if (!body) return;
        codes.forEach(function (el) {
          var code = body[el.getAttribute("data-code")];
          if (code) el.textContent = code;
        });
        secondsLeft = body.seconds_left;
        countdowns.forEach(function (el) { el.textContent = String(secondsLeft); });
      })
      .catch(function () {});
  }

  setInterval(function () {
    secondsLeft -= 1;
    if (secondsLeft <= 0) {
      refresh();
      return;
    }
    countdowns.forEach(function (el) { el.textContent = String(secondsLeft); });
  }, 1000);
})();
