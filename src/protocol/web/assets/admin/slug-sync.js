// Slug-sync: auto-derive a URL-safe slug from a name input until the user
// types in the slug field themselves.
//
// Activated by a form element with `data-slug-sync` and these inputs:
//   <input data-slug-name>   — source name input
//   <input data-slug-target> — target slug input
//
// The form element configures the policy via attributes:
//   data-slug-allow-underscore="true"   (default false)
//   data-slug-max="63"                  (default 63)
//   data-slug-touched="true"            (default false; true when SSR
//                                        rendered a non-empty slug)
(function() {
  function init(form) {
    var nameEl   = form.querySelector('[data-slug-name]');
    var slugEl   = form.querySelector('[data-slug-target]');
    if (!nameEl || !slugEl) return;

    var allowUnderscore = form.dataset.slugAllowUnderscore === 'true';
    var max             = parseInt(form.dataset.slugMax, 10) || 63;
    var touched         = form.dataset.slugTouched === 'true';

    var stripPattern = allowUnderscore ? /[^a-z0-9_-]+/g : /[^a-z0-9]+/g;

    slugEl.addEventListener('input', function() { touched = true; });
    nameEl.addEventListener('input', function() {
      if (touched) return;
      slugEl.value = nameEl.value.toLowerCase()
        .replace(stripPattern, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, max);
    });
  }

  function bootstrap() {
    document.querySelectorAll('form[data-slug-sync]').forEach(init);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }
})();
