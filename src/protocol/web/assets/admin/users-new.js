// Create-user form: email shape validation and password-strength meter.
//
// Activated by presence of #create-user-submit.
(function() {
  function init() {
    var submitBtn = document.getElementById('create-user-submit');
    if (!submitBtn) return;

    var emailEl       = document.getElementById('email');
    var emailError    = document.getElementById('email-error');
    var pwEl          = document.getElementById('password');
    var pwStrength    = document.getElementById('pw-strength');
    var pwError       = document.getElementById('pw-error');
    var strengthLabel = document.getElementById('strength-label');
    var bars          = Array.from(document.querySelectorAll('[data-strength-bar]'));

    if (!emailEl || !pwEl) return;

    var emailDirty = false;
    var passwordDirty = false;

    var STRENGTH_COLORS = ['bg-danger','bg-warning','bg-warning','bg-teal-500','bg-success'];
    var STRENGTH_LABELS = [
      { text: 'Very weak',   cls: 'text-danger-fg'  },
      { text: 'Weak',        cls: 'text-danger-fg'  },
      { text: 'Fair',        cls: 'text-warning-fg' },
      { text: 'Strong',      cls: 'text-teal-500'   },
      { text: 'Very strong', cls: 'text-success-fg' }
    ];

    function emailValid() {
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailEl.value);
    }

    function pwScore(p) {
      var s = 0;
      if (p.length >= 8)          s++;
      if (p.length >= 12)         s++;
      if (/[A-Z]/.test(p))        s++;
      if (/[0-9]/.test(p))        s++;
      if (/[^A-Za-z0-9]/.test(p)) s++;
      return Math.min(s, 4);
    }

    function updateEmail() {
      var valid = emailValid();
      emailEl.classList.toggle('border-danger-fg', emailDirty && !valid);
      if (emailError) emailError.classList.toggle('hidden', !(emailDirty && !valid));
      submitBtn.disabled = emailDirty && !valid;
    }

    function updatePassword() {
      var p = pwEl.value;
      var show = p.length > 0;
      if (pwStrength) pwStrength.classList.toggle('hidden', !show);
      if (pwError) pwError.classList.toggle('hidden', !(passwordDirty && p.length === 0));
      if (show) {
        var score = pwScore(p);
        var color = STRENGTH_COLORS[score];
        bars.forEach(function(bar, i) {
          bar.className = 'h-full flex-1 rounded-full transition-colors duration-200 ' +
            (i < score ? color : 'bg-divider-strong');
        });
        var lbl = STRENGTH_LABELS[score];
        if (strengthLabel) {
          strengthLabel.textContent = lbl.text;
          strengthLabel.className = lbl.cls;
        }
      }
    }

    emailEl.addEventListener('input', updateEmail);
    emailEl.addEventListener('blur',  function() { emailDirty = true; updateEmail(); });
    pwEl.addEventListener('input',    updatePassword);
    pwEl.addEventListener('blur',     function() { passwordDirty = true; updatePassword(); });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
