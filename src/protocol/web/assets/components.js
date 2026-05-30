// Hearth component library — vanilla JS, CSP 'script-src self' safe.
// No ES modules, no bundler, no import/export.
// Components are mounted via [data-component="name"] attributes on
// DOMContentLoaded and every htmx:afterSwap (idempotent — already-mounted
// elements are skipped).

(function () {

  // =========================================================================
  // Component base class
  // =========================================================================

  class Component {
    constructor(root) {
      this._root = root;
      this._teardowns = [];
    }

    /** Query scoped to the component root. */
    $(sel) { return this._root.querySelector(sel); }

    /** Query all scoped to the component root. */
    $$(sel) { return Array.from(this._root.querySelectorAll(sel)); }

    /** Attach an event listener and register it for teardown. */
    on(target, event, handler) {
      target.addEventListener(event, handler);
      this._teardowns.push(() => target.removeEventListener(event, handler));
    }

    /** Remove all listeners and mark element as unmounted. */
    destroy() {
      for (const fn of this._teardowns) fn();
      this._teardowns = [];
      delete this._root._hearthMounted;
    }
  }

  // =========================================================================
  // Registry + auto-mounter
  // =========================================================================

  const _registry = Object.create(null);

  /** Register a component class under the given name. */
  function register(name, cls) {
    _registry[name] = cls;
  }

  /** Mount all unmounted [data-component] elements within root (or document). */
  function mountAll(root) {
    const els = (root || document).querySelectorAll('[data-component]');
    for (const el of els) {
      if (el._hearthMounted) continue;
      const Cls = _registry[el.dataset.component];
      if (!Cls) continue;
      el._hearthMounted = true;
      try { new Cls(el); }
      catch (e) { console.error('[hearth-components]', el.dataset.component, e); }
    }
  }

  document.addEventListener('DOMContentLoaded', () => mountAll(document));
  document.addEventListener('htmx:afterSwap', (e) => mountAll(e.target));

  // =========================================================================
  // Disclosure — toggle .hidden on a target element
  //
  // data-target="#id"           target element by CSS selector
  // data-target-next            (presence) use nextElementSibling as target
  // data-label-open="..."       label text when target is visible
  // data-label-close="..."      label text when target is hidden
  // data-label-target="#id"     element to update with label (default: root)
  // =========================================================================

  class Disclosure extends Component {
    constructor(root) {
      super(root);
      const target = root.dataset.target
        ? document.querySelector(root.dataset.target)
        : ('targetNext' in root.dataset ? root.nextElementSibling : null);
      if (!target) return;

      // data-also-hide="#id" — element to always hide when toggling target
      const alsoHide = root.dataset.alsoHide
        ? document.querySelector(root.dataset.alsoHide)
        : null;

      this.on(root, 'click', () => {
        const nowHidden = target.classList.toggle('hidden');
        const open = !nowHidden;
        if (alsoHide) alsoHide.classList.add('hidden');
        const { labelOpen, labelClose, labelTarget: labelSel } = root.dataset;
        if (labelOpen && labelClose) {
          const labelEl = labelSel ? document.querySelector(labelSel) : root;
          if (labelEl) labelEl.textContent = open ? labelOpen : labelClose;
        }
      });
    }
  }
  register('disclosure', Disclosure);

  // =========================================================================
  // Reveal — toggle .hidden on target + rotate/transform a chevron
  //
  // data-target="#id"           target panel (default: nextElementSibling)
  // data-chevron="#id"          chevron element (default: first <svg> in root)
  // data-chevron-class="..."    CSS class to toggle on chevron (default: rotate-180)
  // data-title-open="..."       root title attribute when open
  // data-title-close="..."      root title attribute when closed
  // =========================================================================

  class Reveal extends Component {
    constructor(root) {
      super(root);
      const target = root.dataset.target
        ? document.querySelector(root.dataset.target)
        : root.nextElementSibling;
      const chevron = root.dataset.chevron
        ? document.querySelector(root.dataset.chevron)
        : root.querySelector('svg');
      const chevronClass = root.dataset.chevronClass || 'rotate-180';

      if (!target) return;

      this.on(root, 'click', () => {
        const nowHidden = target.classList.toggle('hidden');
        const open = !nowHidden;
        if (chevron) chevron.classList.toggle(chevronClass, open);
        if (root.dataset.titleOpen && root.dataset.titleClose) {
          root.title = open ? root.dataset.titleOpen : root.dataset.titleClose;
        }
      });
    }
  }
  register('reveal', Reveal);

  // =========================================================================
  // Tabs — show/hide panels by tab name
  //
  // Tab buttons: [data-tab="name"]        inside root
  // Tab panels:  [data-tab-panel="name"]  inside root
  // Initial tab: aria-selected="true"     on the pre-selected button
  // =========================================================================

  class Tabs extends Component {
    constructor(root) {
      super(root);
      const buttons = this.$$('[data-tab]');
      const panels  = this.$$('[data-tab-panel]');
      // data-active-class="cls" — extra class toggled on the active tab button
      const activeClass = root.dataset.activeClass || '';

      const activate = (name) => {
        for (const btn of buttons) {
          const isActive = btn.dataset.tab === name;
          btn.setAttribute('aria-selected', String(isActive));
          if (activeClass) btn.classList.toggle(activeClass, isActive);
        }
        for (const panel of panels) {
          panel.classList.toggle('hidden', panel.dataset.tabPanel !== name);
        }
      };

      for (const btn of buttons) {
        this.on(btn, 'click', () => activate(btn.dataset.tab));
      }

      const initial = buttons.find(b => b.getAttribute('aria-selected') === 'true');
      activate(initial ? initial.dataset.tab : (buttons[0] ? buttons[0].dataset.tab : ''));
    }
  }
  register('tabs', Tabs);

  // =========================================================================
  // CopyToClipboard — copy text from a source element to the clipboard
  //
  // data-source="#id"           element whose .value or .textContent to copy
  // data-copied-label="..."     temporary button label after copy (default: "Copied!")
  // =========================================================================

  class CopyToClipboard extends Component {
    constructor(root) {
      super(root);
      this.on(root, 'click', async () => {
        const src = root.dataset.source ? document.querySelector(root.dataset.source) : null;
        if (!src) return;
        const text = src.value !== undefined ? src.value : src.textContent;
        await navigator.clipboard.writeText(text);
        const orig = root.textContent;
        root.textContent = root.dataset.copiedLabel || 'Copied!';
        setTimeout(() => { root.textContent = orig; }, 2000);
      });
    }
  }
  register('copy-to-clipboard', CopyToClipboard);

  // =========================================================================
  // Confirm — gate a click with window.confirm()
  //
  // data-message="..."          dialog message (default: "Are you sure?")
  // =========================================================================

  class Confirm extends Component {
    constructor(root) {
      super(root);
      // Capture phase so we intercept before HTMX and other handlers.
      const handler = (e) => {
        const msg = root.dataset.message || 'Are you sure?';
        if (!window.confirm(msg)) {
          e.preventDefault();
          e.stopImmediatePropagation();
        }
      };
      root.addEventListener('click', handler, true);
      this._teardowns.push(() => root.removeEventListener('click', handler, true));
    }
  }
  register('confirm', Confirm);

  // =========================================================================
  // TwoStepConfirm — visual two-step confirmation with auto-reset
  //
  // data-confirm-label="..."    label in confirm state (default: "Confirm?")
  // data-confirm-class="..."    class applied in confirm state
  // data-timeout="4000"         ms before auto-reset (default: 4000)
  // =========================================================================

  class TwoStepConfirm extends Component {
    constructor(root) {
      super(root);
      let confirming = false;
      let timer = null;
      const origLabel  = root.textContent.trim();
      const origClass  = root.className;
      const confirmLabel = root.dataset.confirmLabel || 'Confirm?';
      const confirmClass = root.dataset.confirmClass || '';
      const timeout      = parseInt(root.dataset.timeout || '4000', 10);

      const reset = () => {
        clearTimeout(timer);
        confirming = false;
        root.textContent = origLabel;
        if (confirmClass) root.className = origClass;
      };

      // Capture phase so we intercept before HTMX and other handlers.
      const handler = (e) => {
        if (confirming) {
          reset();
          return; // let the click proceed naturally on second click
        }
        e.preventDefault();
        e.stopImmediatePropagation();
        confirming = true;
        root.textContent = confirmLabel;
        if (confirmClass) root.className = confirmClass;
        timer = setTimeout(reset, timeout);
      };

      root.addEventListener('click', handler, true);
      this._teardowns.push(() => root.removeEventListener('click', handler, true));
    }
  }
  register('two-step-confirm', TwoStepConfirm);

  // =========================================================================
  // TypeToConfirm — enable a target element only when input matches
  //
  // data-match="..."            string the input value must equal
  // data-target="#id"           element to enable/disable (e.g. a submit button)
  // =========================================================================

  class TypeToConfirm extends Component {
    constructor(root) {
      super(root);
      const match  = root.dataset.match || '';
      const target = root.dataset.target ? document.querySelector(root.dataset.target) : null;
      if (!target) return;
      target.disabled = true;
      this.on(root, 'input', () => {
        target.disabled = root.value !== match;
      });
      // Prevent Enter-key submission when value does not yet match.
      this.on(root, 'keydown', (e) => {
        if (e.key === 'Enter' && root.value !== match) e.preventDefault();
      });
    }
  }
  register('type-to-confirm', TypeToConfirm);

  // =========================================================================
  // ShowDialog — open and close a <dialog> element
  //
  // data-target="#id"           dialog element to open
  // data-focus="#id"            element to focus after open (default: dialog)
  // data-action="close"         variant: close the nearest <dialog> ancestor
  // =========================================================================

  class ShowDialog extends Component {
    constructor(root) {
      super(root);

      if (root.dataset.action === 'close') {
        this.on(root, 'click', () => {
          const dlg = root.closest('dialog');
          if (dlg) dlg.close();
        });
        return;
      }

      const dlg = root.dataset.target ? document.querySelector(root.dataset.target) : null;
      if (!dlg) return;

      // Backdrop click closes the dialog.
      this.on(dlg, 'click', (e) => {
        if (e.target === dlg) dlg.close();
      });

      this.on(root, 'click', () => {
        if (dlg.showModal) dlg.showModal();
        else dlg.removeAttribute('hidden');
        const focusEl = root.dataset.focus ? document.querySelector(root.dataset.focus) : dlg;
        focusEl?.focus();
      });
    }
  }
  register('show-dialog', ShowDialog);

  // =========================================================================
  // ScopeSelector — radio + org picker + composed hidden field
  //
  // [data-scope-radio]          radio buttons (inside root)
  // [data-scope-org-select]     org <select> (inside root)
  // [data-scope-org-panel]      panel shown when scope === 'org' (inside root)
  // [data-scope-value]          hidden <input> receiving composed value (inside root)
  // =========================================================================

  class ScopeSelector extends Component {
    constructor(root) {
      super(root);
      const radios      = this.$$('[data-scope-radio]');
      // data-scope-select — alternative to radio buttons: a <select> whose
      // value is 'realm' or 'org'.  Takes precedence over radios when present.
      const scopeSelect = this.$('[data-scope-select]');
      const orgSelect   = this.$('[data-scope-org-select]');
      const orgPanel    = this.$('[data-scope-org-panel]');
      const valueEl     = this.$('[data-scope-value]');

      const sync = () => {
        let scope;
        if (scopeSelect) {
          scope = scopeSelect.value;
        } else {
          const active = radios.find(r => r.checked);
          scope = active ? active.value : '';
        }
        const isOrg = scope === 'org';
        orgPanel?.classList.toggle('hidden', !isOrg);
        if (valueEl) {
          valueEl.value = isOrg && orgSelect ? 'org:' + orgSelect.value : scope;
        }
      };

      if (scopeSelect) {
        this.on(scopeSelect, 'change', sync);
      } else {
        for (const r of radios) this.on(r, 'change', sync);
      }
      if (orgSelect) this.on(orgSelect, 'change', sync);
      sync();
    }
  }
  register('scope-selector', ScopeSelector);

  // =========================================================================
  // SubmitState — show loading indicator when a form submits
  //
  // data-loading="#id"          element to show on submit
  // data-content="#id"          element to hide on submit
  // =========================================================================

  class SubmitState extends Component {
    constructor(root) {
      super(root);
      const loading = root.dataset.loading ? document.querySelector(root.dataset.loading) : null;
      const content = root.dataset.content ? document.querySelector(root.dataset.content) : null;
      if (!loading && !content) return;
      this.on(root, 'submit', () => {
        loading?.classList.remove('hidden');
        content?.classList.add('hidden');
      });
    }
  }
  register('submit-state', SubmitState);

  // =========================================================================
  // HideTarget — on click, add .hidden to a target element
  //
  // data-target="#id"           element to hide
  // =========================================================================

  class HideTarget extends Component {
    constructor(root) {
      super(root);
      const target = root.dataset.target ? document.querySelector(root.dataset.target) : null;
      if (!target) return;
      this.on(root, 'click', () => target.classList.add('hidden'));
    }
  }
  register('hide-target', HideTarget);

  // =========================================================================
  // ValueReveal — show/hide a target based on a <select> value
  //
  // data-show-when="value"      show target when select value equals this
  // data-target="#id"           element to show or hide
  // =========================================================================

  class ValueReveal extends Component {
    constructor(root) {
      super(root);
      const target   = root.dataset.target ? document.querySelector(root.dataset.target) : null;
      const showWhen = root.dataset.showWhen;
      if (!target || !showWhen) return;
      const sync = () => target.classList.toggle('hidden', root.value !== showWhen);
      this.on(root, 'change', sync);
      sync();
    }
  }
  register('value-reveal', ValueReveal);

  // =========================================================================
  // AuditExpand — expand/collapse an audit detail <tr>
  //
  // No data attributes needed: finds closest [data-audit-row] and its
  // next sibling [data-audit-detail] by DOM position.
  // =========================================================================

  class AuditExpand extends Component {
    constructor(root) {
      super(root);
      const row    = root.closest('[data-audit-row]');
      const detail = row ? row.nextElementSibling : null;
      if (!row || !detail) return;

      this.on(root, 'click', () => {
        const nowHidden = detail.classList.toggle('hidden');
        const expanded  = !nowHidden;
        row.classList.toggle('bg-ht-surface-overlay', expanded);
        root.classList.toggle('rotate-90', expanded);
        root.setAttribute('aria-expanded', String(expanded));
        root.setAttribute('aria-label', expanded ? 'Collapse event detail' : 'Expand event detail');
      });
    }
  }
  register('audit-expand', AuditExpand);

  // =========================================================================
  // AutocompleteInput — show a dropdown on focus/input; optionally sync
  // the typed value to a hidden field
  //
  // data-target="#id"           dropdown element to show
  // data-sync-to="#id"          hidden input to keep in sync (optional)
  // =========================================================================

  class AutocompleteInput extends Component {
    constructor(root) {
      super(root);
      const target = root.dataset.target ? document.querySelector(root.dataset.target) : null;
      const syncEl = root.dataset.syncTo  ? document.querySelector(root.dataset.syncTo)  : null;
      if (!target) return;
      const show = () => target.classList.remove('hidden');
      this.on(root, 'focus', show);
      this.on(root, 'input', () => {
        if (syncEl) syncEl.value = root.value;
        show();
      });
    }
  }
  register('autocomplete-input', AutocompleteInput);

  // =========================================================================
  // DismissOutside — add .hidden to self when a click occurs outside
  // =========================================================================

  class DismissOutside extends Component {
    constructor(root) {
      super(root);
      const handler = (e) => {
        if (!root.contains(e.target)) root.classList.add('hidden');
      };
      // Use capture so we see the click before other handlers consume it.
      document.addEventListener('click', handler, true);
      this._teardowns.push(() => document.removeEventListener('click', handler, true));
    }
  }
  register('dismiss-outside', DismissOutside);

  // Expose for external use / debugging
  window.HearthComponents = { register, mountAll };

})();
