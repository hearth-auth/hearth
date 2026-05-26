// Hearth admin UI behaviours — Alpine-free, CSP `script-src 'self'` safe.
//
// Layout reactivity (sidebar, realm nav, toasts, realm pill) is handled by
// vanilla JS classes below. Tab/form interactivity uses Hyperscript `_="..."`
// attributes directly in templates (see HEA-850).

// =========================================================================
// SidebarManager — mobile sidebar toggle
// =========================================================================

class SidebarManager {
  constructor() {
    this.sidebar = document.getElementById('sidebar');
    this.overlay = document.getElementById('sidebar-overlay');
    this.toggle  = document.getElementById('sidebar-toggle');
    if (!this.sidebar) return;

    this.toggle?.addEventListener('click', () => this.open());
    this.overlay?.addEventListener('click', () => this.close());
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') this.close();
    });
  }

  open() {
    this.sidebar.classList.remove('-translate-x-full');
    this.overlay?.classList.remove('hidden');
  }

  close() {
    this.sidebar.classList.add('-translate-x-full');
    this.overlay?.classList.add('hidden');
  }
}

// =========================================================================
// RealmNav — sidebar realm tree (fetches /ui/admin/api/nav/realms)
// =========================================================================

class RealmNav {
  constructor(container) {
    this.container  = container;
    this.loading    = document.getElementById('realm-nav-loading');
    if (!this.container) return;

    this.activePage   = container.dataset.activePage || '';
    const m           = window.location.pathname.match(/^\/ui\/admin\/realms\/([^\/?#]+)(?:\/|$)/);
    this.currentRealm = m ? decodeURIComponent(m[1]) : '';

    this.subPages = [
      { key: 'overview',           label: 'Overview',           href: '/ui/admin/realms/{realm}' },
      { key: 'users',              label: 'Users',              href: '/ui/admin/realms/{realm}/users' },
      { key: 'organizations',      label: 'Organizations',      href: '/ui/admin/realms/{realm}/organizations' },
      { key: 'groups',             label: 'Groups',             href: '/ui/admin/realms/{realm}/groups' },
      { key: 'applications',       label: 'Applications',       href: '/ui/admin/realms/{realm}/applications' },
      { key: 'identity_providers', label: 'Identity Providers', href: '/ui/admin/realms/{realm}/identity-providers' },
      { key: 'sessions',           label: 'Sessions',           href: '/ui/admin/realms/{realm}/sessions' },
      { key: 'webhooks',           label: 'Webhooks',           href: '/ui/admin/realms/{realm}/webhooks' },
      { key: 'audit',              label: 'Audit Log',          href: '/ui/admin/realms/{realm}/audit' },
      { key: 'rbac_permissions',   label: 'Permissions',        href: '/ui/admin/realms/{realm}/rbac/permissions' },
      { key: 'rbac_roles',         label: 'Roles',              href: '/ui/admin/realms/{realm}/rbac/roles' },
      { key: 'rbac_scopes',        label: 'Scopes',             href: '/ui/admin/realms/{realm}/rbac/scopes' },
      { key: 'rbac_debug',         label: 'Permission Check',   href: '/ui/admin/realms/{realm}/rbac/debug' },
    ];
    this._load();
  }

  async _load() {
    try {
      const res = await fetch('/ui/admin/api/nav/realms', { credentials: 'same-origin' });
      if (!res.ok) throw new Error('nav fetch failed');
      const data = await res.json();
      this._render(data.realms || []);
    } catch {
      if (this.loading) this.loading.textContent = 'Could not load realms.';
    }
  }

  _render(realms) {
    this.loading?.remove();

    if (realms.length === 0) {
      const p = document.createElement('p');
      p.className = 'px-2 text-xs text-ht-content-muted';
      p.textContent = 'No realms.';
      this.container.appendChild(p);
      return;
    }

    const list = document.createElement('ul');
    list.className = 'space-y-0.5';

    for (const r of realms) {
      const isCurrent = r.name === this.currentRealm;
      const li = document.createElement('li');

      // ── Expand button ──────────────────────────────────────────────
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm font-medium hover-bg-divider '
        + (isCurrent ? 'text-ht-content-primary' : 'text-ht-content-secondary hover:text-ht-content-primary');

      const chevronSvg = this._svg(
        'M9 18 15 12 9 6', 'polyline',
        'h-3 w-3 shrink-0 transition-transform' + (isCurrent ? ' rotate-90' : '')
      );
      const realmIcon = this._bldgSvg();
      const nameSpan = document.createElement('span');
      nameSpan.textContent = r.name;
      if (r.archived) nameSpan.className = 'text-ht-content-muted line-through';

      btn.append(chevronSvg, realmIcon, nameSpan);

      if (r.archived) {
        const badge = document.createElement('span');
        badge.className = 'ml-auto rounded bg-steel-bg px-1.5 py-0.5 text-[10px] font-medium uppercase text-steel-fg';
        badge.textContent = 'archived';
        btn.appendChild(badge);
      }

      // ── Sub-pages list ─────────────────────────────────────────────
      const subUl = document.createElement('ul');
      subUl.className = 'ml-3 mt-0.5 space-y-0.5 border-l border-divider pl-2';
      if (!isCurrent) subUl.classList.add('hidden');

      for (const page of this.subPages) {
        const isActive = isCurrent && page.key === this.activePage;
        const subLi = document.createElement('li');
        const a = document.createElement('a');
        a.href = page.href.replace('{realm}', encodeURIComponent(r.name));
        a.className = 'flex items-center gap-2 rounded-md px-2 py-1 text-sm '
          + (isActive
            ? 'bg-divider text-ht-content-primary font-medium border-l-2 border-brand'
            : 'text-ht-content-secondary hover:text-ht-content-primary hover-bg-divider');
        if (isActive) a.setAttribute('aria-current', 'page');
        a.textContent = page.label;
        subLi.appendChild(a);
        subUl.appendChild(subLi);
      }

      btn.addEventListener('click', () => {
        const open = !subUl.classList.contains('hidden');
        subUl.classList.toggle('hidden', open);
        chevronSvg.classList.toggle('rotate-90', !open);
      });

      li.append(btn, subUl);
      list.appendChild(li);
    }
    this.container.appendChild(list);
  }

  _svg(points, tag, cls) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2.5');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('class', cls);
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    el.setAttribute('points', points);
    svg.appendChild(el);
    return svg;
  }

  _bldgSvg() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('class', 'h-4 w-4 shrink-0');
    svg.innerHTML = '<rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>';
    return svg;
  }
}

// =========================================================================
// ToastManager — listens for `show-toast` custom events
// =========================================================================

class ToastManager {
  constructor() {
    this.container = document.getElementById('toast-container');
    window.addEventListener('show-toast', (e) => this.show(e.detail.message, e.detail.kind));
  }

  show(message, kind) {
    if (!this.container) return;
    const el = document.createElement('div');
    el.className = 'animate-toast-in rounded px-4 py-3 text-sm font-medium shadow-md '
      + (kind === 'error' ? 'bg-danger text-ht-content-primary' : 'bg-success text-ht-content-primary');
    el.textContent = message;
    this.container.appendChild(el);
    setTimeout(() => el.remove(), 5000);
  }
}

// =========================================================================
// Realm pill — shows current realm slug in the top bar
// =========================================================================

function initRealmPill() {
  const pill = document.getElementById('realm-pill');
  const text = document.getElementById('realm-pill-text');
  if (!pill || !text) return;
  const m = window.location.pathname.match(/\/ui\/admin\/realms\/([^\/?#]+)/);
  if (m) {
    text.textContent = decodeURIComponent(m[1]);
    pill.classList.remove('hidden');
  }
}

// =========================================================================
// Realm wizard — auto-slugs display name → realm name
// =========================================================================

function initRealmWizard() {
  const form = document.querySelector('[data-realm-wizard]');
  if (!form) return;

  const displayInput = form.querySelector('#display_name');
  const realmInput   = form.querySelector('#realm_name');
  if (!displayInput || !realmInput) return;

  let nameTouched = realmInput.dataset.realmNameTouched === 'true';

  function toSlug(s) {
    return s.toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 63);
  }

  displayInput.addEventListener('input', () => {
    if (!nameTouched) {
      realmInput.value = toSlug(displayInput.value);
    }
  });

  realmInput.addEventListener('input', () => {
    nameTouched = true;
    realmInput.dataset.realmNameTouched = 'true';
  });
}

// =========================================================================
// Org list bulk actions — checkbox selection + confirm-delete
// =========================================================================

function initOrgListBulkActions() {
  const form       = document.getElementById('org-bulk-form');
  const allCheck   = document.getElementById('org-all-check');
  const idsInput   = document.getElementById('org-ids-input');
  const actionsEl  = document.getElementById('org-bulk-actions');
  const countLabel = document.getElementById('org-count-label');
  const deleteBtn  = document.getElementById('org-delete-btn');
  if (!form || !allCheck) return;

  const allLabel   = countLabel?.dataset.allLabel || '';
  const normalCls  = deleteBtn?.dataset.normalClass || '';
  const dangerCls  = deleteBtn?.dataset.dangerClass || '';
  let confirmTimer = null;
  let confirming   = false;

  function getCheckedIds() {
    return Array.from(form.querySelectorAll('.row-check:checked')).map(el => el.value);
  }

  function updateState() {
    const ids    = getCheckedIds();
    const total  = form.querySelectorAll('.row-check').length;
    const count  = ids.length;

    if (idsInput) idsInput.value = ids.join(',');
    if (actionsEl) actionsEl.classList.toggle('hidden', count === 0);
    if (countLabel) {
      countLabel.textContent = count > 0 ? `${count} selected` : allLabel;
    }
    if (allCheck) {
      allCheck.checked       = count > 0 && count === total;
      allCheck.indeterminate = count > 0 && count < total;
    }
    // Reset confirm state if selection changes
    if (confirming) resetDelete();
  }

  function resetDelete() {
    confirming = false;
    clearTimeout(confirmTimer);
    if (deleteBtn) {
      deleteBtn.className   = normalCls;
      deleteBtn.textContent = 'Delete selected';
    }
  }

  allCheck.addEventListener('change', () => {
    form.querySelectorAll('.row-check').forEach(cb => { cb.checked = allCheck.checked; });
    updateState();
  });

  form.addEventListener('change', (e) => {
    if (e.target.classList.contains('row-check')) updateState();
  });

  deleteBtn?.addEventListener('click', () => {
    if (confirming) {
      form.submit();
    } else {
      confirming = true;
      if (deleteBtn) {
        deleteBtn.className   = dangerCls;
        deleteBtn.textContent = 'Confirm? Click again';
      }
      confirmTimer = setTimeout(resetDelete, 4000);
    }
  });
}

// =========================================================================
// Roles tab — permissions preview on role select change
// =========================================================================

function initRolesTab(container) {
  if (!container) return;
  const data = readJsonScript('roles-tab-bootstrap');
  if (!data) return;

  const rolePerms   = data.rolePerms  || {};
  const select      = container.querySelector('#role-select');
  const preview     = container.querySelector('#role-perms-preview');
  const chips       = container.querySelector('#role-perms-chips');
  const emptyMsg    = container.querySelector('#role-perms-empty');
  if (!select || !preview || !chips || !emptyMsg) return;

  function updatePreview(roleId) {
    const perms = rolePerms[roleId] || [];
    if (perms.length > 0) {
      chips.innerHTML = perms.map(p =>
        `<span class="inline-flex items-center rounded-full bg-violet-bg px-2 py-0.5 font-mono text-xs text-violet-fg">${escHtml(p)}</span>`
      ).join('');
      preview.classList.remove('hidden');
      emptyMsg.classList.add('hidden');
    } else if (roleId) {
      preview.classList.add('hidden');
      emptyMsg.classList.remove('hidden');
    } else {
      preview.classList.add('hidden');
      emptyMsg.classList.add('hidden');
    }
  }

  select.addEventListener('change', () => updatePreview(select.value));
  // Show preview for the initially selected role
  updatePreview(select.value);
}

// =========================================================================
// Password strength meter (reset_password.html)
// =========================================================================

function initPasswordStrength() {
  const form = document.querySelector('[data-password-strength]');
  if (!form) return;

  const pwInput    = form.querySelector('#password');
  const cfmInput   = form.querySelector('#password_confirm');
  const indicator  = form.querySelector('#password-strength-indicator');
  const bar        = form.querySelector('#password-strength-bar');
  const label      = form.querySelector('#password-strength-text');
  const matchErr   = form.querySelector('#password-match-error');
  const submitBtn  = form.querySelector('#pw-submit-btn');
  if (!pwInput || !cfmInput) return;

  const BAR_COLORS   = ['', 'bg-danger', 'bg-warning', 'bg-info', 'bg-success'];
  const TEXT_COLORS  = ['text-ht-content-muted', 'text-danger-fg', 'text-warning-fg', 'text-info-fg', 'text-success-fg'];
  const LABELS       = ['', 'Weak — too easy to guess', 'Fair — try adding numbers or symbols', 'Good', 'Strong'];

  function calcStrength(pw) {
    if (!pw) return 0;
    let s = 0;
    if (pw.length >= 8)  s++;
    if (pw.length >= 12) s++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
    if (/[0-9]/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    return Math.min(4, s);
  }

  function checkMatch() {
    const mismatch = cfmInput.value.length > 0 && pwInput.value !== cfmInput.value;
    matchErr?.classList.toggle('hidden', !mismatch);
    cfmInput.classList.toggle('border-danger', mismatch);
    if (submitBtn) submitBtn.disabled = mismatch;
  }

  pwInput.addEventListener('input', () => {
    const pw = pwInput.value;
    if (indicator) indicator.classList.toggle('hidden', pw.length === 0);
    if (pw.length > 0 && bar && label) {
      const s = calcStrength(pw);
      bar.style.width  = `${s * 25}%`;
      bar.className    = 'h-full rounded-full transition-all duration-300 ease-out' + (s > 0 ? ` ${BAR_COLORS[s]}/[0.7]` : '');
      label.className  = `mt-1 text-xs ${TEXT_COLORS[s]}`;
      label.textContent = LABELS[s];
    }
    checkMatch();
  });

  cfmInput.addEventListener('input', checkMatch);

  form.addEventListener('submit', (e) => {
    if (pwInput.value !== cfmInput.value) {
      e.preventDefault();
      checkMatch();
    }
  });
}

// =========================================================================
// Attr rows — dynamic key/value rows in user edit (users/edit.html)
// =========================================================================

function initAttrRows() {
  document.addEventListener('click', (e) => {
    // Add row
    const addBtn = e.target.closest('[data-add-attr-row]');
    if (addBtn) {
      const container = addBtn.closest('[data-attr-rows]');
      if (!container) return;
      const rows = container.querySelector('#attr-rows');
      if (!rows) return;
      const row = document.createElement('div');
      row.className = 'flex gap-2 items-center attr-row';
      row.innerHTML = '<input type="text" name="attr_key" placeholder="key" class="input flex-1">'
        + '<input type="text" name="attr_val" placeholder="value" class="input flex-1">'
        + '<button type="button" data-remove-attr-row class="text-ht-content-muted hover:text-danger-fg text-sm px-2">\u2715</button>';
      rows.appendChild(row);
    }

    // Remove row
    const removeBtn = e.target.closest('[data-remove-attr-row]');
    if (removeBtn) {
      removeBtn.closest('.attr-row')?.remove();
    }
  });
}

// =========================================================================
// Config Editor — standalone class (no Alpine, no unsafe-eval)
// =========================================================================
//
// Mounted by editor.html via:
//   new ConfigEditor().init(document.getElementById('config-editor-root'))
//
// DOM protocol:
//   - Static sections use data-bind="dotted.path" / data-bind-bool="..."
//   - Error messages use data-error-for="dotted.path"
//   - Lists use data-list-container="path" + data-list-add="path"
//   - Email transport subsections use data-show-transport="<value>"
//   - Realm section is entirely rendered by _renderRealmSection()

class ConfigEditor {
  constructor() {
    this.mode = 'visual';
    this.activeSection = 'server';
    this.activeRealm = null;
    this.config = {};
    this.originalConfig = '{}';
    this.csrf = '';
    this.saving = false;
    this.errors = {};
    this.validating = false;
    this.validationPassed = false;
    this.showingExport = false;
    this.exportCopied = false;
    this.exportYaml = '';
    this.exportLoading = false;
    this._root = null;
  }

  init(root) {
    if (!root) return;
    this._root = root;

    const fallback = document.getElementById('ssr-editor-fallback');
    if (fallback) fallback.classList.add('hidden');
    root.classList.remove('hidden');

    const initialConfig = readJsonScript('config-editor-data') || {};
    this.config = JSON.parse(JSON.stringify(initialConfig));
    this.originalConfig = JSON.stringify(initialConfig);
    this.csrf = document.querySelector('meta[name="csrf"]')?.content || '';

    const params = new URLSearchParams(window.location.search);
    const linkedSection = params.get('section');
    const linkedRealm = params.get('realm_key');
    if (linkedSection === 'realms' && linkedRealm) {
      this.activeRealm = linkedRealm;
      this.activeSection = 'realm';
    } else if (linkedSection) {
      this.activeSection = linkedSection;
    }

    this._buildSidebar();
    this._switchSection(this.activeSection, this.activeRealm);
    this._attachListeners();
    this._setMode('visual');
  }

  _sectionDefs() {
    return [
      { key: 'server',       label: 'Server' },
      { key: 'storage',      label: 'Storage' },
      { key: 'observability', label: 'Logging' },
      { key: 'operational',  label: 'Limits' },
      { key: 'branding',     label: 'Branding' },
      { key: 'email',        label: 'Email' },
      { key: 'oidc',         label: 'OIDC' },
      { key: 'token',        label: 'Tokens' },
      { key: 'auth',         label: 'Auth' },
      { key: 'onboarding',   label: 'Onboarding' },
    ];
  }

  _buildSidebar() {
    const nav = document.getElementById('config-sections-nav');
    if (!nav) return;
    const readOnly = this._root.dataset.readOnly === 'true';
    const ACTIVE = 'bg-divider text-ht-content-primary';
    const INACTIVE = 'text-ht-content-secondary hover-bg-divider hover:text-ht-content-primary';

    nav.innerHTML = '<p class="mb-2 font-mono text-[11px] font-medium uppercase tracking-[0.12em] text-ht-content-muted">Sections</p>';

    for (const sec of this._sectionDefs()) {
      const isActive = sec.key === this.activeSection && !this.activeRealm;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.dataset.navSection = sec.key;
      btn.className = `block w-full rounded-md px-2 py-1.5 text-left text-sm font-medium transition-colors ${isActive ? ACTIVE : INACTIVE}`;
      btn.textContent = sec.label;
      btn.addEventListener('click', () => {
        this.activeSection = sec.key;
        this.activeRealm = null;
        this._updateSidebarActive();
        this._switchSection(sec.key, null);
      });
      nav.appendChild(btn);
    }

    const realmDiv = document.createElement('div');
    realmDiv.className = 'mt-4 border-t border-divider-subtle pt-3';
    realmDiv.innerHTML = '<p class="mb-2 font-mono text-[11px] font-medium uppercase tracking-[0.12em] text-ht-content-muted">Realms</p>';

    const realmBtns = document.createElement('div');
    realmBtns.id = 'realm-nav-buttons';
    realmDiv.appendChild(realmBtns);

    if (!readOnly) {
      const addBtn = document.createElement('button');
      addBtn.type = 'button';
      addBtn.id = 'add-realm-btn';
      addBtn.className = 'mt-1 flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-xs font-medium text-teal-fg hover-bg-divider';
      addBtn.innerHTML = '<svg class="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Add Realm';
      addBtn.addEventListener('click', () => this._handleAddRealm());
      realmDiv.appendChild(addBtn);
    }
    nav.appendChild(realmDiv);
    this._refreshRealmNav();
  }

  _refreshRealmNav() {
    const container = document.getElementById('realm-nav-buttons');
    if (!container) return;
    const ACTIVE = 'bg-divider text-ht-content-primary';
    const INACTIVE = 'text-ht-content-secondary hover-bg-divider hover:text-ht-content-primary';
    container.innerHTML = '';
    for (const rk of Object.keys(this.config.realms || {})) {
      const isActive = this.activeSection === 'realm' && this.activeRealm === rk;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.dataset.navRealm = rk;
      btn.className = `block w-full rounded-md px-2 py-1.5 text-left text-sm font-medium transition-colors ${isActive ? ACTIVE : INACTIVE}`;
      btn.textContent = rk;
      btn.addEventListener('click', () => {
        this.activeSection = 'realm';
        this.activeRealm = rk;
        this._updateSidebarActive();
        this._switchSection('realm', rk);
      });
      container.appendChild(btn);
    }
  }

  _updateSidebarActive() {
    const ACTIVE = 'bg-divider text-ht-content-primary';
    const INACTIVE = 'text-ht-content-secondary hover-bg-divider hover:text-ht-content-primary';
    document.querySelectorAll('[data-nav-section]').forEach(btn => {
      const isActive = btn.dataset.navSection === this.activeSection && !this.activeRealm;
      btn.className = `block w-full rounded-md px-2 py-1.5 text-left text-sm font-medium transition-colors ${isActive ? ACTIVE : INACTIVE}`;
    });
    document.querySelectorAll('[data-nav-realm]').forEach(btn => {
      const isActive = this.activeSection === 'realm' && btn.dataset.navRealm === this.activeRealm;
      btn.className = `block w-full rounded-md px-2 py-1.5 text-left text-sm font-medium transition-colors ${isActive ? ACTIVE : INACTIVE}`;
    });
  }

  _switchSection(section, realm) {
    document.querySelectorAll('[data-section]').forEach(el => el.classList.add('hidden'));
    if (section === 'realm' && realm) {
      const el = document.getElementById('realm-section');
      if (el) { el.classList.remove('hidden'); this._renderRealmSection(realm); }
    } else {
      const el = document.querySelector(`[data-section="${CSS.escape(section)}"]`);
      if (el) { el.classList.remove('hidden'); this._populateSection(el); }
    }
  }

  _populateSection(container) {
    container.querySelectorAll('[data-bind]').forEach(el => {
      const val = this.getVal(el.dataset.bind, '');
      el.value = val !== undefined && val !== null ? String(val) : '';
    });
    container.querySelectorAll('[data-bind-bool]').forEach(sel => {
      const val = this.getVal(sel.dataset.bindBool, null);
      sel.value = val === true ? 'true' : val === false ? 'false' : '';
    });
    container.querySelectorAll('[data-error-for]').forEach(el => {
      const msg = this.errors[el.dataset.errorFor];
      if (msg) { el.textContent = msg; el.classList.remove('hidden'); }
      else { el.textContent = ''; el.classList.add('hidden'); }
    });
    container.querySelectorAll('[data-list-container]').forEach(el => {
      this._renderList(el, el.dataset.listContainer);
    });
    const transportSel = container.querySelector('[data-bind="email.transport"]');
    if (transportSel) this._updateTransportVisibility(transportSel.value, container);
  }

  _updateTransportVisibility(transport, container) {
    container.querySelectorAll('[data-show-transport]').forEach(el => {
      el.classList.toggle('hidden', el.dataset.showTransport !== transport);
    });
  }

  _renderList(container, path) {
    const items = this.getList(path);
    container.innerHTML = '';
    items.forEach((item, idx) => {
      const row = document.createElement('div');
      row.className = 'flex gap-2 mt-1';
      const inp = document.createElement('input');
      inp.type = 'text';
      inp.value = String(item);
      inp.className = 'input flex-1 font-mono text-sm';
      inp.addEventListener('input', () => {
        const parts = path.split('.');
        let obj = this.config;
        for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
        obj[parts[parts.length - 1]][idx] = inp.value;
      });
      const rmBtn = document.createElement('button');
      rmBtn.type = 'button';
      rmBtn.className = 'shrink-0 text-ht-content-muted hover:text-danger-fg';
      rmBtn.setAttribute('aria-label', 'Remove');
      rmBtn.innerHTML = '<svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
      rmBtn.addEventListener('click', () => { this.removeListItem(path, idx); this._renderList(container, path); });
      row.appendChild(inp);
      row.appendChild(rmBtn);
      container.appendChild(row);
    });
  }

  _renderRealmSection(realm) {
    const section = document.getElementById('realm-section');
    if (!section) return;
    const rc = (this.config.realms || {})[realm] || {};
    const readOnly = this._root.dataset.readOnly === 'true';
    const apps = Object.entries(rc.applications || {});
    const orgs = Object.entries(rc.organizations || {});

    const appRows = apps.length === 0
      ? '<p class="text-xs text-ht-content-muted">No applications defined.</p>'
      : apps.map(([key, app]) => `
          <div class="flex items-center gap-2 rounded-sm border border-divider-subtle bg-ht-surface-base px-3 py-2">
            <span class="flex-1 font-mono text-xs text-ht-content-secondary">${escHtml(key)}</span>
            <span class="text-xs text-ht-content-muted">${escHtml(app.name || key)}</span>
            ${readOnly ? '' : `<button type="button" data-remove-app="${escAttr(realm)}" data-app-key="${escAttr(key)}" class="text-ht-content-muted hover:text-danger-fg" aria-label="Remove"><svg class="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>`}
          </div>`).join('');

    const orgRows = orgs.length === 0
      ? '<p class="text-xs text-ht-content-muted">No organizations defined.</p>'
      : orgs.map(([key, org]) => `
          <div class="flex items-center gap-2 rounded-sm border border-divider-subtle bg-ht-surface-base px-3 py-2">
            <span class="flex-1 font-mono text-xs text-ht-content-secondary">${escHtml(key)}</span>
            <span class="text-xs text-ht-content-muted">${escHtml(org.name || key)}</span>
            ${readOnly ? '' : `<button type="button" data-remove-org="${escAttr(realm)}" data-org-key="${escAttr(key)}" class="text-ht-content-muted hover:text-danger-fg" aria-label="Remove"><svg class="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>`}
          </div>`).join('');

    section.innerHTML = `
      <div class="mb-4 flex items-center justify-between">
        <h2 class="font-mono text-base font-semibold text-ht-content-primary">${escHtml(realm)}</h2>
        ${readOnly ? '' : `<button type="button" id="remove-realm-btn" data-realm="${escAttr(realm)}" class="text-xs text-danger-fg hover:underline">Remove realm</button>`}
      </div>
      <div class="space-y-5">
        <div>
          <h3 class="mb-3 text-xs font-medium uppercase tracking-wider text-ht-content-muted">Web / UI</h3>
          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <label class="block text-sm font-medium text-ht-content-secondary">Theme</label>
              <select data-bind="realms.${escAttr(realm)}.web.theme" class="mt-1.5 input">
                <option value="">— inherit global —</option>
                <option value="ember">Ember (dark default)</option>
                <option value="ocean">Ocean</option>
                <option value="midnight">Midnight</option>
                <option value="forest">Forest</option>
                <option value="cloud">Cloud (light)</option>
                <option value="slate">Slate (light)</option>
              </select>
            </div>
          </div>
          <div class="mt-3">
            <label class="block text-sm font-medium text-ht-content-secondary">Custom CSS</label>
            <textarea data-bind="realms.${escAttr(realm)}.web.custom_css" rows="4"
              class="mt-1.5 input font-mono text-xs" placeholder="/* custom CSS */"></textarea>
          </div>
        </div>
        <div>
          <h3 class="mb-3 text-xs font-medium uppercase tracking-wider text-ht-content-muted">Auth Policy</h3>
          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <label class="block text-sm font-medium text-ht-content-secondary">Registration mode</label>
              <select data-bind="realms.${escAttr(realm)}.auth.registration.mode" class="mt-1.5 input">
                <option value="">— inherit global —</option>
                <option value="disabled">Disabled</option>
                <option value="open">Open</option>
                <option value="invite_only">Invite Only</option>
                <option value="domain_restricted">Domain Restricted</option>
              </select>
            </div>
            <div>
              <label class="block text-sm font-medium text-ht-content-secondary">MFA required</label>
              <select data-bind-bool="realms.${escAttr(realm)}.auth.mfa_required" class="mt-1.5 input">
                <option value="">— inherit global —</option>
                <option value="true">Yes</option>
                <option value="false">No</option>
              </select>
            </div>
          </div>
        </div>
        <div>
          <div class="mb-2 flex items-center justify-between">
            <h3 class="text-xs font-medium uppercase tracking-wider text-ht-content-muted">Applications</h3>
            ${readOnly ? '' : `<button type="button" data-add-app="${escAttr(realm)}" class="text-xs text-teal-fg hover:underline">+ Add</button>`}
          </div>
          <div class="space-y-1">${appRows}</div>
        </div>
        <div>
          <div class="mb-2 flex items-center justify-between">
            <h3 class="text-xs font-medium uppercase tracking-wider text-ht-content-muted">Organizations</h3>
            ${readOnly ? '' : `<button type="button" data-add-org="${escAttr(realm)}" class="text-xs text-teal-fg hover:underline">+ Add</button>`}
          </div>
          <div class="space-y-1">${orgRows}</div>
        </div>
      </div>`;

    this._attachRealmListeners(section, realm);
    this._populateSection(section);
  }

  _attachRealmListeners(section, realm) {
    section.querySelector('#remove-realm-btn')?.addEventListener('click', (e) => {
      this.removeRealm(e.currentTarget.dataset.realm);
    });
    section.querySelectorAll('[data-add-app]').forEach(btn => {
      btn.addEventListener('click', () => { this.addApp(btn.dataset.addApp); this._renderRealmSection(btn.dataset.addApp); });
    });
    section.querySelectorAll('[data-remove-app]').forEach(btn => {
      btn.addEventListener('click', () => { this.removeApp(btn.dataset.removeApp, btn.dataset.appKey); this._renderRealmSection(btn.dataset.removeApp); });
    });
    section.querySelectorAll('[data-add-org]').forEach(btn => {
      btn.addEventListener('click', () => { this.addOrg(btn.dataset.addOrg); this._renderRealmSection(btn.dataset.addOrg); });
    });
    section.querySelectorAll('[data-remove-org]').forEach(btn => {
      btn.addEventListener('click', () => { this.removeOrg(btn.dataset.removeOrg, btn.dataset.orgKey); this._renderRealmSection(btn.dataset.removeOrg); });
    });
  }

  _attachListeners() {
    const readOnly = this._root.dataset.readOnly === 'true';

    document.getElementById('mode-visual-btn')?.addEventListener('click', () => this._setMode('visual'));
    document.getElementById('mode-raw-btn')?.addEventListener('click', () => this._setMode('raw'));
    document.getElementById('export-btn')?.addEventListener('click', () => this.openExport());
    document.getElementById('export-close-btn')?.addEventListener('click', () => this._closeExport());
    document.getElementById('export-close-btn-footer')?.addEventListener('click', () => this._closeExport());
    document.getElementById('export-copy-btn')?.addEventListener('click', () => this.copyExport());
    document.getElementById('export-modal')?.addEventListener('click', e => {
      if (e.target === document.getElementById('export-modal')) this._closeExport();
    });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && this.showingExport) this._closeExport();
    });

    if (!readOnly) {
      document.getElementById('reset-btn')?.addEventListener('click', () => this.reset());
      document.getElementById('preview-btn')?.addEventListener('click', () => this.preview());
      document.getElementById('validate-btn')?.addEventListener('click', () => this.validate());
      document.getElementById('apply-btn')?.addEventListener('click', () => this.apply());
      document.getElementById('raw-preview-top')?.addEventListener('click', () => this.preview());
      document.getElementById('raw-preview-bottom')?.addEventListener('click', () => this.preview());
    }

    // Delegated change/input for data-bind and data-bind-bool
    const visualPanel = document.getElementById('visual-editor-panel');
    if (visualPanel) {
      const handleBind = e => {
        const el = e.target;
        if (el.dataset.bind) {
          this.setVal(el.dataset.bind, el.value);
          if (el.dataset.bind === 'email.transport') {
            const sec = el.closest('[data-section="email"]');
            if (sec) this._updateTransportVisibility(el.value, sec);
          }
        }
        if (el.dataset.bindBool) {
          const v = el.value === 'true' ? true : el.value === 'false' ? false : null;
          this.setVal(el.dataset.bindBool, v);
        }
      };
      visualPanel.addEventListener('change', handleBind);
      visualPanel.addEventListener('input', handleBind);

      // list-add delegation
      visualPanel.addEventListener('click', e => {
        const btn = e.target.closest('[data-list-add]');
        if (!btn) return;
        const path = btn.dataset.listAdd;
        this.addListItem(path);
        const cont = visualPanel.querySelector(`[data-list-container="${CSS.escape(path)}"]`);
        if (cont) this._renderList(cont, path);
      });
    }

    // Raw editor sync
    const yamlEditor = document.getElementById('yaml-editor');
    const yamlMirror = document.getElementById('yaml-mirror');
    if (yamlEditor && yamlMirror) {
      yamlEditor.addEventListener('input', () => { yamlMirror.innerHTML = highlightYaml(yamlEditor.value + '\n'); });
      yamlEditor.addEventListener('scroll', () => { yamlMirror.scrollTop = yamlEditor.scrollTop; yamlMirror.scrollLeft = yamlEditor.scrollLeft; });
    }
  }

  _setMode(mode) {
    this.mode = mode;
    const visual = document.getElementById('visual-editor-panel');
    const raw = document.getElementById('raw-editor-panel');
    const visualBtn = document.getElementById('mode-visual-btn');
    const rawBtn = document.getElementById('mode-raw-btn');
    const ACTIVE = ['bg-divider', 'text-ht-content-primary'];
    const INACTIVE = ['text-ht-content-secondary', 'hover-bg-divider'];

    if (mode === 'visual') {
      visual?.classList.remove('hidden');
      raw?.classList.add('hidden');
      visualBtn?.classList.add(...ACTIVE);
      visualBtn?.classList.remove(...INACTIVE);
      rawBtn?.classList.remove(...ACTIVE);
      rawBtn?.classList.add(...INACTIVE);
    } else {
      visual?.classList.add('hidden');
      raw?.classList.remove('hidden');
      rawBtn?.classList.add(...ACTIVE);
      rawBtn?.classList.remove(...INACTIVE);
      visualBtn?.classList.remove(...ACTIVE);
      visualBtn?.classList.add(...INACTIVE);
      // Sync mirror when entering raw mode
      const ta = document.getElementById('yaml-editor');
      const mirror = document.getElementById('yaml-mirror');
      if (ta && mirror) { mirror.innerHTML = highlightYaml(ta.value + '\n'); mirror.scrollTop = ta.scrollTop; }
    }
  }

  _closeExport() {
    this.showingExport = false;
    document.getElementById('export-modal')?.classList.add('hidden');
  }

  _updateValidationUI() {
    const successEl = document.getElementById('validation-success');
    const errorsEl  = document.getElementById('validation-errors');
    const countEl   = document.getElementById('error-count');
    const hintEl    = document.getElementById('error-inline-hint');
    const orphanEl  = document.getElementById('orphan-errors');
    const errorKeys = Object.keys(this.errors);

    successEl?.classList.toggle('hidden', !this.validationPassed);

    if (errorKeys.length > 0) {
      errorsEl?.classList.remove('hidden');
      if (countEl) countEl.textContent = String(errorKeys.length);
      const hasInline = errorKeys.some(k => this.hasInlineError(k));
      hintEl?.classList.toggle('hidden', !hasInline);
      if (orphanEl) {
        orphanEl.innerHTML = errorKeys
          .filter(k => !this.hasInlineError(k))
          .map(k => `<div class="mt-1.5 ml-6 flex items-start gap-1.5 text-xs text-danger-fg">
            <code class="shrink-0 rounded-sm bg-danger/[0.12] px-1 py-0.5 font-mono text-[11px]">${escHtml(k)}</code>
            <span>${escHtml(this.errors[k])}</span></div>`).join('');
      }
    } else {
      errorsEl?.classList.add('hidden');
    }
  }

  // ── Business logic ──────────────────────────────────────────────────────

  ensure(path) {
    const parts = path.split('.');
    let obj = this.config;
    for (const p of parts) {
      if (obj[p] === undefined || obj[p] === null) obj[p] = {};
      obj = obj[p];
    }
  }

  getVal(path, fallback) {
    const parts = path.split('.');
    if (parts.some(p => p === '__proto__' || p === 'constructor' || p === 'prototype')) return fallback;
    let obj = this.config;
    for (const p of parts) {
      if (obj === undefined || obj === null) return fallback;
      obj = obj[p];
    }
    return obj !== undefined && obj !== null ? obj : fallback;
  }

  setVal(path, value) {
    const parts = path.split('.');
    if (parts.some(p => p === '__proto__' || p === 'constructor' || p === 'prototype')) return;
    let obj = this.config;
    for (let i = 0; i < parts.length - 1; i++) {
      if (obj[parts[i]] === undefined || obj[parts[i]] === null) obj[parts[i]] = {};
      obj = obj[parts[i]];
    }
    const key = parts[parts.length - 1];
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return;
    if (value === '' || value === null) {
      delete obj[key];
    } else if (typeof value === 'string' && !value.includes('${')) {
      if (/^-?\d+$/.test(value)) obj[key] = parseInt(value, 10);
      else if (/^-?\d+\.\d+$/.test(value)) obj[key] = parseFloat(value);
      else obj[key] = value;
    } else {
      obj[key] = value;
    }
    delete this.errors[path];
  }

  _handleAddRealm() { this.addRealm(); }

  addRealm() {
    const name = prompt('Realm slug (lowercase, hyphens):');
    if (!name) return;
    if (!this.config.realms) this.config.realms = {};
    this.config.realms[name] = {};
    this.activeSection = 'realm';
    this.activeRealm = name;
    this._refreshRealmNav();
    this._updateSidebarActive();
    this._switchSection('realm', name);
  }

  removeRealm(key) {
    if (!confirm('Remove realm "' + key + '" from config?')) return;
    delete this.config.realms[key];
    if (this.activeRealm === key) { this.activeRealm = null; this.activeSection = 'server'; }
    this._refreshRealmNav();
    this._updateSidebarActive();
    this._switchSection(this.activeSection, this.activeRealm);
  }

  addApp(realm) {
    const key = prompt('Application key (lowercase, hyphens):');
    if (!key) return;
    if (!this.config.realms[realm].applications) this.config.realms[realm].applications = {};
    this.config.realms[realm].applications[key] = { name: key, redirect_uris: [], grant_types: ['authorization_code'] };
  }
  removeApp(realm, key) { if (confirm('Remove application "' + key + '"?')) delete this.config.realms[realm].applications[key]; }

  addOrg(realm) {
    const slug = prompt('Organization slug (lowercase, hyphens):');
    if (!slug) return;
    if (!this.config.realms[realm].organizations) this.config.realms[realm].organizations = {};
    this.config.realms[realm].organizations[slug] = { name: slug };
  }
  removeOrg(realm, key) { if (confirm('Remove organization "' + key + '"?')) delete this.config.realms[realm].organizations[key]; }

  getList(path) { return this.getVal(path, []) || []; }
  addListItem(path) {
    this.ensure(path.split('.').slice(0, -1).join('.'));
    const parts = path.split('.');
    let obj = this.config;
    for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
    const key = parts[parts.length - 1];
    if (!Array.isArray(obj[key])) obj[key] = [];
    obj[key].push('');
  }
  removeListItem(path, idx) {
    const parts = path.split('.');
    let obj = this.config;
    for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
    obj[parts[parts.length - 1]].splice(idx, 1);
  }

  hasInlineError(key) {
    try { return !!document.querySelector(`[data-error-for="${CSS.escape(key)}"]`); }
    catch { return false; }
  }

  async validate() {
    const btn = document.getElementById('validate-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Checking\u2026'; }
    this.validating = true;
    this.validationPassed = false;
    try {
      const resp = await fetch('/ui/admin/settings/editor/visual/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': this.csrf },
        body: JSON.stringify(this.config),
      });
      const result = await resp.json();
      const newErrors = {};
      if (!result.valid && result.errors) {
        for (const e of result.errors) newErrors[e.field] = e.reason;
      }
      this.errors = newErrors;
      if (result.valid) {
        this.validationPassed = true;
        setTimeout(() => { this.validationPassed = false; this._updateValidationUI(); }, 4000);
      }
      this._updateValidationUI();
      this._switchSection(this.activeSection, this.activeRealm);
      return result.valid;
    } finally {
      this.validating = false;
      if (btn) { btn.disabled = false; btn.textContent = 'Validate'; }
    }
  }

  reset() {
    this.config = JSON.parse(this.originalConfig);
    this.errors = {};
    const diff = document.getElementById('diff-output');
    if (diff) diff.innerHTML = '';
    this._switchSection(this.activeSection, this.activeRealm);
    this._updateValidationUI();
  }

  resetRawEditor() {
    const ta = document.getElementById('yaml-editor');
    if (ta) ta.value = ta.defaultValue;
    const diff = document.getElementById('diff-output');
    if (diff) diff.innerHTML = '';
  }

  async preview() {
    if (this.mode === 'visual') {
      const resp = await fetch('/ui/admin/settings/editor/visual/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': this.csrf },
        body: JSON.stringify(this.config),
      });
      const el = document.getElementById('diff-output');
      if (el) el.innerHTML = await resp.text();
    } else {
      htmx.ajax('POST', '/ui/admin/settings/editor/preview',
        { target: '#diff-output', values: { yaml: document.getElementById('yaml-editor').value } });
    }
  }

  async openExport() {
    this.showingExport = true;
    this.exportLoading = true;
    this.exportCopied = false;
    const modal     = document.getElementById('export-modal');
    const loadingEl = document.getElementById('export-loading');
    const contentEl = document.getElementById('export-content');
    if (modal) modal.classList.remove('hidden');
    if (loadingEl) loadingEl.classList.remove('hidden');
    if (contentEl) contentEl.classList.add('hidden');
    try {
      if (this.mode === 'raw') {
        this.exportYaml = document.getElementById('yaml-editor')?.value || '';
      } else {
        const resp = await fetch('/ui/admin/settings/editor/visual/export', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': this.csrf },
          body: JSON.stringify(this.config),
        });
        if (!resp.ok) throw new Error(await resp.text());
        this.exportYaml = await resp.text();
      }
      renderExportHighlight(this.exportYaml);
    } catch (e) {
      this.exportYaml = '# Error generating YAML:\n# ' + e.message;
      renderExportHighlight(this.exportYaml);
    } finally {
      this.exportLoading = false;
      if (loadingEl) loadingEl.classList.add('hidden');
      if (contentEl) contentEl.classList.remove('hidden');
    }
  }

  copyExport() {
    navigator.clipboard.writeText(this.exportYaml).then(() => {
      this.exportCopied = true;
      const btn       = document.getElementById('export-copy-btn');
      const copyIcon  = document.getElementById('export-copy-icon');
      const checkIcon = document.getElementById('export-check-icon');
      const label     = document.getElementById('export-copy-label');
      if (btn) { btn.classList.remove('btn-ember'); btn.classList.add('bg-success/20', 'text-success-fg'); }
      copyIcon?.classList.add('hidden');
      checkIcon?.classList.remove('hidden');
      if (label) label.textContent = 'Copied!';
      setTimeout(() => {
        this.exportCopied = false;
        if (btn) { btn.classList.add('btn-ember'); btn.classList.remove('bg-success/20', 'text-success-fg'); }
        copyIcon?.classList.remove('hidden');
        checkIcon?.classList.add('hidden');
        if (label) label.textContent = 'Copy';
      }, 2000);
    });
  }

  async apply() {
    if (this.saving) return;
    this.saving = true;
    const applyBtn = document.getElementById('apply-btn');
    if (applyBtn) { applyBtn.disabled = true; applyBtn.textContent = 'Applying\u2026'; }
    try {
      if (this.mode === 'visual') {
        const valid = await this.validate();
        if (!valid) return;
        const resp = await fetch('/ui/admin/settings/editor/visual/apply', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': this.csrf },
          body: JSON.stringify(this.config),
        });
        const result = await resp.json();
        if (result.ok) {
          window.location.href = '/ui/admin/settings/editor?flash=' + encodeURIComponent(result.message || 'Applied') + '&flash_kind=success';
        } else {
          if (result.errors) {
            const newErrors = {};
            for (const e of result.errors) newErrors[e.field] = e.reason;
            this.errors = newErrors;
            this._updateValidationUI();
            this._switchSection(this.activeSection, this.activeRealm);
          }
          const diff = document.getElementById('diff-output');
          if (diff) diff.innerHTML = '<div class="rounded-md bg-danger/[0.12] px-6 py-4 text-sm text-danger-fg ring-1 ring-danger/30"><h3 class="font-semibold">Error</h3><p class="mt-1 font-mono text-xs">' + escHtml(result.error || '') + '</p></div>';
        }
      } else {
        document.getElementById('apply-form').submit();
      }
    } finally {
      this.saving = false;
      if (applyBtn) { applyBtn.disabled = false; applyBtn.textContent = 'Apply Changes'; }
    }
  }
}

// =========================================================================
// Utility helpers
// =========================================================================

// HTML-safe escaping for template literals in ConfigEditor
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escAttr(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Read a JSON payload embedded as `<script type="application/json" id="...">`.
// Such tags are data, not executable scripts, so CSP `script-src 'self'`
// allows them while still blocking real inline `<script>` execution.
function readJsonScript(id) {
  if (!id) return null;
  const el = document.getElementById(id);
  if (!el) return null;
  try { return JSON.parse(el.textContent || ''); }
  catch { return null; }
}

// Lightweight YAML syntax highlighter — regex-based, no dependencies.
// Used by the config editor's raw-tab mirror and export modal.
function highlightYaml(raw) {
  const esc = raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  return esc.split('\n').map(line => {
    if (/^\s*#/.test(line)) {
      return '<span class="text-ht-content-muted italic">' + line + '</span>';
    }
    const m = line.match(/^(\s*)([\w][\w.\-]*)(:)(.*)/);
    if (m) {
      const [, indent, key, colon, rest] = m;
      return indent
        + '<span class="text-brand-ember">' + key + '</span>'
        + '<span class="text-ht-content-muted">' + colon + '</span>'
        + highlightValue(rest);
    }
    const lm = line.match(/^(\s*-\s)(.*)/);
    if (lm) {
      return '<span class="text-ht-content-muted">' + lm[1] + '</span>' + highlightValue(lm[2]);
    }
    return line;
  }).join('\n');
}

function highlightValue(val) {
  if (!val || !val.trim()) return val;
  const v = val.trim();
  const leading = val.slice(0, val.indexOf(v));
  const commentIdx = v.search(/\s+#/);
  let main = v, comment = '';
  if (commentIdx > 0) {
    main = v.slice(0, commentIdx);
    comment = '<span class="text-ht-content-muted italic">' + v.slice(commentIdx) + '</span>';
  }
  if (/^(&quot;.*&quot;|&#x27;.*&#x27;|&apos;.*&apos;|".*"|'.*')$/.test(main)) {
    return leading + '<span class="text-teal-400">' + main + '</span>' + comment;
  }
  if (/^(true|false|yes|no|on|off)$/i.test(main)) {
    return leading + '<span class="text-rose-400">' + main + '</span>' + comment;
  }
  if (/^(null|~)$/i.test(main)) {
    return leading + '<span class="text-ht-content-muted">' + main + '</span>' + comment;
  }
  if (/^-?\d+(\.\d+)?$/.test(main)) {
    return leading + '<span class="text-violet-400">' + main + '</span>' + comment;
  }
  return leading + '<span class="text-teal-400">' + main + '</span>' + comment;
}

function renderExportHighlight(raw) {
  const target = document.getElementById('export-yaml-highlighted');
  if (target && raw) target.innerHTML = highlightYaml(raw);
}

// =========================================================================
// HTMX event bridge — forward showToast HX-Trigger events to ToastManager
// =========================================================================

document.body.addEventListener('showToast', function(e) {
  var d = typeof e.detail === 'string' ? JSON.parse(e.detail) : e.detail;
  window.dispatchEvent(new CustomEvent('show-toast', { detail: d }));
});

// Re-init roles tab after HTMX swaps the tab content
document.body.addEventListener('htmx:afterSwap', function(e) {
  const rolesTab = e.target.querySelector('[data-roles-tab]');
  if (rolesTab) initRolesTab(rolesTab);
});

// =========================================================================
// Global keyboard shortcuts
// =========================================================================
//   /   focus the page-level search box (`#page-search`)
//   c   click the primary CTA on the page (`#primary-cta`)
//   ?   open the shortcut overlay
(function () {
  function inEditable(el) {
    if (!el) return false;
    if (el.isContentEditable) return true;
    var tag = (el.tagName || '').toLowerCase();
    if (tag === 'input') {
      var t = (el.type || 'text').toLowerCase();
      return ['text','search','email','password','number','tel','url','date','datetime-local','time','month','week'].indexOf(t) !== -1;
    }
    return tag === 'textarea' || tag === 'select';
  }

  window.__hearthShortcutHelpOpen = false;
  document.addEventListener('keydown', function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (inEditable(e.target)) return;
    switch (e.key) {
      case '/': {
        var search = document.getElementById('page-search');
        if (search) {
          e.preventDefault();
          search.focus();
          search.select && search.select();
        }
        break;
      }
      case 'c': {
        var cta = document.getElementById('primary-cta');
        if (cta) {
          e.preventDefault();
          cta.click();
        }
        break;
      }
      case '?': {
        e.preventDefault();
        window.dispatchEvent(new CustomEvent('hearth-shortcut-help'));
        break;
      }
      case 'Escape': {
        window.dispatchEvent(new CustomEvent('hearth-shortcut-help-close'));
        break;
      }
      default: break;
    }
  });
})();

// =========================================================================
// Bootstrap — initialize all managers on DOMContentLoaded
// =========================================================================

document.addEventListener('DOMContentLoaded', () => {
  new SidebarManager();
  new RealmNav(document.getElementById('realm-nav'));
  new ToastManager();
  initRealmPill();
  initRealmWizard();
  initOrgListBulkActions();
  initRolesTab(document.querySelector('[data-roles-tab]'));
  initPasswordStrength();
  initAttrRows();
});
