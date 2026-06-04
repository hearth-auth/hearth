// Hearth admin UI behaviours.
//
// Every Alpine component used by `/ui/**` templates is registered here.
// Using @alpinejs/csp (eval-free Pratt parser), so:
//   - x-data MUST reference a pre-registered component name, never an inline
//     object literal like x-data="{ open: false }".
//   - Server-rendered values are passed via data-* attributes or
//     <script type="application/json"> tags, both of which are CSP-safe.
// This allows script-src 'self' with NO 'unsafe-eval' (HEA-1281).

document.addEventListener('alpine:init', () => {
  // -----------------------------------------------------------------------
  // Layout
  // -----------------------------------------------------------------------

  Alpine.data('withLoading', (message) => ({
    submitting: false,
    loadingMessage: message || 'Loading\u2026',
    submit() { this.submitting = true; }
  }));

  // Authenticated shell layout — owns mobile sidebar open/close state.
  Alpine.data('shellLayout', () => ({
    sidebarOpen: false,
  }));

  // Sidebar realm tree. Fetches realms once at mount, derives the current
  // realm from `/ui/admin/realms/{name}/...` per UI_ROUTING.md R-1, so the
  // matching subtree auto-expands and highlights.
  // openRealms tracks which rows are expanded. isRealmOpen/toggleRealm are
  // called from x-for children — no inner x-data inline object on each <li>.
  Alpine.data('realmNav', (activePage) => ({
    loading: true,
    realms: [],
    currentRealm: '',
    activePage: activePage || '',
    openRealms: {},
    subPages: [
      { key: 'overview',           label: 'Overview',          href: '/ui/admin/realms/{realm}' },
      { key: 'users',              label: 'Users',             href: '/ui/admin/realms/{realm}/users' },
      { key: 'organizations',      label: 'Organizations',     href: '/ui/admin/realms/{realm}/organizations' },
      { key: 'groups',             label: 'Groups',            href: '/ui/admin/realms/{realm}/groups' },
      { key: 'applications',       label: 'Applications',      href: '/ui/admin/realms/{realm}/applications' },
      { key: 'identity_providers', label: 'Identity Providers', href: '/ui/admin/realms/{realm}/identity-providers' },
      { key: 'sessions',           label: 'Sessions',          href: '/ui/admin/realms/{realm}/sessions' },
      { key: 'webhooks',           label: 'Webhooks',          href: '/ui/admin/realms/{realm}/webhooks' },
      { key: 'audit',              label: 'Audit Log',         href: '/ui/admin/realms/{realm}/audit' },
      { key: 'rbac_permissions',   label: 'Permissions',       href: '/ui/admin/realms/{realm}/rbac/permissions' },
      { key: 'rbac_roles',         label: 'Roles',             href: '/ui/admin/realms/{realm}/rbac/roles' },
      { key: 'rbac_scopes',        label: 'Scopes',            href: '/ui/admin/realms/{realm}/rbac/scopes' },
      { key: 'rbac_debug',         label: 'Permission Check',  href: '/ui/admin/realms/{realm}/rbac/debug' },
    ],
    isRealmOpen(name) { return !!this.openRealms[name]; },
    toggleRealm(name) { this.openRealms[name] = !this.openRealms[name]; },
    deriveCurrentRealm() {
      const m = window.location.pathname.match(/^\/ui\/admin\/realms\/([^\/?#]+)(?:\/|$)/);
      return m ? decodeURIComponent(m[1]) : '';
    },
    // Capture `this` (the Alpine proxy) synchronously so Promise callbacks
    // always mutate the reactive object — async init() can silently drop
    // reactivity if the microtask runs before Alpine's proxy is fully wired.
    init() {
      const d = this;
      d.currentRealm = d.deriveCurrentRealm();
      if (d.currentRealm) d.openRealms[d.currentRealm] = true;
      fetch('/ui/admin/api/nav/realms', { credentials: 'same-origin' })
        .then(res => res.ok ? res.json() : null)
        .then(data => { if (data) d.realms = data.realms || []; })
        .catch(() => { /* sidebar tree is non-essential */ })
        .finally(() => { d.loading = false; });
    },
  }));

  // Breadcrumb realm pill — extracts the active realm slug from the URL
  // path so the header pill is driven without a server round-trip.
  Alpine.data('breadcrumbRealm', () => ({
    get realm() {
      const m = location.pathname.match(/\/ui\/admin\/realms\/([^/]+)/);
      return m ? decodeURIComponent(m[1]) : '';
    },
  }));

  // Toast container — receives show-toast window events and shows them
  // as ephemeral banners that auto-dismiss after 5 s.
  Alpine.data('toastContainer', () => ({
    toasts: [],
    addToast(detail) {
      const d = typeof detail === 'string' ? JSON.parse(detail) : detail;
      this.toasts.push({ message: d.message, kind: d.kind, id: Date.now() });
      const toasts = this.toasts;
      setTimeout(() => { toasts.shift(); }, 5000);
    },
  }));

  // -----------------------------------------------------------------------
  // Password strength meter (reset_password)
  // -----------------------------------------------------------------------

  Alpine.data('passwordStrength', () => ({
    password: '',
    confirm: '',
    matchError: false,
    get strength() {
      const pw = this.password;
      if (!pw) return 0;
      let s = 0;
      if (pw.length >= 8) s++;
      if (pw.length >= 12) s++;
      if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
      if (/[0-9]/.test(pw)) s++;
      if (/[^A-Za-z0-9]/.test(pw)) s++;
      return Math.min(4, s);
    },
    checkMatch() {
      this.matchError = this.confirm.length > 0 && this.password !== this.confirm;
    },
    submit(form) {
      this.checkMatch();
      if (!this.matchError) form.submit();
    },
  }));

  // -----------------------------------------------------------------------
  // Admin → Users → Roles tab
  // -----------------------------------------------------------------------

  Alpine.data('rolesTabData', () => ({
    assignOpen: false,
    scopeType: 'realm',
    selectedOrg: '',
    selectedRoleId: '',
    rolePerms: {},
    init() {
      const data = readJsonScript(this.$el.dataset.bootstrapId);
      if (data) {
        this.selectedRoleId = data.selectedRoleId || '';
        this.rolePerms = data.rolePerms || {};
      }
    },
    get inheritedPerms() { return this.rolePerms[this.selectedRoleId] || []; },
    // Scope hidden-input value for the role-assign form.
    get scopeValue() {
      return this.scopeType === 'org' && this.selectedOrg
        ? 'org:' + this.selectedOrg
        : 'realm';
    },
  }));

  // -----------------------------------------------------------------------
  // Admin → RBAC debug → Token preview tab
  // -----------------------------------------------------------------------

  Alpine.data('tokenPreview', () => ({
    userId: '',
    result: null,
    loading: false,
    previewUrl: '',
    init() {
      this.previewUrl = this.$el.dataset.previewUrl || '';
    },
    async preview() {
      if (!this.userId.trim()) return;
      this.loading = true;
      this.result = null;
      try {
        const csrf = document.querySelector('meta[name="csrf"]')?.getAttribute('content') || '';
        const body = new URLSearchParams({ user_id: this.userId.trim() });
        const resp = await fetch(this.previewUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-CSRF-Token': csrf,
          },
          body: body.toString(),
        });
        this.result = await resp.text();
      } catch (e) {
        this.result = JSON.stringify({ error: String(e) }, null, 2);
      } finally {
        this.loading = false;
      }
    },
  }));

  // -----------------------------------------------------------------------
  // Admin → Users → Edit — dynamic custom-attributes rows
  // -----------------------------------------------------------------------

  Alpine.data('attrRows', () => ({
    rows: [],
    _nextId: 0,
    addRow() {
      this.rows.push({ id: this._nextId++ });
    },
    removeRow(el) {
      const row = el.closest('.attr-row');
      if (row) row.remove();
    },
  }));

  // -----------------------------------------------------------------------
  // Role assignment (admin → Groups → detail)
  // -----------------------------------------------------------------------

  // Simple scope selector — 'realm' | 'org'. Scope drives whether the org
  // dropdown is visible.
  Alpine.data('groupRoleAssign', () => ({
    scope: 'realm',
  }));

  // -----------------------------------------------------------------------
  // Group create form (admin → Groups → new)
  // -----------------------------------------------------------------------

  // Reads initial name/slug from data-* so Tera-rendered values are
  // CSP-safe. updateSlug() auto-derives the slug from the name until the
  // user edits the slug field directly.
  Alpine.data('groupNewForm', () => ({
    name: '',
    slug: '',
    slugTouched: false,
    init() {
      this.name = this.$el.dataset.name || '';
      this.slug = this.$el.dataset.slug || '';
      this.slugTouched = this.$el.dataset.slugTouched === 'true';
    },
    updateSlug() {
      if (!this.slugTouched) {
        this.slug = this.name.toLowerCase()
          .replace(/[^a-z0-9_-]+/g, '-')
          .replace(/^-+|-+$/g, '')
          .slice(0, 128);
      }
    },
  }));

  // -----------------------------------------------------------------------
  // Onboarding wizard form (admin → Onboarding)
  // -----------------------------------------------------------------------

  // Reads initial display name / realm name from data-* attributes.
  // updateRealmName() auto-derives the realm slug until the user edits it.
  Alpine.data('onboardingWizard', () => ({
    displayName: '',
    realmName: '',
    nameTouched: false,
    init() {
      this.displayName = this.$el.dataset.displayName || '';
      this.realmName = this.$el.dataset.realmName || '';
      this.nameTouched = this.$el.dataset.nameTouched === 'true';
    },
    updateRealmName() {
      if (!this.nameTouched) {
        this.realmName = this.displayName.toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+|-+$/g, '')
          .slice(0, 63);
      }
    },
  }));

  // -----------------------------------------------------------------------
  // Webhook create form (admin → Webhooks → new)
  // -----------------------------------------------------------------------

  Alpine.data('webhookNewForm', () => ({
    showSecret: false,
    testResult: null,
    testLoading: false,
  }));

  // -----------------------------------------------------------------------
  // Organization member search (admin → Orgs → detail member-add section)
  // -----------------------------------------------------------------------

  // Drives the user-search typeahead and invite modal for org member addition.
  Alpine.data('orgMemberSearch', () => ({
    showDropdown: false,
    showInviteModal: false,
    inviteEmail: '',
    searchQuery: '',
    selectedUser: null,
    openInviteModal() {
      this.showInviteModal = true;
      this.inviteEmail = this.searchQuery;
      this.showDropdown = false;
    },
    selectOrgUser(id, name, email) {
      this.selectedUser = { id: id, name: name, email: email };
      this.showDropdown = false;
    },
  }));

  // -----------------------------------------------------------------------
  // Organization invite — role picker (admin → Orgs → detail)
  // -----------------------------------------------------------------------

  Alpine.data('orgRolePicker', () => ({
    role: 'Member',
  }));

  // -----------------------------------------------------------------------
  // Organization bulk-delete (admin → Orgs → list)
  // -----------------------------------------------------------------------

  Alpine.data('orgBulkDelete', () => ({
    selected: 0,
    confirmPending: false,
    allChecked: false,
    idsCsv: '',
    // Called from the select-all checkbox @change.
    updateAll() {
      this.$el.querySelectorAll('input.row-check').forEach(c => { c.checked = this.allChecked; });
      this.$dispatch('org-checked');
    },
    // Called from @org-checked.window — counts currently-checked rows.
    handleOrgChecked() {
      const checked = this.$el.querySelectorAll('input.row-check:checked');
      this.selected = checked.length;
      this.idsCsv = Array.from(checked).map(c => c.value).join(',');
    },
    attemptDelete() {
      if (!this.confirmPending) {
        this.confirmPending = true;
        const self = this;
        setTimeout(() => { self.confirmPending = false; }, 4000);
        return;
      }
      this.$root.submit();
    },
  }));

  // -----------------------------------------------------------------------
  // Organization member row (admin → Orgs → detail member table)
  // -----------------------------------------------------------------------

  // Drives the per-member role/permission accordions.
  Alpine.data('orgMemberRow', () => ({
    addRoleOpen: false,
    addPermOpen: false,
    expandedRole: null,
    toggleRoleForm() { this.addRoleOpen = !this.addRoleOpen; this.addPermOpen = false; },
    togglePermForm() { this.addPermOpen = !this.addPermOpen; this.addRoleOpen = false; },
    closeRoleForm() { this.addRoleOpen = false; },
    closePermForm() { this.addPermOpen = false; },
    toggleRoleExpand(id) { this.expandedRole = this.expandedRole === id ? null : id; },
    isRoleExpanded(id) { return this.expandedRole === id; },
  }));

  // Per-row destructive-action confirm (member remove button).
  Alpine.data('orgConfirmDelete', () => ({
    confirm: false,
  }));

  // -----------------------------------------------------------------------
  // Organization create form (admin → Orgs → new)
  // Mirrors groupNewForm — reads server values from data-* attributes.
  // -----------------------------------------------------------------------

  Alpine.data('orgNewForm', () => ({
    name: '',
    slug: '',
    slugTouched: false,
    init() {
      this.name = this.$el.dataset.name || '';
      this.slug = this.$el.dataset.slug || '';
      this.slugTouched = this.$el.dataset.slugTouched === 'true';
    },
    updateSlug() {
      if (!this.slugTouched) {
        this.slug = this.name.toLowerCase()
          .replace(/[^a-z0-9_-]+/g, '-')
          .replace(/^-+|-+$/g, '')
          .slice(0, 128);
      }
    },
  }));

  // -----------------------------------------------------------------------
  // RBAC debug — tab panel + user-search typeahead
  // -----------------------------------------------------------------------

  Alpine.data('rbacDebug', () => ({
    tab: 'check',
  }));

  // User-search input on the RBAC debug page. Reads initial userId from
  // data-user-id so server-rendered values are CSP-safe.
  Alpine.data('rbacUserSearch', () => ({
    userId: '',
    showDropdown: false,
    init() {
      this.userId = this.$el.dataset.userId || '';
    },
    // Called from HTMX partial when a suggestion row is clicked.
    selectUser(userId) {
      this.userId = userId;
      this.showDropdown = false;
      const input = this.$refs.userIdInput;
      if (input) input.focus();
    },
  }));

  // -----------------------------------------------------------------------
  // RBAC role detail — delete-confirmation dialog
  // -----------------------------------------------------------------------

  Alpine.data('rbacRoleDeleteDialog', () => ({
    showDeleteDialog: false,
  }));

  // -----------------------------------------------------------------------
  // User detail — access tab panel (Roles / Extra Permissions / Effective)
  // -----------------------------------------------------------------------

  Alpine.data('userAccessTabs', () => ({
    tab: 'roles',
  }));

  // -----------------------------------------------------------------------
  // User CSV import (admin → Users → import)
  // -----------------------------------------------------------------------

  Alpine.data('userImport', () => ({
    file: null,
    fileName: '',
    headers: [],
    mapping: { email: '', name: '', role: '' },
    dragOver: false,
    step: 'upload',
    handleFile(f) {
      if (!f) return;
      this.file = f;
      this.fileName = f.name;
      const self = this;
      const reader = new FileReader();
      reader.onload = function(e) {
        const firstLine = e.target.result.split('\n')[0] || '';
        self.headers = firstLine.split(',').map(h => h.trim().replace(/^['"]|['"]$/g, ''));
        self.mapping.email = self.headers.find(h => h.toLowerCase().includes('email')) || '';
        self.mapping.name  = self.headers.find(h => h.toLowerCase().includes('name'))  || '';
        self.mapping.role  = self.headers.find(h => h.toLowerCase().includes('role'))  || '';
        self.step = 'map';
      };
      reader.readAsText(f);
    },
    onDrop(e) {
      this.dragOver = false;
      const f = e.dataTransfer.files[0];
      if (f) this.handleFile(f);
    },
    resetUpload() {
      this.step = 'upload';
      this.file = null;
      this.fileName = '';
      this.headers = [];
    },
  }));

  // -----------------------------------------------------------------------
  // User list — bulk-action toolbar (admin → Users → list)
  // -----------------------------------------------------------------------

  // total-count is passed via data-total-count on the <form> element so the
  // status text ("N users") can be rendered without server-rendered Alpine.
  Alpine.data('userBulkAction', () => ({
    selected: 0,
    action: '',
    confirmPending: false,
    allChecked: false,
    idsCsv: '',
    totalCount: 0,
    init() {
      this.totalCount = parseInt(this.$el.dataset.totalCount || '0', 10);
    },
    get statusText() {
      if (this.selected === 0) {
        const n = this.totalCount;
        return n + ' user' + (n !== 1 ? 's' : '');
      }
      return this.selected + ' selected';
    },
    updateCount() {
      const checked = this.$el.querySelectorAll('input.row-check:checked');
      this.selected = checked.length;
      this.idsCsv = Array.from(checked).map(c => c.value).join(',');
      this.confirmPending = false;
    },
    submit() {
      if (!this.action) return;
      if (this.action === 'deactivate' && !this.confirmPending) {
        this.confirmPending = true;
        return;
      }
      this.$root.submit();
    },
  }));

  // -----------------------------------------------------------------------
  // New user form (admin → Users → new)
  // Email pre-filled from data-email; password strength computed inline.
  // -----------------------------------------------------------------------

  Alpine.data('userNewForm', () => ({
    email: '',
    password: '',
    emailDirty: false,
    passwordDirty: false,
    init() {
      this.email = this.$el.dataset.email || '';
    },
    get emailValid() {
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.email);
    },
    get pwStrength() {
      const p = this.password;
      let s = 0;
      if (p.length >= 8)  s++;
      if (p.length >= 12) s++;
      if (/[A-Z]/.test(p)) s++;
      if (/[0-9]/.test(p)) s++;
      if (/[^A-Za-z0-9]/.test(p)) s++;
      return Math.min(s, 4);
    },
    get strengthLabel() {
      return ['Very weak','Weak','Fair','Strong','Very strong'][this.pwStrength];
    },
    get strengthColor() {
      return ['bg-danger','bg-warning','bg-warning','bg-teal-500','bg-success'][this.pwStrength];
    },
  }));

  // -----------------------------------------------------------------------
  // User permissions tab (admin → Users → detail → Extra Permissions)
  // -----------------------------------------------------------------------

  Alpine.data('userPermGrant', () => ({
    grantOpen: false,
    scopeType: 'realm',
    selectedOrg: '',
    get scopeValue() {
      return this.scopeType === 'org' && this.selectedOrg
        ? 'org:' + this.selectedOrg
        : 'realm';
    },
    toggleGrant() { this.grantOpen = !this.grantOpen; },
    closeGrant()  { this.grantOpen = false; },
  }));

  // -----------------------------------------------------------------------
  // Collapsible disclosure sections (admin → Settings → System Info)
  // -----------------------------------------------------------------------

  // Single-boolean open/close toggle. Defaults to open; set
  // data-open="false" on the host element to start collapsed.
  Alpine.data('disclosure', () => ({
    open: true,
    init() {
      if (this.$el.dataset.open === 'false') this.open = false;
    },
  }));

  // -----------------------------------------------------------------------
  // Admin → Settings → Config Editor
  // -----------------------------------------------------------------------

  Alpine.data('configEditor', () => {
    const initialConfig = readJsonScript('config-editor-data') || {};
    const params = new URLSearchParams(window.location.search);
    const linkedSection = params.get('section');
    const linkedRealm = params.get('realm_key');
    let initialSection = 'server';
    let initialRealm = null;
    if (linkedSection === 'realms' && linkedRealm) {
      initialRealm = linkedRealm;
    } else if (linkedSection) {
      initialSection = linkedSection;
    }

    return {
      mode: 'visual',
      activeSection: initialSection,
      activeRealm: initialRealm,
      config: JSON.parse(JSON.stringify(initialConfig)),
      originalConfig: JSON.stringify(initialConfig),
      csrf: document.querySelector('meta[name="csrf"]')?.content || '',
      saving: false,
      errors: {},
      validating: false,
      validationPassed: false,
      showingExport: false,
      exportCopied: false,
      exportYaml: '',
      exportLoading: false,

      sections: [
        { key: 'server', label: 'Server' },
        { key: 'storage', label: 'Storage' },
        { key: 'observability', label: 'Logging' },
        { key: 'operational', label: 'Limits' },
        { key: 'branding', label: 'Branding' },
        { key: 'email', label: 'Email' },
        { key: 'oidc', label: 'OIDC' },
        { key: 'token', label: 'Tokens' },
        { key: 'auth', label: 'Auth' },
        { key: 'onboarding', label: 'Onboarding' },
      ],

      get realmKeys() { return Object.keys(this.config.realms || {}); },
      get activeAppKeys() {
        const realm = this.config.realms && this.config.realms[this.activeRealm];
        return realm && realm.applications ? Object.keys(realm.applications) : [];
      },
      get activeOrgKeys() {
        const realm = this.config.realms && this.config.realms[this.activeRealm];
        return realm && realm.organizations ? Object.keys(realm.organizations) : [];
      },

      // Hides the SSR fallback div and syncs the YAML textarea mirror
      // once Alpine mounts. Replaces x-init on the component root and the
      // textarea element respectively so those x-init expressions don't
      // need to carry function literals (unsupported by the CSP evaluator).
      init() {
        queueMicrotask(() => {
          const f = document.getElementById('ssr-editor-fallback');
          if (f) f.style.display = 'none';
        });
      },
      initTextarea() {
        this.$nextTick(() => {
          this.syncMirror();
          this.syncMirrorScroll();
        });
      },

      // Boolean realm setting — converts 'true'/'false'/'' to true/false/deleted.
      setRealmBool(path, val) {
        const parts = path.split('.');
        if (parts.some(p => p === '__proto__' || p === 'constructor' || p === 'prototype')) return;
        let obj = this.config;
        for (let i = 0; i < parts.length - 1; i++) {
          if (obj[parts[i]] === undefined || obj[parts[i]] === null) obj[parts[i]] = {};
          obj = obj[parts[i]];
        }
        const key = parts[parts.length - 1];
        if (val === 'true') obj[key] = true;
        else if (val === 'false') obj[key] = false;
        else delete obj[key];
        delete this.errors[path];
      },

      // Comma-separated list realm setting — splits, trims, filters.
      setRealmList(path, val) {
        const items = val.split(',').map(s => s.trim()).filter(s => s);
        if (items.length === 0) {
          this.setVal(path, '');
        } else {
          const parts = path.split('.');
          if (parts.some(p => p === '__proto__' || p === 'constructor' || p === 'prototype')) return;
          let obj = this.config;
          for (let i = 0; i < parts.length - 1; i++) {
            if (obj[parts[i]] === undefined || obj[parts[i]] === null) obj[parts[i]] = {};
            obj = obj[parts[i]];
          }
          obj[parts[parts.length - 1]] = items;
          delete this.errors[path];
        }
      },

      // Navigation helpers — used in editor.html and _editor_sections.html
      // instead of multi-statement expressions (CSP evaluator has no semicolons).
      setSection(key) { this.activeSection = key; this.activeRealm = null; },
      setRealmSection(rk) { this.activeSection = 'realm'; this.activeRealm = rk; },
      setMode(m) { this.mode = m; },

      ensure(path) {
        const parts = path.split('.');
        let obj = this.config;
        for (const p of parts) {
          if (obj[p] === undefined || obj[p] === null) obj[p] = {};
          obj = obj[p];
        }
      },

      getVal(path, fallback) {
        const parts = path.split('.');
        if (parts.some(p => p === '__proto__' || p === 'constructor' || p === 'prototype')) return fallback;
        let obj = this.config;
        for (const p of parts) {
          if (obj === undefined || obj === null) return fallback;
          obj = obj[p];
        }
        return obj !== undefined && obj !== null ? obj : fallback;
      },

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
      },

      addRealm() {
        const name = prompt('Realm slug (lowercase, hyphens):');
        if (!name) return;
        if (!this.config.realms) this.config.realms = {};
        this.config.realms[name] = {};
        this.activeSection = 'realm';
        this.activeRealm = name;
      },
      removeRealm(key) {
        if (!confirm('Remove realm "' + key + '" from config?')) return;
        delete this.config.realms[key];
        if (this.activeRealm === key) {
          this.activeRealm = null;
          this.activeSection = 'server';
        }
      },

      addApp(realm) {
        const key = prompt('Application key (lowercase, hyphens):');
        if (!key) return;
        if (!this.config.realms[realm].applications) this.config.realms[realm].applications = {};
        this.config.realms[realm].applications[key] = { name: key, redirect_uris: [], grant_types: ['authorization_code'] };
      },
      removeApp(realm, key) {
        if (confirm('Remove application "' + key + '"?')) {
          delete this.config.realms[realm].applications[key];
        }
      },

      addOrg(realm) {
        const slug = prompt('Organization slug (lowercase, hyphens):');
        if (!slug) return;
        if (!this.config.realms[realm].organizations) this.config.realms[realm].organizations = {};
        this.config.realms[realm].organizations[slug] = { name: slug };
      },
      removeOrg(realm, key) {
        if (confirm('Remove organization "' + key + '"?')) {
          delete this.config.realms[realm].organizations[key];
        }
      },

      getList(path) { return this.getVal(path, []) || []; },
      addListItem(path) {
        this.ensure(path.split('.').slice(0, -1).join('.'));
        const parts = path.split('.');
        let obj = this.config;
        for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
        const key = parts[parts.length - 1];
        if (!Array.isArray(obj[key])) obj[key] = [];
        obj[key].push('');
      },
      removeListItem(path, idx) {
        const parts = path.split('.');
        let obj = this.config;
        for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
        obj[parts[parts.length - 1]].splice(idx, 1);
      },

      fieldClass(path) {
        if (this.errors[path]) {
          return 'mt-1.5 block w-full rounded-sm border border-danger/60 ring-1 ring-danger/30 bg-ht-surface-input px-3 py-2 text-sm text-ht-content-primary focus:border-danger/60 focus:outline-none focus:ring-1 focus:ring-danger/30';
        }
        return 'mt-1.5 block w-full rounded-sm border border-divider bg-ht-surface-input px-3 py-2 text-sm text-ht-content-primary focus:border-brand-ember focus:outline-none focus:ring-1 focus:ring-brand-ember';
      },

      hasInlineError(key) {
        try { return !!document.querySelector("p[x-show*=\"errors['" + key + "']\"]"); }
        catch { return false; }
      },

      async validate() {
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
            setTimeout(() => { this.validationPassed = false; }, 4000);
          }
          return result.valid;
        } finally {
          this.validating = false;
        }
      },

      reset() {
        this.config = JSON.parse(this.originalConfig);
        this.errors = {};
        const diff = document.getElementById('diff-output');
        if (diff) diff.innerHTML = '';
      },

      resetRawEditor() {
        const ta = document.getElementById('yaml-editor');
        if (ta) ta.value = ta.defaultValue;
        const diff = document.getElementById('diff-output');
        if (diff) diff.innerHTML = '';
      },

      async preview() {
        if (this.mode === 'visual') {
          const resp = await fetch('/ui/admin/settings/editor/visual/preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': this.csrf },
            body: JSON.stringify(this.config),
          });
          document.getElementById('diff-output').innerHTML = await resp.text();
        } else {
          htmx.ajax('POST', '/ui/admin/settings/editor/preview',
            { target: '#diff-output', values: { yaml: document.getElementById('yaml-editor').value } });
        }
      },

      syncMirror() {
        const ta = document.getElementById('yaml-editor');
        const mirror = document.getElementById('yaml-mirror');
        if (!ta || !mirror) return;
        mirror.innerHTML = highlightYaml(ta.value + '\n');
      },
      syncMirrorScroll() {
        const ta = document.getElementById('yaml-editor');
        const mirror = document.getElementById('yaml-mirror');
        if (!ta || !mirror) return;
        mirror.scrollTop = ta.scrollTop;
        mirror.scrollLeft = ta.scrollLeft;
      },

      async openExport() {
        this.showingExport = true;
        this.exportLoading = true;
        this.exportCopied = false;
        try {
          if (this.mode === 'raw') {
            this.exportYaml = document.getElementById('yaml-editor').value;
          } else {
            const resp = await fetch('/ui/admin/settings/editor/visual/export', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': this.csrf },
              body: JSON.stringify(this.config),
            });
            if (!resp.ok) throw new Error(await resp.text());
            this.exportYaml = await resp.text();
          }
          this.$nextTick(() => renderExportHighlight(this.exportYaml));
        } catch (e) {
          this.exportYaml = '# Error generating YAML:\n# ' + e.message;
          this.$nextTick(() => renderExportHighlight(this.exportYaml));
        } finally {
          this.exportLoading = false;
        }
      },

      copyExport() {
        navigator.clipboard.writeText(this.exportYaml).then(() => {
          this.exportCopied = true;
          setTimeout(() => { this.exportCopied = false; }, 2000);
        });
      },

      async apply() {
        if (this.saving) return;
        this.saving = true;
        try {
          if (this.mode === 'visual') {
            const valid = await this.validate();
            if (!valid) { this.saving = false; return; }
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
              }
              document.getElementById('diff-output').innerHTML =
                '<div class="rounded-md bg-danger/[0.12] px-6 py-4 text-sm text-danger-fg ring-1 ring-danger/30">' +
                '<h3 class="font-semibold">Error</h3><p class="mt-1 font-mono text-xs">' + result.error + '</p></div>';
            }
          } else {
            document.getElementById('apply-form').submit();
          }
        } finally {
          this.saving = false;
        }
      },
    };
  });
});

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

// Bridge HTMX HX-Trigger "showToast" events into Alpine's custom event system
document.body.addEventListener('showToast', function(e) {
  var d = typeof e.detail === 'string' ? JSON.parse(e.detail) : e.detail;
  window.dispatchEvent(new CustomEvent('show-toast', {detail: d}));
});

// Global keyboard shortcuts. Bound on `keydown` for cross-browser key
// reliability, and bail when focus is in a text-bearing control so '/'
// doesn't steal keystrokes from the inputs we want to focus.
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
