/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  guidesSidebar: [
    {
      type: 'category',
      label: 'Getting Started',
      collapsed: false,
      items: [
        'getting-started',
        'local-dev',
        'concepts',
      ],
    },
    {
      type: 'category',
      label: 'Configuration',
      items: [
        'hearth-yaml-examples',
        'config-migration',
        'error-codes',
      ],
    },
    {
      type: 'category',
      label: 'Identity & Auth',
      items: [
        'rbac',
        'permission-delivery',
        'client-scoped-roles',
        'organizations',
        'required-actions',
        'sms-mfa-deployment',
        'session-version-revocation',
        'webhooks',
        'federation',
        'scim-provisioning',
      ],
    },
    {
      type: 'category',
      label: 'Security',
      items: [
        'security-model',
        'fapi2',
      ],
    },
    {
      type: 'category',
      label: 'Operations',
      items: [
        'admin-api',
        'api-reference',
        'auditing',
        'backup',
        'clustering',
        'storage-sizing',
        'security-hardening',
        'data-retention',
        'privacy',
        'troubleshooting',
        'disaster-recovery',
        'verify-release',
      ],
    },
    {
      type: 'category',
      label: 'SDKs',
      link: { type: 'doc', id: 'sdks/overview' },
      items: [
        'sdks/typescript',
        'sdks/go',
        'sdks/migration-from-keycloak',
      ],
    },
    {
      type: 'category',
      label: 'Migration',
      items: [
        'migrating-from-keycloak',
        'migrating-from-auth0',
      ],
    },
  ],
};

module.exports = sidebars;
