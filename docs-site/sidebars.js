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
        {
          type: 'category',
          label: 'hearth.yaml Examples',
          link: { type: 'doc', id: 'hearth-yaml-examples/index' },
          items: [
            'hearth-yaml-examples/basics',
            'hearth-yaml-examples/passwordless',
            'hearth-yaml-examples/mfa',
            'hearth-yaml-examples/federation',
            'hearth-yaml-examples/email',
            'hearth-yaml-examples/tls',
            'hearth-yaml-examples/multi-tenancy',
            'hearth-yaml-examples/rbac-and-oauth',
            'hearth-yaml-examples/enterprise',
            'hearth-yaml-examples/branding-and-complex',
          ],
        },
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
        'sdks/node',
        'sdks/go',
        'sdks/python',
        'sdks/rust',
        'sdks/php',
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
