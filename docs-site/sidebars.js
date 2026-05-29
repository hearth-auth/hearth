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
        'client-scoped-roles',
        'organizations',
        'required-actions',
        'sms-mfa-deployment',
        'webhooks',
        'federation',
        'scim-provisioning',
      ],
    },
    {
      type: 'category',
      label: 'Operations',
      items: [
        'admin-api',
        'auditing',
        'backup',
        'clustering',
        'storage-sizing',
        'security-hardening',
        'troubleshooting',
        'disaster-recovery',
        'verify-release',
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
