// @ts-check
const { themes: prismThemes } = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Hearth',
  tagline: 'Self-hosted identity. Sub-millisecond auth, zero dependencies.',
  favicon: 'img/favicon.svg',

  // Update url and baseUrl when GitHub Pages / custom domain is configured.
  // For a custom domain (e.g. docs.hearth.io) set baseUrl: '/'.
  // For a GitHub Pages project site (org.github.io/hearth) set baseUrl: '/hearth/'.
  url: 'https://hearthid.dev',
  baseUrl: '/',

  organizationName: 'hearth-id',
  projectName: 'hearth',
  trailingSlash: false,

  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',

  headTags: [
    {
      tagName: 'link',
      attributes: { rel: 'preconnect', href: 'https://fonts.googleapis.com' },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'preconnect',
        href: 'https://fonts.gstatic.com',
        crossorigin: 'anonymous',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'stylesheet',
        href: 'https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,400;0,9..144,500;1,9..144,400&family=JetBrains+Mono:wght@400;500&family=Manrope:wght@400;500;600&display=swap',
      },
    },
  ],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          // Single source of truth: read guides directly from the repo docs directory.
          path: '../docs/guides',
          routeBasePath: 'docs',
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl: 'https://github.com/hearth-id/hearth/edit/main/',
          versions: {
            current: {
              label: 'next',
              badge: true,
            },
          },
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  plugins: [
    [
      require.resolve('@easyops-cn/docusaurus-search-local'),
      {
        hashed: true,
        docsRouteBasePath: '/docs',
        language: ['en'],
        // Indexes h1–h3 headings as search entries for finer-grained results.
        indexBlog: false,
        indexPages: false,
        searchResultLimits: 8,
      },
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Force dark mode — no toggle, no light mode.
      colorMode: {
        defaultMode: 'dark',
        disableSwitch: true,
        respectPrefersColorScheme: false,
      },

      image: 'img/hearth-social.png',

      navbar: {
        title: 'Hearth',
        logo: {
          alt: 'Hearth — ember mark',
          src: 'img/logo.svg',
        },
        items: [
          {
            to: 'docs/getting-started',
            label: 'Get Started',
            position: 'left',
          },
          {
            type: 'docSidebar',
            sidebarId: 'guidesSidebar',
            position: 'left',
            label: 'Guides',
          },
          {
            to: 'docs/migrating-from-keycloak',
            label: 'Migrate from Keycloak',
            position: 'left',
          },
          {
            type: 'docsVersionDropdown',
            position: 'right',
          },
          {
            href: 'https://github.com/hearth-id/hearth',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },

      footer: {
        style: 'dark',
        links: [
          {
            title: 'Start here',
            items: [
              { label: 'Getting Started', to: 'docs/getting-started' },
              { label: 'Local Dev', to: 'docs/local-dev' },
              { label: 'Concepts', to: 'docs/concepts' },
              { label: 'Error Codes', to: 'docs/error-codes' },
            ],
          },
          {
            title: 'Identity & Auth',
            items: [
              { label: 'RBAC', to: 'docs/rbac' },
              { label: 'Organizations', to: 'docs/organizations' },
              { label: 'Webhooks', to: 'docs/webhooks' },
              { label: 'SCIM Provisioning', to: 'docs/scim-provisioning' },
              { label: 'Federation', to: 'docs/federation' },
            ],
          },
          {
            title: 'Operations',
            items: [
              { label: 'Admin API', to: 'docs/admin-api' },
              { label: 'Clustering', to: 'docs/clustering' },
              { label: 'Backup', to: 'docs/backup' },
              { label: 'Security Hardening', to: 'docs/security-hardening' },
              { label: 'Troubleshooting', to: 'docs/troubleshooting' },
            ],
          },
          {
            title: 'Migrate',
            items: [
              { label: 'From Keycloak', to: 'docs/migrating-from-keycloak' },
              { label: 'From Auth0', to: 'docs/migrating-from-auth0' },
              { label: 'GitHub', href: 'https://github.com/hearth-id/hearth' },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} Hearth. Built with Docusaurus.`,
      },

      prism: {
        // Use nightOwl for both modes — dark-only site, both slots needed by Docusaurus.
        theme: prismThemes.nightOwl,
        darkTheme: prismThemes.nightOwl,
        additionalLanguages: ['rust', 'bash', 'toml', 'yaml', 'json', 'protobuf'],
      },
    }),
};

module.exports = config;
