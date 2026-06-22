/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ['@hearth-auth/sdk'],
  webpack: (config) => {
    // Resolve .js imports to .ts source files for unbuilt local SDK packages.
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js'],
      '.mjs': ['.mts', '.mjs'],
    };
    return config;
  },
};

module.exports = nextConfig;
