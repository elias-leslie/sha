/** @type {import('next').NextConfig} */
const apiUrl = process.env.API_URL || 'http://127.0.0.1:8010'

const nextConfig = {
  // A demo build can be produced without clobbering the production build
  // that the systemd service serves: NEXT_DIST_DIR=.next-demo pnpm build
  distDir: process.env.NEXT_DIST_DIR || '.next',
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/health',
        destination: `${apiUrl}/health`,
      },
    ]
  },
}

export default nextConfig
