/** @type {import('next').NextConfig} */
const apiUrl = process.env.API_URL || 'http://127.0.0.1:8010'

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${apiUrl}/api/:path*`,
      },
      {
        source: '/health',
        destination: `${apiUrl}/health`,
      },
    ]
  },
}

export default nextConfig
