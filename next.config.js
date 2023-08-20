/** @type {import('next').NextConfig} */
const nextConfig = {
    output: 'export',
    experimental: {
        appDir: true,
    },
    images: {
        unoptimized: true
    },
    trailingSlash: true
};
module.exports = nextConfig;
