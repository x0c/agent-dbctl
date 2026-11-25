import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const backend = process.env.AGENT_DBCTL_WEB_ORIGIN ?? 'http://127.0.0.1:8080'

export default defineConfig({
  base: '/',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(import.meta.dirname, './src') },
  },
  build: {
    outDir: path.resolve(import.meta.dirname, '../internal/webui/dist'),
    emptyOutDir: true,
    target: 'es2022',
    cssMinify: 'lightningcss',
    sourcemap: false,
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: 'react-vendor',
              test: /node_modules[/\\](?:react|react-dom|scheduler)[/\\]/,
              priority: 30,
            },
            {
              name: 'icons-vendor',
              test: /node_modules[/\\]lucide-react[/\\]/,
              priority: 20,
            },
            {
              name: 'ui-vendor',
              test: /node_modules[/\\]@x0c[/\\]/,
              priority: 15,
            },
          ],
        },
      },
    },
  },
  server: {
    port: 5176,
    proxy: {
      '/api': { target: backend, changeOrigin: false },
      '/healthz': { target: backend, changeOrigin: false },
    },
  },
})
