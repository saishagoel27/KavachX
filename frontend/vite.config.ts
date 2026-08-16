import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const backend = env.VITE_DEV_PROXY_TARGET || 'http://127.0.0.1:8000'

  // Proxy is only used when VITE_API_BASE_URL is empty (same-origin mode).
  // With an absolute VITE_API_BASE_URL the browser calls the backend directly
  // and the backend's CORS_ALLOW_ORIGINS must include this dev origin.
  const proxy = { target: backend, changeOrigin: true }

  return {
    plugins: [react()],
    server: {
      port: Number(env.VITE_PORT || 5173),
      strictPort: false,
      proxy: {
        '/api': proxy,
        '/auth': proxy,
        '/health': proxy,
      },
    },
    preview: {
      port: Number(env.VITE_PREVIEW_PORT || 4173),
    },
  }
})
