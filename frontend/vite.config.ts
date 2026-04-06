import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://0.0.0.0:3001',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://0.0.0.0:3001',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://0.0.0.0:3001',
        ws: true,
      },
    },
  },
})
