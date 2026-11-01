import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/v1': {
        target: 'http://localhost:8001',
        changeOrigin: true,
        ws: true,
      },
      '/healthz': 'http://localhost:8001',
    },
  },
});

