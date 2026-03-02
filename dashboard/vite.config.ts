import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-react': ['react', 'react-dom'],
          'vendor-antd': ['antd', '@ant-design/pro-components'],
          'vendor-charts': ['recharts'],
          'vendor-router': ['@tanstack/react-router', '@tanstack/react-query'],
        },
      },
    },
  },
});
