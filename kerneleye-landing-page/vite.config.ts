import path from "path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  base: './',
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    // Enable SSR for SEO
    ssr: false,
    // Generate static HTML for pre-rendering
    rollupOptions: {
      output: {
        manualChunks: undefined,
      },
    },
  },
});
