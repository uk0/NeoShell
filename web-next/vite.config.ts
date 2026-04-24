import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build output goes directly into ../website/dist so we can rsync only the
// built assets up to bwg1 without any extra layer.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: "assets",
    // Inline tiny files (fonts etc) when under 4 KB to cut round-trips.
    assetsInlineLimit: 4096,
    cssCodeSplit: true,
    rollupOptions: {
      output: {
        manualChunks: {
          motion: ["framer-motion"],
        },
      },
    },
  },
  server: {
    port: 5173,
  },
});
