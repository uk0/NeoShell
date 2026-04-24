import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build output goes directly into dist/ so we can rsync only the built
// assets up to bwg1 without any extra layer.
const BUILD_ID = new Date().toISOString().replace(/[-:T.Z]/g, "").slice(0, 14);

export default defineConfig({
  plugins: [
    react(),
    // Stamp the current build id into index.html so the runtime can
    // compare it with the JS bundle's baked-in __BUILD_ID__ and force
    // a reload when a stale HTML sneaks past every cache layer.
    {
      name: "build-id-html",
      transformIndexHtml(html) {
        return html.replace(/%BUILD_ID%/g, BUILD_ID);
      },
    },
  ],
  define: {
    __BUILD_ID__: JSON.stringify(BUILD_ID),
  },
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
