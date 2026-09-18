import preact from "@preact/preset-vite";
import { defineConfig } from "vitest/config";

export default defineConfig(({ command }) => {
  const backendTarget = process.env.INDEX_DEV_BACKEND_URL;
  const publicHost = process.env.INDEX_DEV_PUBLIC_HOST;
  const routedDevelopment = command === "serve" && backendTarget && publicHost;

  return {
    plugins: [preact()],
    cacheDir: process.env.INDEX_VITE_CACHE_DIR,
    server: routedDevelopment
      ? {
          host: "0.0.0.0",
          port: 5173,
          strictPort: true,
          allowedHosts: [publicHost],
          hmr: {
            protocol: "wss",
            host: publicHost,
            clientPort: 443,
          },
          proxy: {
            "/api": {
              target: backendTarget,
              changeOrigin: false,
            },
            "/health": {
              target: backendTarget,
              changeOrigin: false,
            },
          },
        }
      : undefined,
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test-setup.ts"],
      include: ["src/**/*.test.{ts,tsx}"],
    },
    build: {
      outDir: "dist",
      emptyOutDir: true,
    },
  };
});
