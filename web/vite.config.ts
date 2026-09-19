import preact from "@preact/preset-vite";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { defineConfig } from "vitest/config";

function gitRevision(gitDirectory: string | undefined): string | null {
  if (!gitDirectory) return null;
  try {
    const head = readFileSync(join(gitDirectory, "HEAD"), "utf8").trim();
    if (!head.startsWith("ref: ")) return head.slice(0, 12);
    const reference = head.slice(5);
    const loose = join(gitDirectory, reference);
    if (existsSync(loose))
      return readFileSync(loose, "utf8").trim().slice(0, 12);
    const packed = readFileSync(join(gitDirectory, "packed-refs"), "utf8");
    const match = packed
      .split("\n")
      .find((line) => line.endsWith(` ${reference}`));
    return match?.split(" ")[0]?.slice(0, 12) ?? null;
  } catch {
    return null;
  }
}

export default defineConfig(({ command }) => {
  const backendTarget = process.env.INDEX_DEV_BACKEND_URL;
  const publicHost = process.env.INDEX_DEV_PUBLIC_HOST;
  const routedDevelopment = command === "serve" && backendTarget && publicHost;
  const revision = gitRevision(process.env.INDEX_DEV_GIT_DIR);

  return {
    plugins: [preact()],
    define: {
      __INDEX_DEV_REVISION__: JSON.stringify(revision),
    },
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
