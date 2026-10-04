import preact from "@preact/preset-vite";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

// pdf.js loads its CMaps, standard fonts, and non-WebAssembly image decoders
// by file name from a base URL, so they cannot take Vite's hashed names. The
// build copies the files the PDF preview needs, unchanged, into a versioned
// directory under `assets/`, which the server already embeds and caches as
// immutable. `src/pdf-preview.tsx` derives the same directory from pdf.js's
// runtime version. Liberation fonts (GPL-2.0 with a font exception) and the
// WebAssembly binaries are deliberately left out: the browser's system fonts
// stand in for Helvetica, and the app CSP blocks WebAssembly anyway.
function pdfjsAssets(): Plugin {
  const require = createRequire(import.meta.url);
  const packageRoot = dirname(require.resolve("pdfjs-dist/package.json"));
  const { version } = JSON.parse(
    readFileSync(join(packageRoot, "package.json"), "utf8"),
  ) as { version: string };
  const groups: [directory: string, include: RegExp][] = [
    ["cmaps", /\.bcmap$/],
    ["standard_fonts", /^Foxit[A-Za-z]+\.pfb$/],
    ["wasm", /^(openjpeg|jbig2)_nowasm_fallback\.js$/],
  ];
  return {
    name: "crabinet-pdfjs-assets",
    apply: "build",
    generateBundle() {
      for (const [directory, include] of groups) {
        for (const name of readdirSync(join(packageRoot, directory))) {
          if (!include.test(name)) continue;
          this.emitFile({
            type: "asset",
            fileName: `assets/pdfjs-${version}/${directory}/${name}`,
            source: readFileSync(join(packageRoot, directory, name)),
          });
        }
      }
    },
  };
}

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
  const backendTarget =
    process.env.CRABINET_DEV_BACKEND_URL ?? process.env.INDEX_DEV_BACKEND_URL;
  const publicHost =
    process.env.CRABINET_DEV_PUBLIC_HOST ?? process.env.INDEX_DEV_PUBLIC_HOST;
  const routedDevelopment = command === "serve" && backendTarget && publicHost;
  const revision = gitRevision(
    process.env.CRABINET_DEV_GIT_DIR ?? process.env.INDEX_DEV_GIT_DIR,
  );

  return {
    plugins: [preact(), pdfjsAssets()],
    define: {
      __CRABINET_DEV_REVISION__: JSON.stringify(revision),
    },
    cacheDir:
      process.env.CRABINET_VITE_CACHE_DIR ?? process.env.INDEX_VITE_CACHE_DIR,
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
