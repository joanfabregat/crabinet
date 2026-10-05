import { useEffect, useRef, useState } from "preact/hooks";
import type { PDFDocumentLoadingTask, RenderTask } from "pdfjs-dist";
import workerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url";

import { LoadingSpinner } from "./loading-spinner";

/** Upper bound on the page canvas backing store, in device pixels. */
export const MAX_CANVAS_PIXELS = 16 * 1024 * 1024;
/** pdf.js skips embedded images larger than this many pixels. */
const MAX_IMAGE_PIXELS = 50_000_000;
/** Width used when the container has not been laid out yet. */
const FALLBACK_WIDTH = 800;

type PdfJs = typeof import("pdfjs-dist");

let pdfjsPromise: Promise<PdfJs> | null = null;

/** Loads pdf.js on first use, as its own chunk, with a same-origin worker. */
function loadPdfJs(): Promise<PdfJs> {
  pdfjsPromise ??= import("pdfjs-dist").then(
    (pdfjs) => {
      pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;
      return pdfjs;
    },
    (error: unknown) => {
      pdfjsPromise = null;
      throw error;
    },
  );
  return pdfjsPromise;
}

/**
 * Where pdf.js finds the files it loads by name. Production builds copy them
 * into a versioned directory under `assets/` (see `vite.config.ts`); the
 * development server serves them from the package itself.
 */
function pdfjsDataUrl(version: string, directory: string): string {
  const base = import.meta.env.DEV
    ? `${import.meta.env.BASE_URL}node_modules/pdfjs-dist/`
    : `${import.meta.env.BASE_URL}assets/pdfjs-${version}/`;
  return new URL(`${base}${directory}/`, document.baseURI).href;
}

type Failure = "password" | "invalid" | "network" | "render";

type State =
  | { status: "loading" }
  | { status: "rendered" }
  | { status: "failed"; failure: Failure };

function classify(error: unknown): Failure {
  const name =
    error && typeof error === "object" && "name" in error
      ? String(error.name)
      : "";
  if (name === "PasswordException") return "password";
  if (name === "InvalidPDFException" || name === "FormatError")
    return "invalid";
  if (name === "ResponseException" || name === "UnexpectedResponseException")
    return "network";
  if (error instanceof TypeError) return "network";
  return "render";
}

const failureText: Record<Failure, string> = {
  password: "This PDF is password-protected.",
  invalid: "This file could not be read as a PDF.",
  network: "The PDF could not be loaded.",
  render: "The first page could not be rendered.",
};

/**
 * Picks the render scale so the page fills `cssWidth` CSS pixels at the
 * device pixel ratio, without the canvas exceeding {@link MAX_CANVAS_PIXELS}.
 */
export function canvasScale(
  pageWidth: number,
  pageHeight: number,
  cssWidth: number,
  devicePixelRatio: number,
): number {
  if (
    !(pageWidth > 0 && pageHeight > 0) ||
    !Number.isFinite(pageWidth * pageHeight)
  ) {
    throw new RangeError("Invalid page size");
  }
  const ratio =
    Number.isFinite(devicePixelRatio) && devicePixelRatio > 0
      ? Math.min(devicePixelRatio, 4)
      : 1;
  const desired = (Math.max(cssWidth, 1) / pageWidth) * ratio;
  const ceiling = Math.sqrt(MAX_CANVAS_PIXELS / (pageWidth * pageHeight));
  return Math.min(desired, ceiling);
}

/**
 * Renders the first page of a same-origin PDF into a canvas. The full
 * document is left to the browser's own viewer.
 */
export function PdfFirstPage({
  url,
  filename,
}: {
  url: string;
  filename: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    let loadingTask: PDFDocumentLoadingTask | null = null;
    let renderTask: RenderTask | null = null;
    setState({ status: "loading" });

    // Destroying the loading task aborts the fetch, destroys the document,
    // and terminates its worker.
    const release = () => {
      const task = loadingTask;
      loadingTask = null;
      task?.destroy().catch(() => {});
    };

    const run = async () => {
      const pdfjs = await loadPdfJs();
      if (cancelled) return;
      loadingTask = pdfjs.getDocument({
        url,
        // Same-origin requests carry the session cookie either way.
        withCredentials: false,
        // Fetch only the byte ranges page 1 needs when the server allows it.
        disableRange: false,
        disableStream: true,
        disableAutoFetch: true,
        // The app CSP has no 'wasm-unsafe-eval': use the JavaScript decoders.
        useWasm: false,
        wasmUrl: pdfjsDataUrl(pdfjs.version, "wasm"),
        cMapUrl: pdfjsDataUrl(pdfjs.version, "cmaps"),
        cMapPacked: true,
        standardFontDataUrl: pdfjsDataUrl(pdfjs.version, "standard_fonts"),
        useSystemFonts: true,
        enableXfa: false,
        maxImageSize: MAX_IMAGE_PIXELS,
        canvasMaxAreaInBytes: MAX_CANVAS_PIXELS * 4,
        verbosity: pdfjs.VerbosityLevel.ERRORS,
      });
      const pdf = await loadingTask.promise;
      if (cancelled) return;
      const page = await pdf.getPage(1);
      const canvas = canvasRef.current;
      if (cancelled || !canvas) return;

      const unit = page.getViewport({ scale: 1 });
      const scale = canvasScale(
        unit.width,
        unit.height,
        containerRef.current?.clientWidth || FALLBACK_WIDTH,
        window.devicePixelRatio,
      );
      const viewport = page.getViewport({ scale });
      canvas.width = Math.max(1, Math.floor(viewport.width));
      canvas.height = Math.max(1, Math.floor(viewport.height));
      // Annotations are not drawn: no form widgets, links, or scripts.
      renderTask = page.render({
        canvas,
        viewport,
        annotationMode: pdfjs.AnnotationMode.DISABLE,
      });
      await renderTask.promise;
      renderTask = null;
      if (cancelled) return;
      // The pixels stay on the canvas; the document and worker are not needed.
      release();
      setState({ status: "rendered" });
    };

    run().catch((error: unknown) => {
      if (cancelled) return;
      release();
      setState({ status: "failed", failure: classify(error) });
    });

    return () => {
      cancelled = true;
      renderTask?.cancel();
      release();
    };
  }, [url]);

  return (
    <div class="pdf-first-page" ref={containerRef}>
      {state.status === "loading" && (
        <div class="preview-loading-frame is-loading">
          <LoadingSpinner />
        </div>
      )}
      {state.status === "failed" && (
        <div class="preview-error" role="alert">
          <p>{failureText[state.failure]}</p>
          <p>Open it in a new tab or download it to view it.</p>
        </div>
      )}
      {/* Keyed by URL so a superseded render can only paint a detached canvas. */}
      <canvas
        key={url}
        ref={canvasRef}
        role="img"
        aria-label={`First page of ${filename}`}
        style={{
          display: state.status === "rendered" ? "block" : "none",
          width: "100%",
          height: "auto",
        }}
      />
    </div>
  );
}
