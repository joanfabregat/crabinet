import { render, screen, waitFor } from "@testing-library/preact";
import { beforeEach, describe, expect, it, vi } from "vitest";

const pdfjs = vi.hoisted(() => ({
  GlobalWorkerOptions: { workerSrc: "" },
  version: "0.0.0-test",
  VerbosityLevel: { ERRORS: 0 },
  AnnotationMode: { DISABLE: 0, ENABLE: 1 },
  getDocument: vi.fn(),
}));

vi.mock("pdfjs-dist", () => pdfjs);
vi.mock("pdfjs-dist/build/pdf.worker.min.mjs?url", () => ({
  default: "/assets/pdf.worker.min-test.mjs",
}));

import { canvasScale, MAX_CANVAS_PIXELS, PdfFirstPage } from "./pdf-preview";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

class NamedError extends Error {
  constructor(name: string) {
    super(name);
    this.name = name;
  }
}

/** A controllable stand-in for one pdf.js loading task and its page. */
function fakeDocument() {
  const load = deferred<unknown>();
  const draw = deferred<void>();
  const renderTask = { promise: draw.promise, cancel: vi.fn() };
  const page = {
    getViewport: ({ scale }: { scale: number }) => ({
      width: 600 * scale,
      height: 800 * scale,
    }),
    render: vi.fn<
      (parameters: { canvas: HTMLCanvasElement }) => typeof renderTask
    >(() => renderTask),
  };
  const getPage = vi.fn(async () => page);
  const task = {
    promise: load.promise,
    destroy: vi.fn(async () => {}),
  };
  return {
    task,
    page,
    renderTask,
    getPage,
    open: () => load.resolve({ getPage }),
    fail: (error: unknown) => load.reject(error),
    finishRender: () => draw.resolve(),
  };
}

beforeEach(() => {
  pdfjs.getDocument.mockReset();
});

describe("PdfFirstPage", () => {
  it("shows a status while loading, then the first page as an image", async () => {
    const pdf = fakeDocument();
    pdfjs.getDocument.mockReturnValue(pdf.task);

    render(<PdfFirstPage url="/api/pdf?path=a.pdf" filename="a.pdf" />);
    expect(
      screen.getByRole("status", { name: "Loading preview" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("img")).toBeNull();

    await waitFor(() => expect(pdfjs.getDocument).toHaveBeenCalledOnce());
    pdf.open();
    await waitFor(() => expect(pdf.page.render).toHaveBeenCalledOnce());
    pdf.finishRender();

    const image = await screen.findByRole("img", {
      name: "First page of a.pdf",
    });
    expect(image.tagName).toBe("CANVAS");
    expect(screen.queryByRole("status")).toBeNull();
    expect(pdf.getPage).toHaveBeenCalledExactlyOnceWith(1);
    // The document and its worker are released once the pixels are drawn.
    expect(pdf.task.destroy).toHaveBeenCalledOnce();
    expect(pdfjs.GlobalWorkerOptions.workerSrc).toBe(
      "/assets/pdf.worker.min-test.mjs",
    );
  });

  it("asks pdf.js for a range-loaded, script-free, WebAssembly-free render", async () => {
    const pdf = fakeDocument();
    pdfjs.getDocument.mockReturnValue(pdf.task);

    render(<PdfFirstPage url="/api/pdf?path=a.pdf" filename="a.pdf" />);
    await waitFor(() => expect(pdfjs.getDocument).toHaveBeenCalledOnce());
    const options = pdfjs.getDocument.mock.calls[0]?.[0] as Record<
      string,
      unknown
    >;
    expect(options).toMatchObject({
      url: "/api/pdf?path=a.pdf",
      withCredentials: false,
      disableRange: false,
      disableStream: true,
      disableAutoFetch: true,
      useWasm: false,
      enableXfa: false,
      cMapPacked: true,
    });
    for (const key of ["cMapUrl", "standardFontDataUrl", "wasmUrl"]) {
      const value = new URL(String(options[key]));
      expect(value.origin).toBe(window.location.origin);
      expect(value.pathname.endsWith("/")).toBe(true);
    }

    pdf.open();
    await waitFor(() => expect(pdf.page.render).toHaveBeenCalledOnce());
    expect(pdf.page.render.mock.calls[0]?.[0]).toMatchObject({
      annotationMode: pdfjs.AnnotationMode.DISABLE,
    });
  });

  it.each([
    ["PasswordException", "This PDF is password-protected."],
    ["InvalidPDFException", "This file could not be read as a PDF."],
    ["ResponseException", "The PDF could not be loaded."],
    ["AbortException", "The first page could not be rendered."],
  ])(
    "explains a %s and points to the other ways to open the file",
    async (name, message) => {
      const pdf = fakeDocument();
      pdfjs.getDocument.mockReturnValue(pdf.task);

      render(<PdfFirstPage url="/api/pdf?path=b.pdf" filename="b.pdf" />);
      await waitFor(() => expect(pdfjs.getDocument).toHaveBeenCalledOnce());
      pdf.fail(new NamedError(name));

      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(message);
      expect(alert).toHaveTextContent(
        "Open it in a new tab or download it to view it.",
      );
      expect(screen.queryByRole("img")).toBeNull();
      expect(screen.queryByRole("status")).toBeNull();
      expect(pdf.task.destroy).toHaveBeenCalledOnce();
    },
  );

  it("reports a failed render rather than a blank page", async () => {
    const pdf = fakeDocument();
    pdfjs.getDocument.mockReturnValue(pdf.task);
    pdf.page.getViewport = () => ({ width: 0, height: 0 });

    render(<PdfFirstPage url="/api/pdf?path=c.pdf" filename="c.pdf" />);
    await waitFor(() => expect(pdfjs.getDocument).toHaveBeenCalledOnce());
    pdf.open();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The first page could not be rendered.",
    );
    expect(pdf.page.render).not.toHaveBeenCalled();
  });

  it("destroys the loading task when unmounted while loading", async () => {
    const pdf = fakeDocument();
    pdfjs.getDocument.mockReturnValue(pdf.task);

    const view = render(
      <PdfFirstPage url="/api/pdf?path=d.pdf" filename="d.pdf" />,
    );
    await waitFor(() => expect(pdfjs.getDocument).toHaveBeenCalledOnce());
    view.unmount();

    expect(pdf.task.destroy).toHaveBeenCalledOnce();
    pdf.open();
    await Promise.resolve();
    expect(pdf.getPage).not.toHaveBeenCalled();
  });

  it("cancels the render and destroys the document when unmounted mid-render", async () => {
    const pdf = fakeDocument();
    pdfjs.getDocument.mockReturnValue(pdf.task);

    const view = render(
      <PdfFirstPage url="/api/pdf?path=e.pdf" filename="e.pdf" />,
    );
    await waitFor(() => expect(pdfjs.getDocument).toHaveBeenCalledOnce());
    pdf.open();
    await waitFor(() => expect(pdf.page.render).toHaveBeenCalledOnce());
    view.unmount();

    expect(pdf.renderTask.cancel).toHaveBeenCalledOnce();
    expect(pdf.task.destroy).toHaveBeenCalledOnce();
  });

  it("never lets a superseded document paint or change the state", async () => {
    const first = fakeDocument();
    const second = fakeDocument();
    pdfjs.getDocument
      .mockReturnValueOnce(first.task)
      .mockReturnValueOnce(second.task);

    const view = render(
      <PdfFirstPage url="/api/pdf?path=first.pdf" filename="first.pdf" />,
    );
    await waitFor(() => expect(pdfjs.getDocument).toHaveBeenCalledOnce());
    first.open();
    await waitFor(() => expect(first.page.render).toHaveBeenCalledOnce());

    view.rerender(
      <PdfFirstPage url="/api/pdf?path=second.pdf" filename="second.pdf" />,
    );
    expect(first.renderTask.cancel).toHaveBeenCalledOnce();
    expect(first.task.destroy).toHaveBeenCalledOnce();
    await waitFor(() => expect(pdfjs.getDocument).toHaveBeenCalledTimes(2));

    second.open();
    await waitFor(() => expect(second.page.render).toHaveBeenCalledOnce());
    second.finishRender();
    const image = await screen.findByRole("img", {
      name: "First page of second.pdf",
    });

    // The stale render targeted a different, detached canvas.
    const staleCanvas = first.page.render.mock.calls[0]?.[0].canvas;
    expect(staleCanvas).not.toBe(image);
    expect(staleCanvas?.isConnected).toBe(false);
    expect(second.page.render.mock.calls[0]?.[0].canvas).toBe(image);

    // A late completion or failure of the first document changes nothing.
    first.finishRender();
    await Promise.resolve();
    expect(screen.getByRole("img")).toBe(image);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("ignores a superseded document that fails late", async () => {
    const first = fakeDocument();
    const second = fakeDocument();
    pdfjs.getDocument
      .mockReturnValueOnce(first.task)
      .mockReturnValueOnce(second.task);

    const view = render(
      <PdfFirstPage url="/api/pdf?path=first.pdf" filename="first.pdf" />,
    );
    await waitFor(() => expect(pdfjs.getDocument).toHaveBeenCalledOnce());
    view.rerender(
      <PdfFirstPage url="/api/pdf?path=second.pdf" filename="second.pdf" />,
    );
    await waitFor(() => expect(pdfjs.getDocument).toHaveBeenCalledTimes(2));
    first.fail(new NamedError("InvalidPDFException"));
    await Promise.resolve();

    expect(screen.queryByRole("alert")).toBeNull();
    expect(
      screen.getByRole("status", { name: "Loading preview" }),
    ).toBeInTheDocument();
    expect(first.getPage).not.toHaveBeenCalled();
  });
});

describe("canvasScale", () => {
  it("fills the container width at the device pixel ratio", () => {
    expect(canvasScale(600, 800, 300, 2)).toBeCloseTo(1);
    expect(canvasScale(600, 800, 600, 1)).toBeCloseTo(1);
  });

  it("caps the canvas backing store", () => {
    const scale = canvasScale(612, 792, 4000, 3);
    const pixels = 612 * scale * (792 * scale);
    expect(pixels).toBeLessThanOrEqual(MAX_CANVAS_PIXELS + 1);
    expect(pixels).toBeGreaterThan(MAX_CANVAS_PIXELS * 0.99);
  });

  it("bounds hostile device pixel ratios", () => {
    expect(canvasScale(600, 800, 600, Number.NaN)).toBeCloseTo(1);
    expect(canvasScale(600, 800, 60, 1000)).toBeCloseTo(0.4);
  });

  it("rejects degenerate page sizes", () => {
    for (const [width, height] of [
      [0, 800],
      [600, -1],
      [Number.NaN, 800],
      [Number.MAX_VALUE, Number.MAX_VALUE],
    ] as const) {
      expect(() => canvasScale(width, height, 600, 1)).toThrow(RangeError);
    }
  });
});
