import { describe, expect, it, vi } from "vitest";

import {
  ApiError,
  createApiClient,
  directoryEventsUrl,
  downloadUrl,
  htmlPreviewUrl,
  imagePreviewUrl,
  renderedHtmlPreviewUrl,
} from "./api";

describe("API client", () => {
  it("uses the versioned same-origin contract and encodes share and path values", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        shareId: "team/a",
        path: "R&D/東京",
        entries: [],
      }),
    );
    const api = createApiClient({ fetch });

    await api.directory("team/a", "R&D/東京", "opaque cursor");

    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe(
      "/api/v1/shares/team%2Fa/directory?path=R%26D%2F%E6%9D%B1%E4%BA%AC&limit=100&cursor=opaque+cursor",
    );
    expect(init).toMatchObject({ credentials: "same-origin" });
  });

  it("requests a directory without hidden entries when the preference is off", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(
        Response.json({ shareId: "docs", path: "", entries: [] }),
      );

    await createApiClient({ fetch }).directory(
      "docs",
      "",
      undefined,
      undefined,
      false,
    );

    expect(fetch.mock.calls[0]?.[0]).toBe(
      "/api/v1/shares/docs/directory?path=&limit=100&showHidden=false",
    );
  });

  it("sends authentication mutations once and includes CSRF only on logout", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const api = createApiClient({ fetch, retryDelayMs: 0 });

    await expect(
      api.login({ username: "joan", password: "secret" }),
    ).rejects.toMatchObject({
      kind: "network",
    });
    await api.logout("csrf-value");

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({ username: "joan", password: "secret" }),
    });
    expect(
      new Headers(fetch.mock.calls[1]?.[1]?.headers).get("X-CSRF-Token"),
    ).toBe("csrf-value");
  });

  it("returns structured errors without trusting non-JSON response bodies", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          code: "SESSION_EXPIRED",
          message: "expired",
          requestId: "r1",
        }),
        {
          status: 401,
          headers: { "content-type": "application/problem+json" },
        },
      ),
    );

    await expect(createApiClient({ fetch }).session()).rejects.toEqual(
      expect.objectContaining({
        name: "ApiError",
        kind: "unauthorized",
        status: 401,
        code: "SESSION_EXPIRED",
        requestId: "r1",
        retryable: false,
      }),
    );
  });

  it.each([null, [], "denied", 42, true])(
    "keeps a JSON %j error body classified by HTTP status",
    async (body) => {
      const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
        new Response(JSON.stringify(body), {
          status: 403,
          headers: {
            "content-type": "application/problem+json",
            "x-request-id": "header-request-id",
          },
        }),
      );

      await expect(createApiClient({ fetch }).session()).rejects.toMatchObject({
        kind: "forbidden",
        status: 403,
        message: "Request failed with status 403",
        code: undefined,
        requestId: "header-request-id",
      });
    },
  );

  it("ignores non-string problem fields", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({ code: 7, message: ["denied"], requestId: false }),
        {
          status: 409,
          headers: { "content-type": "application/json" },
        },
      ),
    );

    await expect(createApiClient({ fetch }).session()).rejects.toMatchObject({
      kind: "conflict",
      status: 409,
      message: "Request failed with status 409",
      code: undefined,
      requestId: undefined,
    });
  });

  it("retries safe reads once after transient network and server failures", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValueOnce(new Response("unavailable", { status: 503 }))
      .mockResolvedValueOnce(
        Response.json({ shareId: "docs", path: "", entries: [] }),
      );
    const api = createApiClient({ fetch, retryDelayMs: 0 });

    await expect(api.session()).rejects.toBeInstanceOf(ApiError);
    await expect(api.directory("docs", "")).resolves.toMatchObject({
      entries: [],
    });
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("converts AbortSignal cancellation to an explicit non-retryable error", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (_input, init) => {
      return await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        );
      });
    });
    const controller = new AbortController();
    const request = createApiClient({ fetch }).directory(
      "docs",
      "",
      undefined,
      controller.signal,
    );
    controller.abort();

    await expect(request).rejects.toMatchObject({
      kind: "aborted",
      retryable: false,
    });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("keeps cancellation structured when a safe request is waiting to retry", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockRejectedValue(new TypeError("offline"));
    const controller = new AbortController();
    const request = createApiClient({ fetch, retryDelayMs: 1_000 }).session(
      controller.signal,
    );
    controller.abort();

    await expect(request).rejects.toMatchObject({
      kind: "aborted",
      retryable: false,
    });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("rejects successful responses that are not valid JSON", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(new Response("not json"));
    await expect(createApiClient({ fetch }).session()).rejects.toMatchObject({
      kind: "invalid-response",
    });
  });

  it("rejects valid JSON that violates the typed response contract", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        shareId: "docs",
        path: "",
        entries: [{ name: "../escape", kind: "directory" }],
      }),
    );

    await expect(
      createApiClient({ fetch }).directory("docs", ""),
    ).rejects.toMatchObject({
      kind: "invalid-response",
    });
  });

  it.each([
    ".",
    "..",
    "folder/name",
    "folder\\name",
    "control\u0001",
    "literal%2e",
    "trailing.",
    "trailing ",
    "Cafe\u0301",
    "\ud800",
  ])("rejects ambiguous response filename %j", async (name) => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        shareId: "docs",
        path: "",
        entries: [{ name, kind: "file" }],
      }),
    );

    await expect(
      createApiClient({ fetch }).directory("docs", ""),
    ).rejects.toMatchObject({
      kind: "invalid-response",
    });
  });

  it("rejects an invalid request path before calling fetch", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();

    await expect(
      createApiClient({ fetch }).directory("docs", "../escape"),
    ).rejects.toMatchObject({ kind: "invalid-request" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("loads a runtime-validated preview through the same-origin API", async () => {
    const source = "const payload = '<img onerror=alert(1)>';\n";
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        kind: "code",
        source,
        language: "javascript",
        size: new TextEncoder().encode(source).byteLength,
        truncated: false,
      }),
    );

    await expect(
      createApiClient({ fetch }).preview("team/a", "src/東京.js"),
    ).resolves.toMatchObject({ kind: "code", source });
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/shares/team%2Fa/preview?path=src%2F%E6%9D%B1%E4%BA%AC.js",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("normalizes the backend's null language for plain text", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        kind: "text",
        source: "plain",
        language: null,
        size: 5,
        truncated: false,
      }),
    );

    await expect(
      createApiClient({ fetch }).preview("docs", "notes.txt"),
    ).resolves.toEqual({
      kind: "text",
      source: "plain",
      size: 5,
      truncated: false,
    });
  });

  it("accepts only bounded server-validated raster metadata", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        kind: "image",
        source: "",
        language: null,
        mimeType: "image/png",
        width: 640,
        height: 480,
        size: 2048,
        truncated: false,
      }),
    );
    await expect(
      createApiClient({ fetch }).preview("docs", "photo.png"),
    ).resolves.toMatchObject({
      kind: "image",
      mimeType: "image/png",
      width: 640,
      height: 480,
    });
  });

  it.each([
    { kind: "active_html", source: "x", size: 1, truncated: false },
    { kind: "code", source: "x", size: 2, truncated: false },
    {
      kind: "code",
      source: "x",
      size: 1,
      truncated: false,
      language: "made-up-language",
    },
    {
      kind: "text",
      source: "x",
      size: 1,
      truncated: false,
      language: "rust",
    },
    {
      kind: "html_source",
      source: "x",
      size: 1,
      truncated: false,
    },
    { kind: "text", source: "bad\u0000text", size: 8, truncated: false },
    { kind: "text", source: "bad\u0085text", size: 9, truncated: false },
    null,
    [],
  ])("rejects a malformed preview document %#", async (body) => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json(body));

    await expect(
      createApiClient({ fetch }).preview("docs", "file.txt"),
    ).rejects.toMatchObject({ kind: "invalid-response" });
  });

  it("builds only authenticated API URLs for HTML source and downloads", () => {
    expect(htmlPreviewUrl("team/a", "pages/demo.html")).toBe(
      "/api/v1/shares/team%2Fa/preview/html?path=pages%2Fdemo.html",
    );
    expect(downloadUrl("team/a", "pages/demo.html")).toBe(
      "/api/v1/shares/team%2Fa/download?path=pages%2Fdemo.html",
    );
    expect(renderedHtmlPreviewUrl("team/a", "pages/demo.html")).toBe(
      "/api/v1/shares/team%2Fa/preview/html/rendered?path=pages%2Fdemo.html",
    );
    expect(imagePreviewUrl("team/a", "photo.png")).toBe(
      "/api/v1/shares/team%2Fa/preview/image?path=photo.png",
    );
    expect(directoryEventsUrl("team/a", "pages")).toBe(
      "/api/v1/shares/team%2Fa/events?path=pages",
    );
    expect(() => downloadUrl("docs", "../secret")).toThrow(ApiError);
  });

  it("adds CSRF and precondition headers to every file mutation", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
      const url = String(input);
      const body =
        new Headers(init?.headers).get("content-type") === "application/json" &&
        init?.body
          ? JSON.parse(String(init.body))
          : undefined;
      const path =
        body?.destination ??
        body?.path ??
        new URL(url, "https://crabinet.test").searchParams.get("path")!;
      return Response.json({ shareId: "work", path, outcome: "success" });
    });
    const api = createApiClient({ fetch });

    await api.createDirectory("work", "docs", "csrf");
    await api.createFile("work", "docs/a.txt", "csrf");
    await api.saveText("work", "docs/a.txt", "hello", 'W/"v1"', "csrf");
    await api.moveEntry("work", "docs/a.txt", "docs/b.txt", 'W/"v2"', "csrf");
    await api.deleteEntry("work", "docs/b.txt", 'W/"v3"', "csrf");

    expect(fetch).toHaveBeenCalledTimes(5);
    for (const call of fetch.mock.calls) {
      expect(new Headers(call[1]?.headers).get("X-CSRF-Token")).toBe("csrf");
      expect(call[1]?.credentials).toBe("same-origin");
    }
    expect(new Headers(fetch.mock.calls[2]?.[1]?.headers).get("If-Match")).toBe(
      'W/"v1"',
    );
    expect(new Headers(fetch.mock.calls[3]?.[1]?.headers).get("If-Match")).toBe(
      'W/"v2"',
    );
    expect(new Headers(fetch.mock.calls[4]?.[1]?.headers).get("If-Match")).toBe(
      'W/"v3"',
    );
  });

  it("rejects malformed mutation success and metadata responses", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(Response.json({ outcome: "success" }))
      .mockResolvedValueOnce(
        Response.json({
          shareId: "docs",
          path: "a.txt",
          name: "../a.txt",
          kind: "file",
          size: 1,
          etag: 'W/"v"',
        }),
      )
      .mockResolvedValueOnce(
        Response.json({
          shareId: "docs",
          path: "b.txt",
          name: "b.txt",
          kind: "file",
          size: 1,
          accessedAtMs: -1,
          etag: 'W/"v"',
        }),
      );
    const api = createApiClient({ fetch });

    await expect(api.createFile("docs", "a.txt", "csrf")).rejects.toMatchObject(
      { kind: "invalid-response" },
    );
    await expect(api.metadata("docs", "a.txt")).rejects.toMatchObject({
      kind: "invalid-response",
    });
    await expect(api.metadata("docs", "b.txt")).rejects.toMatchObject({
      kind: "invalid-response",
    });
  });

  it("streams a browser File through FormData with progress, CSRF, and replace preconditions", async () => {
    const xhr = new FakeXhr();
    const progress = vi.fn();
    const file = new File(["payload"], "report.txt", { type: "text/plain" });
    const api = createApiClient({
      fetch: vi.fn(),
      xhrFactory: () => xhr as unknown as XMLHttpRequest,
    });
    const request = api.uploadFile("team/a", "reports", file, "csrf", {
      replace: true,
      etag: 'W/"old"',
      onProgress: progress,
    });

    expect(xhr.method).toBe("POST");
    expect(xhr.url).toBe(
      "/api/v1/shares/team%2Fa/uploads?path=reports&replace=true",
    );
    expect(xhr.headers.get("X-CSRF-Token")).toBe("csrf");
    expect(xhr.headers.get("If-Match")).toBe('W/"old"');
    expect(xhr.body).toBeInstanceOf(FormData);
    expect((xhr.body as FormData).get("file")).toMatchObject({
      name: "report.txt",
      size: 7,
    });

    xhr.upload.dispatchEvent(
      new ProgressEvent("progress", {
        loaded: 4,
        total: 7,
        lengthComputable: true,
      }),
    );
    expect(progress).toHaveBeenCalledWith(4, 7);
    xhr.respond(207, {
      shareId: "team/a",
      outcomes: [{ path: "reports/report.txt", outcome: "replaced" }],
    });
    await expect(request).resolves.toMatchObject({
      outcomes: [{ outcome: "replaced" }],
    });
  });

  it("aborts upload transport without retrying or converting cancellation to failure", async () => {
    const xhr = new FakeXhr();
    const controller = new AbortController();
    const api = createApiClient({
      fetch: vi.fn(),
      xhrFactory: () => xhr as unknown as XMLHttpRequest,
    });
    const request = api.uploadFile(
      "docs",
      "",
      new File(["large"], "large.bin"),
      "csrf",
      { signal: controller.signal },
    );

    controller.abort();
    await expect(request).rejects.toMatchObject({ kind: "aborted" });
    expect(xhr.aborted).toBe(true);
  });
});

class FakeXhr extends EventTarget {
  readonly upload = new EventTarget();
  readonly headers = new Map<string, string>();
  method = "";
  url = "";
  body: Document | XMLHttpRequestBodyInit | null = null;
  status = 0;
  response: unknown;
  responseType: XMLHttpRequestResponseType = "";
  withCredentials = false;
  aborted = false;

  open(method: string, url: string) {
    this.method = method;
    this.url = url;
  }

  setRequestHeader(name: string, value: string) {
    this.headers.set(name, value);
  }

  getResponseHeader() {
    return null;
  }

  send(body: Document | XMLHttpRequestBodyInit | null) {
    this.body = body;
  }

  abort() {
    this.aborted = true;
    this.dispatchEvent(new Event("abort"));
  }

  respond(status: number, response: unknown) {
    this.status = status;
    this.response = response;
    this.dispatchEvent(new Event("load"));
  }
}
