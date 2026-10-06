import { describe, expect, it, vi } from "vitest";

import {
  ApiError,
  archiveUrl,
  countLines,
  createApiClient,
  directoryEventsUrl,
  downloadUrl,
  htmlPreviewUrl,
  imagePreviewUrl,
  openUrl,
  thumbnailStatus,
  thumbnailUrl,
  renderedHtmlPreviewUrl,
  svgPreviewUrl,
  withCsrfRetry,
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

  it("saves the start folder using a same-origin CSRF-protected request", async () => {
    const folder = { shareId: "docs", path: "projects" };
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json({ defaultFolder: folder }));

    await expect(
      createApiClient({ fetch }).updateDefaultFolder(folder, "csrf-value"),
    ).resolves.toEqual(folder);
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/preferences",
      expect.objectContaining({
        method: "PUT",
        credentials: "same-origin",
        body: JSON.stringify({ defaultFolder: folder }),
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-CSRF-Token": "csrf-value",
        }),
      }),
    );
  });

  it("saves display settings as a partial CSRF-protected update", async () => {
    const saved = { showHiddenFiles: false, theme: "dark" };
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json(saved));

    await expect(
      createApiClient({ fetch }).updatePreferences(
        { theme: "dark" },
        "csrf-value",
      ),
    ).resolves.toEqual(saved);
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/preferences/display",
      expect.objectContaining({
        method: "PUT",
        credentials: "same-origin",
        body: JSON.stringify({ theme: "dark" }),
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-CSRF-Token": "csrf-value",
        }),
      }),
    );
  });

  it.each([
    [undefined],
    [{ showHiddenFiles: "true", theme: "system" }],
    [{ showHiddenFiles: true, theme: "sepia" }],
    [{ showHiddenFiles: true }],
  ])("rejects display settings %j that break the contract", async (value) => {
    const session = {
      user: { id: "u", username: "u", displayName: "U" },
      shares: [],
      preferences: value,
      csrfToken: "csrf",
    };
    const respond = (body: unknown) =>
      createApiClient({
        fetch: vi
          .fn<typeof globalThis.fetch>()
          .mockResolvedValue(Response.json(body ?? {})),
      });

    await expect(respond(session).session()).rejects.toMatchObject({
      kind: "invalid-response",
    });
    await expect(
      respond(value).updatePreferences({ theme: "dark" }, "csrf"),
    ).rejects.toMatchObject({ kind: "invalid-response" });
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

  it("starts discoverable passkey sign-in without an account name", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        flowId: "flow",
        options: { publicKey: { challenge: "c", allowCredentials: [] } },
      }),
    );
    const api = createApiClient({ fetch });

    await api.startPasskeyLogin();
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/auth/passkeys/login/start",
      expect.objectContaining({ method: "POST", body: "{}" }),
    );
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

  it("accepts a listed folder size and rejects a malformed one", async () => {
    const listing = (entry: Record<string, unknown>) =>
      vi
        .fn<typeof globalThis.fetch>()
        .mockResolvedValue(
          Response.json({ shareId: "docs", path: "", entries: [entry] }),
        );
    const page = await createApiClient({
      fetch: listing({
        name: "photos",
        kind: "directory",
        folderSize: { size: 42, complete: false },
      }),
    }).directory("docs", "");
    expect(page.entries[0]!.folderSize).toEqual({ size: 42, complete: false });

    for (const entry of [
      { name: "a.txt", kind: "file", folderSize: { size: 1, complete: true } },
      { name: "photos", kind: "directory", folderSize: { size: -1 } },
      {
        name: "photos",
        kind: "directory",
        folderSize: { size: 1.5, complete: true },
      },
      { name: "photos", kind: "directory", folderSize: 42 },
    ]) {
      await expect(
        createApiClient({ fetch: listing(entry) }).directory("docs", ""),
      ).rejects.toMatchObject({ kind: "invalid-response" });
    }
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

  it.each([
    ["https://lh3.googleusercontent.com/a/avatar", true],
    ["https://www.gravatar.com/avatar/abc", true],
    ["http://lh3.googleusercontent.com/a/avatar", false],
    ["https://lh3.googleusercontent.com.evil.example/a", false],
    ["https://evil.example/avatar.png", false],
    ["https://user@lh3.googleusercontent.com/a", false],
    ["https://lh3.googleusercontent.com:8443/a", false],
    ["javascript:alert(1)", false],
    ["not a url", false],
  ])(
    "keeps profile picture %s only for CSP-allowed hosts",
    async (url, kept) => {
      const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
        Response.json({
          user: { id: "u", username: "u", displayName: "U", pictureUrl: url },
          shares: [],
          preferences: { showHiddenFiles: true, theme: "system" },
          csrfToken: "csrf",
        }),
      );
      const session = await createApiClient({ fetch }).session();
      expect(session.user.pictureUrl).toBe(kept ? url : undefined);
      expect(session.user.displayName).toBe("U");
    },
  );

  it("validates passkey responses before handing them to the UI", async () => {
    const passkey = { id: "k", name: "Laptop", createdAt: 1, lastUsedAt: null };
    const respond = (body: unknown) =>
      createApiClient({
        fetch: vi
          .fn<typeof globalThis.fetch>()
          .mockResolvedValue(Response.json(body)),
      });

    await expect(respond({ passkeys: [passkey] }).passkeys()).resolves.toEqual([
      passkey,
    ]);
    await expect(
      respond({
        passkeys: [{ ...passkey, createdAt: "yesterday" }],
      }).passkeys(),
    ).rejects.toMatchObject({ kind: "invalid-response" });
    await expect(respond([passkey]).passkeys()).rejects.toMatchObject({
      kind: "invalid-response",
    });
    await expect(
      respond({ ...passkey, name: 7 }).finishPasskeyRegistration(
        "flow",
        {} as never,
        "csrf",
      ),
    ).rejects.toMatchObject({ kind: "invalid-response" });
    await expect(
      respond(passkey).renamePasskey("other", "Laptop", "csrf"),
    ).rejects.toMatchObject({ kind: "invalid-response" });
    await expect(
      respond(passkey).renamePasskey("k", "Laptop", "csrf"),
    ).resolves.toEqual(passkey);

    const creation = {
      challenge: "c",
      rp: { name: "Crabinet", id: "files.example" },
      user: { id: "dXNlcg", name: "joan", displayName: "Joan" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [{ id: "k", type: "public-key" }],
    };
    await expect(
      respond({
        flowId: "flow",
        options: { publicKey: creation },
      }).startPasskeyRegistration("Laptop", "csrf"),
    ).resolves.toEqual({ flowId: "flow", options: { publicKey: creation } });
    for (const publicKey of [
      { ...creation, challenge: "" },
      { ...creation, user: { ...creation.user, id: 1 } },
      { ...creation, pubKeyCredParams: [] },
      { ...creation, excludeCredentials: [{ id: "k", type: "other" }] },
    ]) {
      await expect(
        respond({
          flowId: "flow",
          options: { publicKey },
        }).startPasskeyRegistration("Laptop", "csrf"),
      ).rejects.toMatchObject({ kind: "invalid-response" });
    }
    await expect(
      respond({
        options: { publicKey: { challenge: "c" } },
      }).startPasskeyLogin(),
    ).rejects.toMatchObject({ kind: "invalid-response" });
    await expect(
      respond({ flowId: "flow", options: {} }).startPasskeyLogin("joan"),
    ).rejects.toMatchObject({ kind: "invalid-response" });
  });

  it("exposes the API error code so re-authentication differs from CSRF", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json(
        {
          error: {
            code: "reauthentication_required",
            message: "Sign in again",
          },
        },
        { status: 403 },
      ),
    );
    await expect(
      createApiClient({ fetch }).startPasskeyRegistration("Laptop", "csrf"),
    ).rejects.toMatchObject({
      kind: "forbidden",
      status: 403,
      code: "reauthentication_required",
    });
  });

  it("retries a mutation once with a refreshed CSRF token for the same user", async () => {
    const refreshed = {
      user: { id: "u", username: "u", displayName: "U" },
      shares: [],
      preferences: { showHiddenFiles: true, theme: "system" as const },
      csrfToken: "fresh",
    };
    const api = { session: vi.fn(async () => refreshed) };
    const onRefreshed = vi.fn();
    const mutate = vi
      .fn<(token: string) => Promise<string>>()
      .mockRejectedValueOnce(
        new ApiError("forbidden", "stale", { status: 403, code: "forbidden" }),
      )
      .mockResolvedValue("done");

    await expect(
      withCsrfRetry(api, "stale", "u", onRefreshed, mutate),
    ).resolves.toBe("done");
    expect(mutate.mock.calls).toEqual([["stale"], ["fresh"]]);
    expect(onRefreshed).toHaveBeenCalledWith(refreshed);

    const reauth = vi
      .fn<(token: string) => Promise<string>>()
      .mockRejectedValue(
        new ApiError("forbidden", "reauth", {
          status: 403,
          code: "reauthentication_required",
        }),
      );
    await expect(
      withCsrfRetry(api, "stale", "u", onRefreshed, reauth),
    ).rejects.toMatchObject({ code: "reauthentication_required" });
    expect(reauth).toHaveBeenCalledOnce();

    const otherUser = vi
      .fn<(token: string) => Promise<string>>()
      .mockRejectedValue(
        new ApiError("forbidden", "stale", { status: 403, code: "forbidden" }),
      );
    await expect(
      withCsrfRetry(api, "stale", "someone-else", onRefreshed, otherUser),
    ).rejects.toMatchObject({ code: "account_changed" });
    expect(otherUser).toHaveBeenCalledOnce();
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

  it("accepts the head of a large text file with its shown size and lines", async () => {
    const source = "line\r\n".repeat(1000);
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        kind: "markdown_source",
        source,
        language: "markdown",
        size: 40_000_000,
        truncated: true,
        shownBytes: 6000,
        shownLines: 1000,
        openable: true,
      }),
    );

    await expect(
      createApiClient({ fetch }).preview("docs", "big.md"),
    ).resolves.toEqual({
      kind: "markdown_source",
      source,
      language: "markdown",
      size: 40_000_000,
      truncated: true,
      shownBytes: 6000,
      shownLines: 1000,
      openable: true,
    });
  });

  it("accepts a whole SVG document as its own kind", async () => {
    const source = "<svg xmlns='http://www.w3.org/2000/svg'/>";
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        kind: "svg",
        source,
        language: "xml",
        size: source.length,
        truncated: false,
        openable: true,
        thumbnailable: false,
      }),
    );

    await expect(
      createApiClient({ fetch }).preview("docs", "logo.svg"),
    ).resolves.toMatchObject({ kind: "svg", language: "xml", source });
    expect(svgPreviewUrl("docs", "art/logo.svg")).toBe(
      "/api/v1/shares/docs/preview/svg?path=art%2Flogo.svg",
    );
  });

  it("accepts the head of a large SVG and a renderable large HTML head", async () => {
    const svg = {
      kind: "svg",
      source: "<svg/>\n",
      language: "xml",
      size: 900,
      truncated: true,
      shownBytes: 7,
      shownLines: 1,
      openable: true,
      renderable: false,
    };
    const html = {
      kind: "html_source",
      source: "<p>x</p>\n",
      language: "html",
      size: 30_000_000,
      truncated: true,
      shownBytes: 9,
      shownLines: 1,
      openable: true,
      renderable: true,
    };
    for (const body of [svg, html]) {
      const fetch = vi
        .fn<typeof globalThis.fetch>()
        .mockResolvedValue(Response.json(body));
      await expect(
        createApiClient({ fetch }).preview("docs", "file"),
      ).resolves.toEqual(body);
    }
  });

  it("counts lines like the server, including a final line without a feed", () => {
    expect(countLines("")).toBe(0);
    expect(countLines("a")).toBe(1);
    expect(countLines("a\n")).toBe(1);
    expect(countLines("a\r\nb")).toBe(2);
    expect(countLines("\n\n")).toBe(2);
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
    // Head fields on a whole document, or a head that misdescribes itself.
    {
      kind: "text",
      source: "x",
      size: 1,
      truncated: false,
      shownBytes: 1,
      shownLines: 1,
    },
    { kind: "text", source: "a\n", size: 900, truncated: true },
    {
      kind: "text",
      source: "a\n",
      size: 900,
      truncated: true,
      shownBytes: 3,
      shownLines: 1,
    },
    {
      kind: "text",
      source: "a\nb",
      size: 900,
      truncated: true,
      shownBytes: 3,
      shownLines: 1,
    },
    {
      kind: "text",
      source: "a\n",
      size: 2,
      truncated: true,
      shownBytes: 2,
      shownLines: 1,
    },
    {
      kind: "text",
      source: "a\n".repeat(1001),
      size: 1_000_000,
      truncated: true,
      shownBytes: 2002,
      shownLines: 1001,
    },
    {
      kind: "text",
      source: "a".repeat(64 * 1024 + 1),
      size: 1_000_000,
      truncated: true,
      shownBytes: 64 * 1024 + 1,
      shownLines: 1,
    },
    // Streamed kinds are never heads; SVG is always XML.
    {
      kind: "pdf",
      source: "",
      mimeType: "application/pdf",
      size: 900,
      truncated: true,
      shownBytes: 0,
      shownLines: 0,
    },
    { kind: "svg", source: "<svg/>", size: 6, truncated: false },
    // Only HTML renders, and only with a boolean.
    {
      kind: "svg",
      source: "<svg/>",
      language: "xml",
      size: 6,
      truncated: false,
      renderable: true,
    },
    {
      kind: "markdown_source",
      source: "# x",
      language: "markdown",
      size: 3,
      truncated: false,
      renderable: true,
    },
    {
      kind: "html_source",
      source: "<p>",
      language: "html",
      size: 3,
      truncated: false,
      renderable: "yes",
    },
    {
      kind: "svg",
      source: "<svg/>",
      language: "xml",
      size: 6,
      truncated: false,
      thumbnailable: true,
    },
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

  it.each([
    { kind: "pdf", mimeType: "application/pdf" },
    { kind: "audio", mimeType: "audio/mpeg" },
    { kind: "audio", mimeType: "audio/mp4" },
    { kind: "video", mimeType: "video/webm" },
    { kind: "video", mimeType: "video/mp4" },
  ])(
    "accepts streamed $kind metadata of any size with a signature type",
    async ({ kind, mimeType }) => {
      const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
        Response.json({
          kind,
          source: "",
          language: null,
          mimeType,
          size: 5 * 1024 * 1024 * 1024,
          truncated: false,
          openable: kind === "pdf",
        }),
      );
      await expect(
        createApiClient({ fetch }).preview("docs", "file.bin"),
      ).resolves.toEqual({
        kind,
        source: "",
        mimeType,
        size: 5 * 1024 * 1024 * 1024,
        truncated: false,
        openable: kind === "pdf",
      });
    },
  );

  it("keeps the codecs the server named for audio and video", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        kind: "video",
        source: "",
        language: null,
        mimeType: "video/mp4",
        codecs: "avc1.42E01E, mp4a.40.2",
        size: 10,
        truncated: false,
        openable: false,
      }),
    );
    await expect(
      createApiClient({ fetch }).preview("docs", "clip.mp4"),
    ).resolves.toMatchObject({ codecs: "avc1.42E01E, mp4a.40.2" });
  });

  it.each([
    // Only audio and video carry codecs.
    { kind: "pdf", mimeType: "application/pdf", codecs: "vp9" },
    // The value goes into a quoted media type parameter.
    { kind: "video", mimeType: "video/webm", codecs: 'vp9"; x="' },
    { kind: "video", mimeType: "video/webm", codecs: "vp9,opus" },
    { kind: "video", mimeType: "video/webm", codecs: "" },
    { kind: "video", mimeType: "video/webm", codecs: 9 },
    {
      kind: "video",
      mimeType: "video/webm",
      codecs: Array(9).fill("vp9").join(", "),
    },
  ])("rejects malformed codecs %#", async (fields) => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(
        Response.json({ source: "", size: 1, truncated: false, ...fields }),
      );
    await expect(
      createApiClient({ fetch }).preview("docs", "file.bin"),
    ).rejects.toMatchObject({ kind: "invalid-response" });
  });

  it("keeps the server's openable flag on text previews", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      Response.json({
        kind: "text",
        source: "plain",
        language: null,
        size: 5,
        truncated: false,
        openable: true,
      }),
    );
    await expect(
      createApiClient({ fetch }).preview("docs", "notes.txt"),
    ).resolves.toMatchObject({ kind: "text", openable: true });
  });

  it.each([
    // A streamed kind must carry its own family's media type and no source.
    {
      kind: "pdf",
      source: "",
      mimeType: "image/png",
      size: 1,
      truncated: false,
    },
    { kind: "pdf", source: "", size: 1, truncated: false },
    {
      kind: "video",
      source: "",
      mimeType: "audio/mpeg",
      size: 1,
      truncated: false,
    },
    {
      kind: "audio",
      source: "",
      mimeType: "text/html",
      size: 1,
      truncated: false,
    },
    {
      kind: "pdf",
      source: "%PDF-",
      mimeType: "application/pdf",
      size: 5,
      truncated: false,
    },
    {
      kind: "video",
      source: "",
      mimeType: "video/mp4",
      width: 4,
      size: 1,
      truncated: false,
    },
    // Text stays bounded by the preview limit and gets no media type.
    {
      kind: "text",
      source: "x",
      mimeType: "application/pdf",
      size: 1,
      truncated: false,
    },
    { kind: "text", source: "x", size: 1, truncated: false, openable: "yes" },
  ])("rejects inconsistent streamed preview metadata %#", async (body) => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json(body));
    await expect(
      createApiClient({ fetch }).preview("docs", "file.bin"),
    ).rejects.toMatchObject({ kind: "invalid-response" });
  });

  it("parses thumbnail availability and RAW previews", async () => {
    const respond = (body: unknown) =>
      vi.fn<typeof globalThis.fetch>().mockResolvedValue(Response.json(body));
    await expect(
      createApiClient({
        fetch: respond({
          kind: "image",
          source: "",
          language: null,
          mimeType: "image/jpeg",
          size: 2048,
          truncated: false,
          openable: true,
          thumbnailable: true,
        }),
      }).preview("docs", "photo.jpg"),
    ).resolves.toMatchObject({ kind: "image", thumbnailable: true });
    await expect(
      createApiClient({
        fetch: respond({
          kind: "raw",
          source: "",
          language: null,
          size: 50_000_000,
          truncated: false,
          openable: false,
          thumbnailable: true,
        }),
      }).preview("docs", "camera.dng"),
    ).resolves.toEqual({
      kind: "raw",
      source: "",
      size: 50_000_000,
      truncated: false,
      openable: false,
      thumbnailable: true,
    });
  });

  it.each([
    // RAW files always come with a thumbnail and are never opened inline.
    { kind: "raw", source: "", size: 1, truncated: false },
    {
      kind: "raw",
      source: "",
      size: 1,
      truncated: false,
      thumbnailable: false,
    },
    {
      kind: "raw",
      source: "",
      size: 1,
      truncated: false,
      thumbnailable: true,
      openable: true,
    },
    {
      kind: "raw",
      source: "",
      mimeType: "image/jpeg",
      size: 1,
      truncated: false,
      thumbnailable: true,
    },
    {
      kind: "raw",
      source: "x",
      size: 1,
      truncated: false,
      thumbnailable: true,
    },
    // Thumbnails exist only for images and RAW files.
    {
      kind: "pdf",
      source: "",
      mimeType: "application/pdf",
      size: 5,
      truncated: false,
      thumbnailable: true,
    },
    { kind: "text", source: "x", size: 1, truncated: false, thumbnailable: 1 },
  ])("rejects inconsistent thumbnail metadata %#", async (body) => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(Response.json(body));
    await expect(
      createApiClient({ fetch }).preview("docs", "file.bin"),
    ).rejects.toMatchObject({ kind: "invalid-response" });
  });

  it("builds thumbnail URLs for the two allowed sizes", () => {
    expect(thumbnailUrl("team/a", "R&D/photo.jpg", 1600)).toBe(
      "/api/v1/shares/team%2Fa/thumbnail?path=R%26D%2Fphoto.jpg&size=1600",
    );
    expect(thumbnailUrl("docs", "photo.jpg", 256)).toBe(
      "/api/v1/shares/docs/thumbnail?path=photo.jpg&size=256",
    );
    expect(() => thumbnailUrl("docs", "../secret", 256)).toThrow(ApiError);
  });

  it("reports why a thumbnail failed", async () => {
    const url = "/api/v1/shares/docs/thumbnail?path=a.png&size=1600";
    const ok = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(new Response("jpeg", { status: 200 }));
    await expect(thumbnailStatus(url, undefined, ok)).resolves.toBeUndefined();
    expect(ok).toHaveBeenCalledWith(
      url,
      expect.objectContaining({ credentials: "same-origin" }),
    );
    for (const [status, code] of [
      [413, "thumbnail_too_large"],
      [415, "unsupported_entry"],
      [429, "busy"],
    ] as const) {
      const failing = vi
        .fn<typeof globalThis.fetch>()
        .mockResolvedValue(
          Response.json({ code, message: "No thumbnail" }, { status }),
        );
      await expect(
        thumbnailStatus(url, undefined, failing),
      ).rejects.toMatchObject({ status, code });
    }
    const offline = vi
      .fn<typeof globalThis.fetch>()
      .mockRejectedValue(new TypeError("offline"));
    await expect(
      thumbnailStatus(url, undefined, offline),
    ).rejects.toMatchObject({ kind: "network" });
  });

  it("builds the inline open URL with the same path validation as downloads", () => {
    expect(openUrl("team/a", "R&D/東京 report.pdf")).toBe(
      "/api/v1/shares/team%2Fa/open?path=R%26D%2F%E6%9D%B1%E4%BA%AC+report.pdf",
    );
    expect(() => openUrl("docs", "../secret")).toThrow(ApiError);
    expect(() => openUrl("docs", "/absolute")).toThrow(ApiError);
    expect(() => openUrl("docs", "a//b")).toThrow(ApiError);
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

  it("builds folder archive URLs, with no path for the share root", () => {
    expect(archiveUrl("team/a", "")).toBe("/api/v1/shares/team%2Fa/archive");
    expect(archiveUrl("team/a", "R&D/東京")).toBe(
      "/api/v1/shares/team%2Fa/archive?path=R%26D%2F%E6%9D%B1%E4%BA%AC",
    );
    expect(() => archiveUrl("docs", "../secret")).toThrow(ApiError);
  });

  it("checks a folder archive and cancels the admitted response body", async () => {
    let signal: AbortSignal | undefined;
    const fetch = vi.fn<typeof globalThis.fetch>(async (_input, init) => {
      signal = init?.signal ?? undefined;
      return new Response("PK", {
        headers: { "content-type": "application/zip" },
      });
    });

    await createApiClient({ fetch }).checkArchive("docs", "photos");

    expect(fetch.mock.calls[0]?.[0]).toBe(
      "/api/v1/shares/docs/archive?path=photos",
    );
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({
      credentials: "same-origin",
    });
    expect(signal?.aborted).toBe(true);
  });

  it("rejects a refused folder archive with the server's error code", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(
        Response.json(
          { error: { code: "too_large", message: "Too large" } },
          { status: 413 },
        ),
      );

    await expect(
      createApiClient({ fetch }).checkArchive("docs", ""),
    ).rejects.toMatchObject({ status: 413, code: "too_large" });
    expect(fetch.mock.calls[0]?.[0]).toBe("/api/v1/shares/docs/archive");
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
      return Response.json({
        shareId: "work",
        path,
        outcome: "success",
        trashId: "trash-1",
      });
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

  it("lists Trash and sends CSRF for restore and permanent deletion", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
      if (String(input) === "/api/v1/shares/work/trash?limit=100")
        return Response.json({
          shareId: "work",
          items: [
            {
              id: "id/1",
              originalPath: "notes.txt",
              kind: "file",
              deletedAt: "2026-09-01T10:00:00Z",
              deletedBy: "Joan",
              expiresAt: "2026-10-01T10:00:00Z",
            },
          ],
        });
      return new Response(null, { status: 204 });
    });
    const api = createApiClient({ fetch });
    expect((await api.trash("work")).items[0]?.id).toBe("id/1");
    await api.restoreTrash("work", "id/1", "archive/notes.txt", "csrf");
    await api.purgeTrash("work", "id/1", "csrf");
    expect(fetch.mock.calls[1]?.[0]).toBe(
      "/api/v1/shares/work/trash/id%2F1/restore",
    );
    expect(fetch.mock.calls[1]?.[1]?.body).toBe(
      JSON.stringify({ destination: "archive/notes.txt" }),
    );
    expect(
      new Headers(fetch.mock.calls[1]?.[1]?.headers).get("X-CSRF-Token"),
    ).toBe("csrf");
    expect(fetch.mock.calls[2]?.[0]).toBe("/api/v1/shares/work/trash/id%2F1");
    expect(
      new Headers(fetch.mock.calls[2]?.[1]?.headers).get("X-CSRF-Token"),
    ).toBe("csrf");
  });

  it("empties a share's Trash with CSRF and validates the result", async () => {
    const result = {
      shareId: "work",
      outcome: "success",
      purged: 250,
      failed: 1,
      moreRemaining: true,
    };
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      Response.json(result),
    );
    const api = createApiClient({ fetch });
    expect(await api.emptyTrash("work", "csrf")).toEqual(result);
    expect(fetch.mock.calls[0]?.[0]).toBe("/api/v1/shares/work/trash/empty");
    expect(fetch.mock.calls[0]?.[1]?.method).toBe("POST");
    expect(
      new Headers(fetch.mock.calls[0]?.[1]?.headers).get("X-CSRF-Token"),
    ).toBe("csrf");
    for (const invalid of [
      { ...result, shareId: "other" },
      { ...result, purged: -1 },
      { ...result, failed: 1.5 },
      { ...result, moreRemaining: "no" },
    ]) {
      fetch.mockResolvedValueOnce(Response.json(invalid));
      await expect(api.emptyTrash("work", "csrf")).rejects.toMatchObject({
        kind: "invalid-response",
      });
    }
  });

  it("pages Trash with an opaque cursor and validates it", async () => {
    const item = {
      id: "id-2",
      originalPath: "old.txt",
      kind: "file",
      deletedAt: "2026-09-01T10:00:00Z",
      deletedBy: "Joan",
      expiresAt: "2026-10-01T10:00:00Z",
    };
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        Response.json({ shareId: "work", items: [item], nextCursor: "c/2+" }),
      )
      .mockResolvedValueOnce(
        Response.json({ shareId: "work", items: [], nextCursor: 7 }),
      )
      .mockResolvedValueOnce(
        Response.json({ shareId: "work", items: [], nextCursor: "" }),
      );
    const api = createApiClient({ fetch });
    const page = await api.trash("work", "first cursor");
    expect(page.nextCursor).toBe("c/2+");
    expect(fetch.mock.calls[0]?.[0]).toBe(
      "/api/v1/shares/work/trash?limit=100&cursor=first+cursor",
    );
    await expect(api.trash("work", page.nextCursor)).rejects.toMatchObject({
      kind: "invalid-response",
    });
    expect(fetch.mock.calls[1]?.[0]).toBe(
      "/api/v1/shares/work/trash?limit=100&cursor=c%2F2%2B",
    );
    await expect(api.trash("work")).rejects.toMatchObject({
      kind: "invalid-response",
    });
  });

  it("accepts upload outcomes for a share that cannot be measured", async () => {
    for (const outcome of [
      "share_too_large_to_measure",
      "share_too_deep_to_measure",
    ]) {
      const xhr = new FakeXhr();
      const api = createApiClient({
        fetch: vi.fn(),
        xhrFactory: () => xhr as unknown as XMLHttpRequest,
      });
      const request = api.uploadFile(
        "docs",
        "",
        new File(["x"], "x.txt"),
        "csrf",
      );
      xhr.respond(207, {
        shareId: "docs",
        outcomes: [{ path: "x.txt", outcome }],
      });
      await expect(request).resolves.toMatchObject({
        outcomes: [{ outcome }],
      });
    }
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
      )
      .mockResolvedValueOnce(
        Response.json({
          shareId: "docs",
          path: "c.txt",
          name: "c.txt",
          kind: "file",
          size: 1,
          modifiedAtMs: "2026-09-16T18:30:00Z",
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
    await expect(api.metadata("docs", "c.txt")).rejects.toMatchObject({
      kind: "invalid-response",
    });
  });

  it("parses optional metadata timestamps, including the modification time", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        Response.json({
          shareId: "docs",
          path: "a.txt",
          name: "a.txt",
          kind: "file",
          size: 1,
          modifiedAtMs: 1_789_599_000_000,
          accessedAtMs: 1_789_599_600_000,
          createdAtMs: 1_789_513_200_000,
          etag: 'W/"v"',
        }),
      )
      .mockResolvedValueOnce(
        Response.json({
          shareId: "docs",
          path: "folder",
          name: "folder",
          kind: "directory",
          etag: 'W/"d"',
        }),
      );
    const api = createApiClient({ fetch });

    await expect(api.metadata("docs", "a.txt")).resolves.toMatchObject({
      modifiedAtMs: 1_789_599_000_000,
      accessedAtMs: 1_789_599_600_000,
      createdAtMs: 1_789_513_200_000,
    });
    const directory = await api.metadata("docs", "folder");
    expect(directory.modifiedAtMs).toBeUndefined();
    expect(directory.kind).toBe("directory");
  });

  it("requests one folder's size and validates the answer", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        Response.json({
          shareId: "docs",
          path: "Photos/2026",
          size: 14_000_000_000,
          complete: false,
        }),
      )
      .mockResolvedValueOnce(
        Response.json({
          shareId: "docs",
          path: "other",
          size: 1,
          complete: true,
        }),
      )
      .mockResolvedValueOnce(
        Response.json({ shareId: "docs", path: "a", size: -1, complete: true }),
      )
      .mockResolvedValueOnce(
        Response.json({ shareId: "docs", path: "a", size: 1, complete: "yes" }),
      );
    const api = createApiClient({ fetch });

    await expect(api.folderSize("docs", "Photos/2026")).resolves.toEqual({
      shareId: "docs",
      path: "Photos/2026",
      size: 14_000_000_000,
      complete: false,
    });
    expect(fetch.mock.calls[0]?.[0]).toBe(
      "/api/v1/shares/docs/folder-size?path=Photos%2F2026",
    );
    for (const path of ["a", "a", "a"]) {
      await expect(api.folderSize("docs", path)).rejects.toMatchObject({
        kind: "invalid-response",
      });
    }
    await expect(api.folderSize("docs", "../a")).rejects.toMatchObject({
      kind: "invalid-request",
    });
  });

  it("reads the folder-size setting from the session", async () => {
    const base = {
      user: { id: "u", username: "u", displayName: "u" },
      shares: [],
      preferences: { showHiddenFiles: false, theme: "system" },
      csrfToken: "csrf",
    };
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(Response.json({ ...base, folderSizes: true }))
      .mockResolvedValueOnce(Response.json(base))
      .mockResolvedValueOnce(Response.json({ ...base, folderSizes: "on" }));
    const api = createApiClient({ fetch });

    expect((await api.session()).folderSizes).toBe(true);
    expect((await api.session()).folderSizes).toBeUndefined();
    await expect(api.session()).rejects.toMatchObject({
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
