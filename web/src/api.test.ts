import { describe, expect, it, vi } from "vitest";

import { ApiError, createApiClient } from "./api";

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
});
