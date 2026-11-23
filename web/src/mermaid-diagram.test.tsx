import { fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { describe, expect, it } from "vitest";

import { MermaidDiagram } from "./mermaid-diagram";
import { MAX_MERMAID_CHARACTERS } from "./mermaid-policy";

describe("MermaidDiagram", () => {
  it("does not start a renderer for oversized input", () => {
    const { container } = render(
      <MermaidDiagram source={"x".repeat(MAX_MERMAID_CHARACTERS + 1)} />,
    );
    expect(screen.getByRole("status")).toHaveTextContent("too large to render");
    expect(container.querySelector("iframe")).toBeNull();
  });

  it("ignores messages from other windows and removes a failed renderer", async () => {
    const { container } = render(
      <MermaidDiagram source="flowchart LR\nA --> B" />,
    );
    const frame = container.querySelector("iframe")!;
    fireEvent(
      window,
      new MessageEvent("message", {
        source: window,
        origin: "null",
        data: {
          type: "crabinet-mermaid-result",
          id: "diagram-1",
          ok: true,
          height: 500,
        },
      }),
    );
    expect(container.querySelector(".mermaid-diagram")).toHaveAttribute(
      "aria-busy",
      "true",
    );
    // Capture the request ID through the outgoing message, not a guessed ID.
    let id: string | undefined;
    frame.contentWindow!.postMessage = (message: { id: string }) => {
      id = message.id;
    };
    fireEvent(
      window,
      new MessageEvent("message", {
        source: frame.contentWindow,
        origin: "null",
        data: { type: "crabinet-mermaid-ready" },
      }),
    );
    await waitFor(() => expect(id).toBeDefined());
    for (const [origin, requestId] of [
      ["https://example.com", id],
      ["null", "stale-request"],
    ]) {
      fireEvent(
        window,
        new MessageEvent("message", {
          source: frame.contentWindow,
          origin,
          data: {
            type: "crabinet-mermaid-result",
            id: requestId,
            ok: true,
            height: 500,
          },
        }),
      );
      expect(container.querySelector(".mermaid-diagram")).toHaveAttribute(
        "aria-busy",
        "true",
      );
    }
    fireEvent(
      window,
      new MessageEvent("message", {
        source: frame.contentWindow,
        origin: "null",
        data: { type: "crabinet-mermaid-result", id, ok: false },
      }),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(
      "could not be rendered",
    );
    expect(container.querySelector("iframe")).toBeNull();
  });
});
