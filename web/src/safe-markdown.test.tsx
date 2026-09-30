import { fireEvent, render, screen, within } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import { MAX_RENDER_CHARACTERS, SafeMarkdown } from "./safe-markdown";

async function renderMarkdown(source: string) {
  render(<SafeMarkdown source={source} />);
  const document = screen.getByTestId("markdown-document");
  await vi.waitFor(() =>
    expect(document).toHaveAttribute("aria-busy", "false"),
  );
  return document;
}

describe("SafeMarkdown", () => {
  it("renders GitHub Flavored Markdown inline and block syntax", async () => {
    const document = await renderMarkdown(
      [
        "# Title",
        "",
        "Some **bold**, *italic*, ~~gone~~ and `code` text.",
        "",
        "| Left | Right |",
        "| :--- | ----: |",
        "| a    | 1     |",
        "",
        "- [x] done",
        "- [ ] open",
        "",
        "Visit https://example.com today.",
      ].join("\n"),
    );

    expect(
      screen.getByRole("heading", { name: "Title", level: 1 }),
    ).toHaveAttribute("id", "user-content-title");
    expect(document.querySelector("strong")).toHaveTextContent("bold");
    expect(document.querySelector("em")).toHaveTextContent("italic");
    expect(document.querySelector("s")).toHaveTextContent("gone");
    expect(document.querySelector("p code")).toHaveTextContent("code");

    const table = screen.getByRole("table");
    expect(
      within(table).getByRole("columnheader", { name: "Right" }),
    ).toHaveStyle({ textAlign: "right" });
    expect(within(table).getByRole("cell", { name: "a" })).toBeVisible();

    const tasks = screen.getAllByRole("checkbox");
    expect(tasks).toHaveLength(2);
    expect(tasks[0]).toBeChecked();
    expect(tasks[0]).toBeDisabled();
    expect(tasks[1]).not.toBeChecked();
    expect(document.querySelector("li")).toHaveTextContent(/^done$/);

    const link = screen.getByRole("link", { name: "https://example.com" });
    expect(link).toHaveAttribute("href", "https://example.com/");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer nofollow");
  });

  it("renders GitHub alerts, footnotes, and in-document links", async () => {
    const document = await renderMarkdown(
      [
        "[Jump](#details)",
        "",
        "> [!WARNING]",
        "> Mind the gap.",
        "",
        "A claim.[^1]",
        "",
        "## Details",
        "",
        "[^1]: The source.",
      ].join("\n"),
    );

    const alert = screen.getByRole("note");
    expect(alert).toHaveClass("markdown-alert-warning");
    expect(alert).toHaveTextContent(/^Warning\s*Mind the gap\.$/);
    expect(alert).not.toHaveTextContent("[!WARNING]");

    const footnote = document.querySelector("sup a");
    expect(footnote).toHaveAttribute("href", "#fn1");
    expect(document.querySelector("#user-content-fn1")).toHaveTextContent(
      "The source.",
    );

    const heading = screen.getByRole("heading", { name: "Details" });
    const scrollIntoView = vi.fn();
    heading.scrollIntoView = scrollIntoView;
    const jump = screen.getByRole("link", { name: "Jump" });
    expect(fireEvent.click(jump)).toBe(false);
    expect(scrollIntoView).toHaveBeenCalledOnce();
  });

  it("keeps allowlisted raw HTML and drops or disarms everything else", async () => {
    const document = await renderMarkdown(
      [
        "<details open><summary>More</summary>",
        "",
        'Press <kbd>Ctrl</kbd> <b onclick="alert(1)" class="modal" style="position:fixed" id="app">now</b>.',
        "",
        "</details>",
        "",
        '<p align="center">centered</p>',
        "",
        "<script>window.__markdownScript = true</script>",
        "<style>body { display: none }</style>",
        '<iframe src="https://attacker.invalid"></iframe>',
        '<svg><a href="javascript:alert(1)">svg</a></svg>',
        '<form action="/api/v1/auth/logout"><button>Unsafe form</button><input name="token"></form>',
        '<img src="https://attacker.invalid/pixel" alt="tracking pixel" onerror="alert(1)">',
        "",
        "[script](javascript:alert(1)) [data](data:text/html,x) [relative](docs/other.md)",
        '<a href="JaVaScRiPt:alert(1)">raw</a> <a href="vbscript:x">vb</a>',
      ].join("\n"),
    );

    expect(document.querySelector("details")).toHaveAttribute("open");
    expect(document.querySelector("kbd")).toHaveTextContent("Ctrl");
    const bold = document.querySelector("b")!;
    expect(bold.getAttributeNames()).toEqual(["id"]);
    expect(bold.id).toBe("user-content-app");
    expect(document.querySelector("p[align='center']")).toHaveTextContent(
      "centered",
    );

    expect(
      document.querySelector(
        "script, style, iframe, svg:not(.lucide), form, button, img, [onclick], [onerror], [style]:not(th, td)",
      ),
    ).toBeNull();
    expect(document.querySelectorAll("input")).toHaveLength(0);
    expect(document).toHaveTextContent("Unsafe form");
    expect(document).not.toHaveTextContent("__markdownScript");
    expect(document).not.toHaveTextContent("display: none");
    expect(
      document.querySelector(".markdown-image-placeholder"),
    ).toHaveTextContent("tracking pixel");
    expect(window).not.toHaveProperty("__markdownScript");

    for (const anchor of document.querySelectorAll("a")) {
      expect(anchor.getAttribute("href")).toMatch(/^(https?:|mailto:|#)/);
    }
    // markdown-it itself refuses javascript: and data: Markdown links.
    expect(document).toHaveTextContent("[script](javascript:alert(1))");
    for (const name of ["relative", "raw", "vb"]) {
      expect(screen.getByText(name)).toHaveClass("markdown-inert-link");
    }
  });

  it("highlights fenced code by language alias and keeps other fences as text", async () => {
    await renderMarkdown(
      ["```ts", "const x = 1;", "```", "", "```nope", "<b>raw</b>", "```"].join(
        "\n",
      ),
    );

    const blocks = screen.getAllByLabelText("Code block");
    expect(blocks).toHaveLength(2);
    expect(blocks[0]).toHaveClass("shiki-source");
    expect(blocks[0]).toHaveTextContent("const x = 1;");
    expect(blocks[1]).toHaveClass("markdown-code");
    expect(blocks[1]!.textContent).toBe("<b>raw</b>");
  });

  it("flattens raw HTML nested deeper than the render limit", async () => {
    const depth = 500;
    const document = await renderMarkdown(
      `${"<div>".repeat(depth)}deep${"</div>".repeat(depth)}`,
    );
    expect(document).toHaveTextContent("deep");
    expect(document.querySelectorAll("div").length).toBeLessThan(100);
  });

  it("refuses to render oversized documents", () => {
    render(<SafeMarkdown source={"a".repeat(MAX_RENDER_CHARACTERS + 1)} />);
    expect(screen.getByTestId("markdown-document")).toHaveTextContent(
      "too large to render",
    );
  });
});
