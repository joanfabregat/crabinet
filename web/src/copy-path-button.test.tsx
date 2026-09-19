import { fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CopyPathButton } from "./copy-path-button";

const originalClipboard = Object.getOwnPropertyDescriptor(
  Navigator.prototype,
  "clipboard",
);

afterEach(() => {
  if (originalClipboard) {
    Object.defineProperty(Navigator.prototype, "clipboard", originalClipboard);
  } else {
    Reflect.deleteProperty(Navigator.prototype, "clipboard");
  }
});

describe("CopyPathButton", () => {
  it("copies an exact share-qualified Unicode path and announces success", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(Navigator.prototype, "clipboard", {
      configurable: true,
      get: () => ({ writeText }),
    });
    render(
      <CopyPathButton
        value="scratch/blog/Café notes.md"
        label="Copy full path for Café notes.md"
      />,
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: "Copy full path for Café notes.md",
      }),
    );

    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith("scratch/blog/Café notes.md"),
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "Copied scratch/blog/Café notes.md",
    );
  });

  it("shows a selected read-only fallback when clipboard access fails", async () => {
    Object.defineProperty(Navigator.prototype, "clipboard", {
      configurable: true,
      get: () => ({
        writeText: vi.fn().mockRejectedValue(new Error("denied")),
      }),
    });
    render(
      <CopyPathButton
        value="work/report: draft.txt"
        label="Copy full path for report: draft.txt"
      />,
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: "Copy full path for report: draft.txt",
      }),
    );

    expect(
      await screen.findByRole("dialog", { name: "Copy full path" }),
    ).toBeInTheDocument();
    const fallback = screen.getByLabelText("Select and copy this path");
    expect(fallback).toHaveValue("work/report: draft.txt");
    expect(fallback).toHaveAttribute("readonly");
    await waitFor(() => expect(fallback).toHaveFocus());
  });
});
