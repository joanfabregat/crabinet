import "./test-setup";

import { fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { describe, expect, it } from "vitest";

import { TooltipLayer } from "./tooltip-layer";

function renderTooltip(label = "Copy full path for Reports") {
  render(
    <>
      <div class="clipping-panel" style="overflow: hidden">
        <button class="tooltip-action" data-tooltip={label} type="button">
          Copy
        </button>
      </div>
      <TooltipLayer />
    </>,
  );
  return screen.getByRole("button", { name: "Copy" });
}

describe("tooltip layer", () => {
  it("renders a fixed tooltip independently of a clipping panel", async () => {
    const trigger = renderTooltip();
    fireEvent.pointerOver(trigger);

    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).toHaveTextContent("Copy full path for Reports");
    expect(tooltip).toHaveClass("app-tooltip", "is-visible");
    expect(tooltip.closest(".clipping-panel")).toBeNull();
  });

  it("supports keyboard focus and escape dismissal", async () => {
    const trigger = renderTooltip("Rename");
    fireEvent(
      trigger,
      new FocusEvent("focusin", { bubbles: true, relatedTarget: null }),
    );
    expect(await screen.findByRole("tooltip")).toHaveTextContent("Rename");

    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("tooltip")).not.toBeInTheDocument(),
    );
  });

  it("tracks tooltip label changes while open", async () => {
    const trigger = renderTooltip();
    fireEvent.pointerOver(trigger);
    await screen.findByRole("tooltip");

    trigger.dataset.tooltip = "Copied";
    await waitFor(() =>
      expect(screen.getByRole("tooltip")).toHaveTextContent("Copied"),
    );
  });

  it("dismisses when its trigger leaves the page", async () => {
    const trigger = renderTooltip();
    fireEvent.pointerOver(trigger);
    await screen.findByRole("tooltip");

    trigger.remove();
    await waitFor(() =>
      expect(screen.queryByRole("tooltip")).not.toBeInTheDocument(),
    );
  });
});
