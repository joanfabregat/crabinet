import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import { ToastProvider, useToast, type ToastOptions } from "./toast";

function Trigger({
  message,
  options,
}: {
  message: string;
  options?: ToastOptions;
}) {
  const showToast = useToast();
  return (
    <button type="button" onClick={() => showToast(message, options)}>
      Show
    </button>
  );
}

describe("toasts", () => {
  it.each([
    [undefined, "toast-success", ".lucide-circle-check"],
    ["warning", "toast-warning", ".lucide-triangle-alert"],
    ["error", "toast-error", ".lucide-circle-alert"],
  ] as const)(
    "colours a %s toast and gives it the matching icon",
    (tone, className, icon) => {
      render(
        <ToastProvider>
          <Trigger message="Something happened." options={{ tone }} />
        </ToastProvider>,
      );

      fireEvent.click(screen.getByRole("button", { name: "Show" }));
      const toast = screen.getByText("Something happened.").closest(".toast");
      expect(toast).toHaveClass(className);
      expect(toast?.querySelector(icon)).not.toBeNull();
    },
  );

  it("runs an action once and dismisses the toast", () => {
    const undo = vi.fn();
    render(
      <ToastProvider>
        <Trigger
          message="Moved a.txt to Trash."
          options={{ action: { label: "Undo", onClick: undo } }}
        />
      </ToastProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Show" }));
    fireEvent.click(screen.getByRole("button", { name: "Undo" }));
    expect(undo).toHaveBeenCalledOnce();
    expect(screen.queryByText("Moved a.txt to Trash.")).toBeNull();
  });
});
