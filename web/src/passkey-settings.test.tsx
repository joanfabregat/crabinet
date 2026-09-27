import { fireEvent, render, screen, waitFor, within } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import type { ApiClient, Passkey } from "./api";
import { PasskeySettings } from "./passkey-settings";

describe("passkey settings", () => {
  it("renames and removes one of multiple keys without changing the others", async () => {
    const keys: Passkey[] = [
      { id: "first", name: "Laptop", createdAt: 100, lastUsedAt: null },
      { id: "second", name: "Phone", createdAt: 200, lastUsedAt: null },
    ];
    const renamePasskey = vi.fn(async (_id: string, name: string) => ({ ...keys[0], name }));
    const removePasskey = vi.fn(async () => undefined);
    const api = {
      authMethods: vi.fn(async () => ({ passwordEnabled: false, oidcEnabled: true, passkeyEnabled: true })),
      passkeys: vi.fn(async () => keys),
      renamePasskey,
      removePasskey,
    } as unknown as ApiClient;
    render(<PasskeySettings api={api} csrfToken="csrf" onSessionExpired={vi.fn()} />);
    expect(await screen.findByText("Laptop")).toBeInTheDocument();
    expect(screen.getByText("Phone")).toBeInTheDocument();

    const laptop = screen.getByText("Laptop").closest("li")!;
    fireEvent.click(within(laptop).getByRole("button", { name: "Rename" }));
    fireEvent.input(within(laptop).getByLabelText("Passkey name"), { target: { value: "Work laptop" } });
    fireEvent.click(within(laptop).getByRole("button", { name: "Save name" }));
    await waitFor(() => expect(renamePasskey).toHaveBeenCalledWith("first", "Work laptop", "csrf"));
    expect(await screen.findByText("Work laptop")).toBeInTheDocument();

    const phone = screen.getByText("Phone").closest("li")!;
    fireEvent.click(within(phone).getByRole("button", { name: "Remove" }));
    expect(removePasskey).not.toHaveBeenCalled();
    fireEvent.click(within(phone).getByRole("button", { name: "Confirm remove" }));
    await waitFor(() => expect(removePasskey).toHaveBeenCalledWith("second", "csrf"));
    expect(screen.queryByText("Phone")).not.toBeInTheDocument();
    expect(screen.getByText("Work laptop")).toBeInTheDocument();
  });
});
