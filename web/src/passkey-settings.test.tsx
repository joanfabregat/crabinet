import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/preact";
import { beforeEach, describe, expect, it, vi } from "vitest";

const webauthn = vi.hoisted(() => ({
  startRegistration: vi.fn(),
  startAuthentication: vi.fn(),
  cancelCeremony: vi.fn(),
}));

vi.mock("@simplewebauthn/browser", () => ({
  browserSupportsWebAuthn: () => true,
  startRegistration: webauthn.startRegistration,
  startAuthentication: webauthn.startAuthentication,
  WebAuthnAbortService: { cancelCeremony: webauthn.cancelCeremony },
}));

import { ApiError, type ApiClient, type Passkey, type Session } from "./api";
import { App } from "./app";
import type { BrowserNavigation, BrowserRoute } from "./navigation";
import { isWebAuthnCancellation, PasskeySettings } from "./passkey-settings";

const session: Session = {
  user: { id: "u-1", username: "joan", displayName: "Joan" },
  shares: [{ id: "work", name: "Working files", access: "read-write" }],
  csrfToken: "csrf",
};

const passkeyMethods = vi.fn(async () => ({
  passwordEnabled: false,
  oidcEnabled: true,
  passkeyEnabled: true,
}));

function settingsApi(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    authMethods: passkeyMethods,
    passkeys: vi.fn(async () => []),
    session: vi.fn(async () => ({ ...session, csrfToken: "fresh" })),
    ...overrides,
  } as unknown as ApiClient;
}

function renderSettings(
  api: ApiClient,
  props: Partial<Parameters<typeof PasskeySettings>[0]> = {},
) {
  const onSessionRefreshed = vi.fn();
  const onBusyChange = vi.fn();
  const view = render(
    <PasskeySettings
      api={api}
      csrfToken="csrf"
      userId="u-1"
      onSessionExpired={vi.fn()}
      onSessionRefreshed={onSessionRefreshed}
      onBusyChange={onBusyChange}
      {...props}
    />,
  );
  return { ...view, onSessionRefreshed, onBusyChange };
}

async function requestNewPasskey() {
  fireEvent.input(await screen.findByLabelText("Name for new passkey"), {
    target: { value: "Laptop" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Add passkey" }));
}

const registrationChallenge = {
  flowId: "flow",
  options: { publicKey: { challenge: "c" } },
};

class StaticNavigation implements BrowserNavigation {
  constructor(private readonly route: BrowserRoute) {}
  current() {
    return this.route;
  }
  go() {}
  subscribe() {
    return () => undefined;
  }
}

beforeEach(() => {
  webauthn.startRegistration.mockReset();
  webauthn.startAuthentication.mockReset();
  webauthn.cancelCeremony.mockReset();
});

describe("passkey settings", () => {
  it("renames and removes one of multiple keys without changing the others", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const keys: Passkey[] = [
      { id: "first", name: "Laptop", createdAt: 100, lastUsedAt: null },
      { id: "second", name: "Phone", createdAt: 200, lastUsedAt: null },
    ];
    const renamePasskey = vi.fn(async (_id: string, name: string) => ({
      ...keys[0],
      name,
    }));
    const removePasskey = vi.fn(async () => undefined);
    const api = settingsApi({
      passkeys: vi.fn(async () => keys),
      renamePasskey,
      removePasskey,
    } as unknown as Partial<ApiClient>);
    renderSettings(api);
    expect(await screen.findByText("Laptop")).toBeInTheDocument();
    expect(screen.getByText("Phone")).toBeInTheDocument();

    const laptop = screen.getByText("Laptop").closest("li")!;
    const renameButton = within(laptop).getByRole("button", {
      name: "Rename Laptop",
    });
    expect(renameButton).toHaveAttribute("data-tooltip", "Rename");
    expect(renameButton.closest(".passkey-row-header")).toContainElement(
      screen.getByText("Laptop"),
    );
    fireEvent.click(renameButton);
    fireEvent.input(within(laptop).getByLabelText("Passkey name"), {
      target: { value: "Work laptop" },
    });
    fireEvent.click(within(laptop).getByRole("button", { name: "Save name" }));
    await waitFor(() =>
      expect(renamePasskey).toHaveBeenCalledWith(
        "first",
        "Work laptop",
        "csrf",
      ),
    );
    expect(await screen.findByText("Work laptop")).toBeInTheDocument();

    const phone = screen.getByText("Phone").closest("li")!;
    const removeButton = within(phone).getByRole("button", {
      name: "Remove Phone",
    });
    expect(removeButton).toHaveAttribute("data-tooltip", "Remove");
    fireEvent.click(removeButton);
    expect(removePasskey).not.toHaveBeenCalled();
    expect(confirm).toHaveBeenCalledWith(
      "Remove passkey “Phone”? This cannot be undone.",
    );
    confirm.mockReturnValue(true);
    fireEvent.click(removeButton);
    await waitFor(() =>
      expect(removePasskey).toHaveBeenCalledWith("second", "csrf"),
    );
    expect(screen.queryByText("Phone")).not.toBeInTheDocument();
    expect(screen.getByText("Work laptop")).toBeInTheDocument();
    confirm.mockRestore();
  });

  it("asks for a recent sign-in instead of reporting a generic failure", async () => {
    const api = settingsApi({
      startPasskeyRegistration: vi.fn().mockRejectedValue(
        new ApiError("forbidden", "Sign in again", {
          status: 403,
          code: "reauthentication_required",
        }),
      ),
    });
    renderSettings(api);
    await requestNewPasskey();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "For security, sign out and sign in again, then add the passkey within 10 minutes.",
    );
    expect(api.session).not.toHaveBeenCalled();
    expect(webauthn.startRegistration).not.toHaveBeenCalled();
  });

  it.each([
    new DOMException("The operation was not allowed", "NotAllowedError"),
    new DOMException("The operation was aborted", "AbortError"),
    Object.assign(new Error("Registration ceremony was aborted"), {
      name: "AbortError",
      code: "ERROR_CEREMONY_ABORTED",
    }),
  ])(
    "treats a dismissed passkey prompt (%s) as a silent cancel",
    async (cause) => {
      expect(isWebAuthnCancellation(cause)).toBe(true);
      const finishPasskeyRegistration = vi.fn();
      const api = settingsApi({
        startPasskeyRegistration: vi.fn(async () => registrationChallenge),
        finishPasskeyRegistration,
      } as unknown as Partial<ApiClient>);
      webauthn.startRegistration.mockRejectedValue(cause);
      renderSettings(api);
      await requestNewPasskey();

      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: "Add passkey" }),
        ).toBeEnabled(),
      );
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      expect(finishPasskeyRegistration).not.toHaveBeenCalled();
    },
  );

  it("retries a passkey rename once with a refreshed CSRF token", async () => {
    const keys: Passkey[] = [
      { id: "first", name: "Laptop", createdAt: 100, lastUsedAt: null },
    ];
    const renamePasskey = vi
      .fn<ApiClient["renamePasskey"]>()
      .mockRejectedValueOnce(
        new ApiError("forbidden", "stale", { status: 403, code: "forbidden" }),
      )
      .mockImplementation(async (id, name) => ({ ...keys[0]!, id, name }));
    const api = settingsApi({
      passkeys: vi.fn(async () => keys),
      renamePasskey,
    });
    const { onSessionRefreshed } = renderSettings(api);

    fireEvent.click(
      await screen.findByRole("button", { name: "Rename Laptop" }),
    );
    fireEvent.input(screen.getByLabelText("Passkey name"), {
      target: { value: "Desk" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save name" }));

    expect(await screen.findByText("Desk")).toBeInTheDocument();
    expect(renamePasskey.mock.calls.map((call) => call[2])).toEqual([
      "csrf",
      "fresh",
    ]);
    expect(onSessionRefreshed).toHaveBeenCalledWith(
      expect.objectContaining({ csrfToken: "fresh" }),
    );
  });

  it("does not retry a passkey removal when another account is now signed in", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const removePasskey = vi
      .fn<ApiClient["removePasskey"]>()
      .mockRejectedValue(
        new ApiError("forbidden", "stale", { status: 403, code: "forbidden" }),
      );
    const api = settingsApi({
      passkeys: vi.fn(async () => [
        { id: "first", name: "Laptop", createdAt: 100, lastUsedAt: null },
      ]),
      removePasskey,
      session: vi.fn(async () => ({
        ...session,
        user: { ...session.user, id: "u-2" },
        csrfToken: "other",
      })),
    });
    const { onSessionRefreshed } = renderSettings(api);

    fireEvent.click(
      await screen.findByRole("button", { name: "Remove Laptop" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "A different account is now signed in",
    );
    expect(removePasskey).toHaveBeenCalledOnce();
    expect(onSessionRefreshed).not.toHaveBeenCalled();
    expect(screen.getByText("Laptop")).toBeInTheDocument();
    confirm.mockRestore();
  });

  it("reports busy while registering and cancels the ceremony on unmount", async () => {
    const api = settingsApi({
      startPasskeyRegistration: vi.fn(async () => registrationChallenge),
    } as unknown as Partial<ApiClient>);
    webauthn.startRegistration.mockReturnValue(new Promise(() => undefined));
    const { onBusyChange, unmount } = renderSettings(api);
    await requestNewPasskey();

    await waitFor(() => expect(webauthn.startRegistration).toHaveBeenCalled());
    expect(onBusyChange).toHaveBeenLastCalledWith(true);
    unmount();
    expect(webauthn.cancelCeremony).toHaveBeenCalledOnce();
    expect(onBusyChange).toHaveBeenLastCalledWith(false);
  });

  it("keeps Settings open while a passkey registration is in progress", async () => {
    const api = {
      session: vi.fn(async () => session),
      authMethods: passkeyMethods,
      passkeys: vi.fn(async () => []),
      startPasskeyRegistration: vi.fn(async () => registrationChallenge),
      directory: vi.fn(async (shareId: string, path: string) => ({
        shareId,
        path,
        entries: [],
      })),
    } as unknown as ApiClient;
    webauthn.startRegistration.mockReturnValue(new Promise(() => undefined));
    render(
      <App
        api={api}
        navigation={new StaticNavigation({ shareId: "work", path: "" })}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Settings" }));
    await requestNewPasskey();
    await waitFor(() => expect(webauthn.startRegistration).toHaveBeenCalled());

    fireEvent.keyDown(document, { key: "Escape" });
    const dialog = screen.getByRole("dialog", { name: "Settings" });
    expect(
      within(dialog).getByRole("button", { name: "Close Settings" }),
    ).toBeDisabled();
    fireEvent.mouseDown(dialog.parentElement!);
    expect(screen.getByRole("dialog", { name: "Settings" })).toBeVisible();
  });

  it("does not report an error when passkey sign-in is dismissed", async () => {
    const api = {
      session: vi
        .fn()
        .mockRejectedValue(new ApiError("unauthorized", "anonymous")),
      authMethods: passkeyMethods,
      startPasskeyLogin: vi.fn(async () => ({
        flowId: "flow",
        options: { publicKey: { challenge: "c" } },
      })),
      finishPasskeyLogin: vi.fn(),
    } as unknown as ApiClient;
    webauthn.startAuthentication.mockRejectedValue(
      new DOMException("The operation was not allowed", "NotAllowedError"),
    );
    render(
      <App
        api={api}
        navigation={new StaticNavigation({ shareId: null, path: "" })}
      />,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Sign in with a passkey" }),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Sign in with a passkey" }),
      ).toBeEnabled(),
    );
    expect(webauthn.startAuthentication).toHaveBeenCalled();
    expect(
      screen.queryByText(/Passkey sign-in failed/),
    ).not.toBeInTheDocument();
    expect(api.finishPasskeyLogin).not.toHaveBeenCalled();
  });
});
