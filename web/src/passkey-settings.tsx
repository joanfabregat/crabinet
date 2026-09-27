import { useEffect, useState } from "preact/hooks";
import {
  browserSupportsWebAuthn,
  startRegistration,
} from "@simplewebauthn/browser";

import { ApiError, type ApiClient, type Passkey } from "./api";

interface Props {
  api: ApiClient;
  csrfToken: string;
  onSessionExpired: () => void;
}

function dateLabel(seconds: number): string {
  return new Date(seconds * 1000).toLocaleDateString();
}

export function PasskeySettings({ api, csrfToken, onSessionExpired }: Props) {
  const [enabled, setEnabled] = useState(false);
  const [keys, setKeys] = useState<Passkey[]>([]);
  const [name, setName] = useState("");
  const [editingId, setEditingId] = useState<string>();
  const [editedName, setEditedName] = useState("");
  const [confirmRemove, setConfirmRemove] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    const controller = new AbortController();
    api.authMethods(controller.signal).then(
      (methods) => {
        if (!methods.passkeyEnabled) return;
        setEnabled(true);
        api.passkeys(controller.signal).then(setKeys, (cause) => {
          if (controller.signal.aborted) return;
          if (cause instanceof ApiError && cause.kind === "unauthorized")
            onSessionExpired();
          else setError("Could not load your passkeys.");
        });
      },
      () => {
        if (!controller.signal.aborted)
          setError("Could not load passkey settings.");
      },
    );
    return () => controller.abort();
  }, [api]);

  const failed = (cause: unknown, message: string) => {
    if (cause instanceof ApiError && cause.kind === "unauthorized") {
      onSessionExpired();
    } else {
      setError(message);
    }
  };

  const add = async () => {
    if (!name.trim() || busy) return;
    setBusy(true);
    setError(undefined);
    try {
      const challenge = await api.startPasskeyRegistration(
        name.trim(),
        csrfToken,
      );
      const credential = await startRegistration({
        optionsJSON: challenge.options.publicKey,
      });
      const key = await api.finishPasskeyRegistration(
        challenge.flowId,
        credential,
        csrfToken,
      );
      setKeys((current) => [key, ...current]);
      setName("");
    } catch (cause) {
      failed(
        cause,
        "Could not add the passkey. Try again or choose another device.",
      );
    } finally {
      setBusy(false);
    }
  };

  const rename = async (id: string) => {
    if (!editedName.trim() || busy) return;
    setBusy(true);
    setError(undefined);
    try {
      const updated = await api.renamePasskey(id, editedName.trim(), csrfToken);
      setKeys((current) =>
        current.map((key) => (key.id === id ? updated : key)),
      );
      setEditingId(undefined);
    } catch (cause) {
      failed(cause, "Could not rename the passkey. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string) => {
    if (busy) return;
    setBusy(true);
    setError(undefined);
    try {
      await api.removePasskey(id, csrfToken);
      setKeys((current) => current.filter((key) => key.id !== id));
      setConfirmRemove(undefined);
    } catch (cause) {
      failed(cause, "Could not remove the passkey. Try again.");
    } finally {
      setBusy(false);
    }
  };

  if (!enabled && !error) return null;

  return (
    <section class="passkey-settings" aria-labelledby="passkeys-title">
      <h3 id="passkeys-title">Passkeys</h3>
      <p class="muted">
        Use a passkey to sign in without a password or identity provider. You
        can add more than one and manage each separately.
      </p>
      {error && (
        <p class="passkey-error" role="alert">
          {error}
        </p>
      )}
      {enabled && (
        <>
          {keys.length === 0 && <p class="muted">No passkeys added yet.</p>}
          <ul class="passkey-list">
            {keys.map((key) => (
              <li key={key.id}>
                {editingId === key.id ? (
                  <div class="passkey-edit">
                    <label for={`passkey-name-${key.id}`}>Passkey name</label>
                    <input
                      id={`passkey-name-${key.id}`}
                      value={editedName}
                      maxLength={80}
                      onInput={(event) =>
                        setEditedName(event.currentTarget.value)
                      }
                      disabled={busy}
                    />
                    <div class="passkey-actions">
                      <button
                        class="button"
                        type="button"
                        disabled={busy || !editedName.trim()}
                        onClick={() => void rename(key.id)}
                      >
                        Save name
                      </button>
                      <button
                        class="button button-secondary"
                        type="button"
                        disabled={busy}
                        onClick={() => setEditingId(undefined)}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <strong>{key.name}</strong>
                    <small>
                      Added {dateLabel(key.createdAt)}
                      {key.lastUsedAt
                        ? ` · Last used ${dateLabel(key.lastUsedAt)}`
                        : ""}
                    </small>
                    <div class="passkey-actions">
                      <button
                        class="button button-secondary"
                        type="button"
                        disabled={busy}
                        onClick={() => {
                          setEditingId(key.id);
                          setEditedName(key.name);
                          setConfirmRemove(undefined);
                        }}
                      >
                        Rename
                      </button>
                      {confirmRemove === key.id ? (
                        <>
                          <button
                            class="button button-danger"
                            type="button"
                            disabled={busy}
                            onClick={() => void remove(key.id)}
                          >
                            Confirm remove
                          </button>
                          <button
                            class="button button-secondary"
                            type="button"
                            disabled={busy}
                            onClick={() => setConfirmRemove(undefined)}
                          >
                            Cancel
                          </button>
                        </>
                      ) : (
                        <button
                          class="button button-secondary"
                          type="button"
                          disabled={busy}
                          onClick={() => {
                            setConfirmRemove(key.id);
                            setEditingId(undefined);
                          }}
                        >
                          Remove
                        </button>
                      )}
                    </div>
                  </>
                )}
              </li>
            ))}
          </ul>
          <label for="new-passkey-name">Name for new passkey</label>
          <div class="passkey-add">
            <input
              id="new-passkey-name"
              value={name}
              maxLength={80}
              placeholder="e.g. My laptop"
              onInput={(event) => setName(event.currentTarget.value)}
              disabled={busy}
            />
            <button
              class="button"
              type="button"
              disabled={
                busy ||
                !name.trim() ||
                !browserSupportsWebAuthn() ||
                keys.length >= 20
              }
              onClick={() => void add()}
            >
              {busy ? "Working…" : "Add passkey"}
            </button>
          </div>
          {!browserSupportsWebAuthn() && (
            <p class="muted">This browser does not support passkeys.</p>
          )}
        </>
      )}
    </section>
  );
}
