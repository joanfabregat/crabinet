export type ThemePreference = "system" | "light" | "dark";

// The account's saved theme is the source of truth once signed in. This
// browser-wide copy lets the sign-in page and first paint honor it too.
export const themePreferenceKey = "crabinet.theme";

// Present once the copy above mirrors an account's saved theme. A light or
// dark copy without it was chosen before themes were saved per account.
export const themeSyncedKey = "crabinet.theme.synced";

/** Returns a light or dark choice made before themes followed the account. */
export function readLegacyThemePreference(): ThemePreference | null {
  try {
    if (window.localStorage.getItem(themeSyncedKey) !== null) return null;
  } catch {
    return null;
  }
  const preference = readThemePreference();
  return preference === "system" ? null : preference;
}

export function readThemePreference(): ThemePreference {
  try {
    const value = window.localStorage.getItem(themePreferenceKey);
    return value === "light" || value === "dark" ? value : "system";
  } catch {
    return "system";
  }
}

export function applyThemePreference(preference: ThemePreference): void {
  const root = document.documentElement;
  if (preference === "system") delete root.dataset.theme;
  else root.dataset.theme = preference;
}

/** Calls `listener` when another tab changes the stored preference. */
export function subscribeThemePreference(
  listener: (preference: ThemePreference) => void,
): () => void {
  const onStorage = (event: StorageEvent) => {
    if (event.key === themePreferenceKey || event.key === null) {
      listener(readThemePreference());
    }
  };
  window.addEventListener("storage", onStorage);
  return () => window.removeEventListener("storage", onStorage);
}

/** Applies an account's theme and stores the browser-wide copy of it. */
export function saveThemePreference(preference: ThemePreference): void {
  applyThemePreference(preference);
  try {
    if (preference === "system") {
      window.localStorage.removeItem(themePreferenceKey);
    } else {
      window.localStorage.setItem(themeSyncedKey, "1");
      window.localStorage.setItem(themePreferenceKey, preference);
    }
  } catch {
    // The theme still applies to this tab if storage is blocked.
  }
}
