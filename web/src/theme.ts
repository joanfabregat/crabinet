export type ThemePreference = "system" | "light" | "dark";

// Browser-wide rather than per account, so the sign-in page honors it too.
export const themePreferenceKey = "crabinet.theme";

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

export function saveThemePreference(preference: ThemePreference): void {
  applyThemePreference(preference);
  try {
    if (preference === "system") {
      window.localStorage.removeItem(themePreferenceKey);
    } else {
      window.localStorage.setItem(themePreferenceKey, preference);
    }
  } catch {
    // The theme still applies to this tab if storage is blocked.
  }
}
