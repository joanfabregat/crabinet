import { render } from "preact";

import { App } from "./app";
import "./styles.css";
import {
  applyThemePreference,
  readThemePreference,
  subscribeThemePreference,
} from "./theme";

applyThemePreference(readThemePreference());
subscribeThemePreference(applyThemePreference);

if (import.meta.env.DEV) document.title = "[dev] Crabinet";

render(<App />, document.getElementById("app")!);
