import { render } from "preact";

import { App } from "./app";
import "./styles.css";

if (import.meta.env.DEV) document.title = "[dev] Crabinet";

render(<App />, document.getElementById("app")!);
