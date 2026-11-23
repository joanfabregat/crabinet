import mermaid from "mermaid";

import { MAX_MERMAID_CHARACTERS, MAX_MERMAID_HEIGHT } from "./mermaid-policy";

// This entry point runs ONLY in mermaid-renderer.html, behind both a response
// CSP sandbox and an iframe sandbox without allow-same-origin. User text never
// reaches the application's DOM. Mermaid owns its own isolated rendering DOM.
const container = document.getElementById("diagram")!;
const parentOrigin = document.referrer
  ? new URL(document.referrer).origin
  : undefined;
let started = false;

window.addEventListener("click", (event) => event.preventDefault(), true);
window.addEventListener("submit", (event) => event.preventDefault(), true);

window.addEventListener("message", async (event: MessageEvent<unknown>) => {
  if (
    started ||
    event.source !== window.parent ||
    event.origin !== parentOrigin ||
    !event.data ||
    typeof event.data !== "object"
  )
    return;
  const data = event.data as Record<string, unknown>;
  if (
    data.type !== "crabinet-mermaid-render" ||
    typeof data.id !== "string" ||
    typeof data.source !== "string" ||
    data.source.length > MAX_MERMAID_CHARACTERS
  )
    return;
  started = true;
  document.body.style.margin = "0";
  document.body.style.padding = "8px";
  document.body.style.boxSizing = "border-box";
  document.documentElement.style.colorScheme =
    data.dark === true ? "dark" : "light";
  const reply = (ok: boolean, height = 200) =>
    window.parent.postMessage(
      { type: "crabinet-mermaid-result", id: data.id, ok, height },
      parentOrigin!,
    );
  try {
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      suppressErrorRendering: true,
      maxTextSize: MAX_MERMAID_CHARACTERS,
      maxEdges: 250,
      htmlLabels: true,
      theme: data.dark === true ? "dark" : "default",
      fontFamily: "system-ui, sans-serif",
      flowchart: { useMaxWidth: true },
      secure: [
        "secure",
        "securityLevel",
        "startOnLoad",
        "suppressErrorRendering",
        "maxTextSize",
        "maxEdges",
        "htmlLabels",
        "flowchart",
        "dompurifyConfig",
        "themeCSS",
        "fontFamily",
      ],
    });
    // run() reads the text node and renders through Mermaid's strict sanitizer.
    // No application-side HTML sink or user-controlled script is involved.
    container.className = "mermaid";
    container.replaceChildren(document.createTextNode(data.source));
    await mermaid.run({ nodes: [container] });
    // Mermaid's strict mode disables callbacks but can still emit URL links.
    // Keep their layout while removing every navigation target.
    for (const link of container.querySelectorAll("a")) {
      link.removeAttribute("href");
      link.removeAttributeNS("http://www.w3.org/1999/xlink", "href");
      link.removeAttribute("target");
      link.setAttribute("aria-disabled", "true");
    }
    const svg = container.querySelector("svg");
    if (!svg) throw new Error("missing diagram");
    // Mermaid can emit percentage heights, which size against the frame's
    // old viewport instead of the diagram's aspect ratio. Use its intrinsic
    // viewBox and available width, with no viewport-height dependency.
    svg.removeAttribute("height");
    svg.style.display = "block";
    svg.style.width = "100%";
    svg.style.height = "auto";
    const naturalWidth = svg.viewBox.baseVal.width;
    if (Number.isFinite(naturalWidth) && naturalWidth > 0)
      svg.style.maxWidth = `${naturalWidth}px`;

    let previousHeight = 0;
    const reportSize = () => {
      const height = Math.max(
        120,
        Math.ceil(document.body.getBoundingClientRect().height),
      );
      if (!Number.isFinite(height) || height > MAX_MERMAID_HEIGHT) {
        reply(false);
        observer.disconnect();
        return;
      }
      if (height !== previousHeight) {
        previousHeight = height;
        reply(true, height);
      }
    };
    const observer = new ResizeObserver(reportSize);
    observer.observe(container);
    reportSize();
    // Font/layout completion and preview/window width changes can all change
    // the rendered height after the first result has reached the parent.
    void document.fonts.ready.then(reportSize);
  } catch {
    container.replaceChildren();
    reply(false);
  }
});

if (window.parent !== window && parentOrigin) {
  window.parent.postMessage({ type: "crabinet-mermaid-ready" }, parentOrigin);
}
