import { useEffect, useRef, useState } from "preact/hooks";

import { MAX_MERMAID_CHARACTERS, MAX_MERMAID_HEIGHT } from "./mermaid-policy";

let nextDiagram = 0;

export function MermaidDiagram({ source }: { source: string }) {
  const [dark, setDark] = useState(false);
  useEffect(() => {
    const root = document.documentElement;
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    const update = () =>
      setDark(
        root.dataset.theme === "dark" ||
          (!root.dataset.theme && media?.matches === true),
      );
    const observer = new MutationObserver(update);
    observer.observe(root, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
    media?.addEventListener("change", update);
    update();
    return () => {
      observer.disconnect();
      media?.removeEventListener("change", update);
    };
  }, []);

  if (source.length > MAX_MERMAID_CHARACTERS)
    return (
      <p class="preview-empty" role="status">
        This diagram is too large to render. Its source is still available.
      </p>
    );
  if (!source.trim())
    return <p class="preview-empty">This diagram is empty.</p>;

  return <DiagramFrame key={`${dark}:${source}`} source={source} dark={dark} />;
}

function DiagramFrame({ source, dark }: { source: string; dark: boolean }) {
  const frame = useRef<HTMLIFrameElement>(null);
  const id = useRef(`diagram-${++nextDiagram}`);
  const timer = useRef<number>();
  const settled = useRef(false);
  const [status, setStatus] = useState<"loading" | "ready" | "failed">(
    "loading",
  );
  const [height, setHeight] = useState(200);

  const send = () =>
    frame.current?.contentWindow?.postMessage(
      { type: "crabinet-mermaid-render", id: id.current, source, dark },
      // A sandbox without allow-same-origin has an opaque target origin.
      "*",
    );

  useEffect(() => {
    const receive = (event: MessageEvent<unknown>) => {
      if (
        event.source !== frame.current?.contentWindow ||
        event.origin !== "null" ||
        !event.data ||
        typeof event.data !== "object"
      )
        return;
      const data = event.data as Record<string, unknown>;
      if (data.type === "crabinet-mermaid-ready") send();
      if (data.type !== "crabinet-mermaid-result" || data.id !== id.current)
        return;
      window.clearTimeout(timer.current);
      settled.current = true;
      if (
        data.ok === true &&
        typeof data.height === "number" &&
        Number.isFinite(data.height)
      ) {
        setHeight(Math.min(MAX_MERMAID_HEIGHT, Math.max(120, data.height)));
        setStatus("ready");
      } else setStatus("failed");
    };
    window.addEventListener("message", receive);
    return () => {
      window.clearTimeout(timer.current);
      window.removeEventListener("message", receive);
    };
  }, [source, dark]);

  return (
    <div class="mermaid-diagram" aria-busy={status === "loading"}>
      {status === "failed" ? (
        <p class="preview-empty" role="status">
          This diagram could not be rendered. Its source is still available.
        </p>
      ) : (
        <>
          {status === "loading" && <p role="status">Rendering diagram…</p>}
          <iframe
            ref={frame}
            src="/mermaid-renderer.html"
            title="Mermaid diagram"
            sandbox="allow-scripts"
            loading="lazy"
            referrerPolicy="same-origin"
            height={height}
            onLoad={() => {
              if (settled.current) return;
              timer.current = window.setTimeout(
                () => setStatus("failed"),
                15_000,
              );
              send();
            }}
          />
        </>
      )}
    </div>
  );
}
