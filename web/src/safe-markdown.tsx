import {
  ImageOff,
  Info,
  Lightbulb,
  MessageSquareWarning,
  OctagonAlert,
  TriangleAlert,
} from "lucide-preact";
import { type ComponentChildren, type JSX, h } from "preact";
import { useEffect, useMemo, useState } from "preact/hooks";
import { HighlightedCode, highlightLanguage } from "./highlighted-code";
import type { AlertKind } from "./markdown-parser";

/**
 * GitHub Flavored Markdown preview.
 *
 * markdown-it turns the source into HTML, including the file's own raw HTML.
 * That string is parsed into a detached `DOMParser` document, which runs no
 * scripts and loads no resources, and then walked into Preact elements through
 * a fixed tag and attribute allowlist. Nothing reaches `innerHTML`. Links open
 * only for http(s) and mailto, images are never loaded, and ids are prefixed
 * so a document cannot shadow the application's own elements.
 */
export const MAX_RENDER_CHARACTERS = 1024 * 1024;
const MAX_DEPTH = 64;
const ID_PREFIX = "user-content-";

type Rendered =
  | { status: "loading" }
  | { status: "ready"; html: string }
  | { status: "failed" };

export function SafeMarkdown({ source }: { source: string }) {
  const tooLarge = source.length > MAX_RENDER_CHARACTERS;
  const [rendered, setRendered] = useState<Rendered>({ status: "loading" });

  useEffect(() => {
    if (tooLarge) return;
    let active = true;
    setRendered({ status: "loading" });
    import("./markdown-parser").then(
      ({ renderMarkdownHtml }) => {
        if (active) {
          setRendered({ status: "ready", html: renderMarkdownHtml(source) });
        }
      },
      () => {
        if (active) setRendered({ status: "failed" });
      },
    );
    return () => {
      active = false;
    };
  }, [source, tooLarge]);

  const content = useMemo(
    () =>
      rendered.status === "ready"
        ? toElements(
            new DOMParser().parseFromString(rendered.html, "text/html").body,
            0,
          )
        : null,
    [rendered],
  );

  if (tooLarge || rendered.status === "failed") {
    return (
      <p class="preview-empty" data-testid="markdown-document">
        {tooLarge
          ? "This file is too large to render. The Source tab shows its text."
          : "The Markdown renderer could not load. The Source tab shows the file's text."}
      </p>
    );
  }
  return (
    <div
      class="markdown-document"
      data-testid="markdown-document"
      aria-busy={rendered.status === "loading"}
      onClick={followFragmentLink}
    >
      {content}
    </div>
  );
}

/** In-document links (table of contents, footnotes) scroll instead of routing. */
function followFragmentLink(event: JSX.TargetedMouseEvent<HTMLDivElement>) {
  const link = (event.target as Element).closest?.("a[href^='#']");
  if (!link || !event.currentTarget.contains(link)) return;
  event.preventDefault();
  const id = ID_PREFIX + safeDecode(link.getAttribute("href")!.slice(1));
  const target = Array.from(event.currentTarget.querySelectorAll("[id]")).find(
    (candidate) => candidate.id === id,
  );
  target?.scrollIntoView?.({ block: "start" });
}

function safeDecode(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Elements whose content is dropped, not shown as text. */
const DROPPED = new Set([
  "audio",
  "base",
  "canvas",
  "dialog",
  "embed",
  "frame",
  "frameset",
  "head",
  "iframe",
  "link",
  "math",
  "meta",
  "noembed",
  "noframes",
  "noscript",
  "object",
  "picture",
  "script",
  "select",
  "source",
  "style",
  "svg",
  "template",
  "textarea",
  "title",
  "track",
  "video",
]);

/** Elements rendered as themselves. Anything else is unwrapped to its content. */
const ALLOWED = new Set([
  "abbr",
  "b",
  "bdi",
  "bdo",
  "blockquote",
  "br",
  "caption",
  "cite",
  "code",
  "col",
  "colgroup",
  "dd",
  "del",
  "details",
  "dfn",
  "div",
  "dl",
  "dt",
  "em",
  "figcaption",
  "figure",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "hr",
  "i",
  "ins",
  "kbd",
  "li",
  "mark",
  "ol",
  "p",
  "pre",
  "q",
  "rp",
  "rt",
  "ruby",
  "s",
  "samp",
  "section",
  "small",
  "span",
  "strike",
  "strong",
  "sub",
  "summary",
  "sup",
  "table",
  "tbody",
  "td",
  "tfoot",
  "th",
  "thead",
  "time",
  "tr",
  "tt",
  "u",
  "ul",
  "var",
  "wbr",
]);

const ALIGNABLE = new Set([
  "div",
  "p",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "table",
  "tr",
  "td",
  "th",
]);
const ALIGNMENTS = new Set(["left", "right", "center", "justify"]);
const LINK_PROTOCOLS = new Set(["http:", "https:", "mailto:"]);

function toElements(parent: Node, depth: number): ComponentChildren[] {
  return Array.from(parent.childNodes, (node, index) =>
    toElement(node, depth, index),
  );
}

function toElement(node: Node, depth: number, key: number): ComponentChildren {
  if (node.nodeType === Node.TEXT_NODE) return (node as Text).data;
  if (node.nodeType !== Node.ELEMENT_NODE) return null;
  const element = node as Element;
  const tag = element.localName;
  if (element.namespaceURI !== "http://www.w3.org/1999/xhtml") return null;
  if (DROPPED.has(tag)) return null;
  // Beyond this depth, raw HTML nesting is flattened to its text.
  if (depth >= MAX_DEPTH) return element.textContent;
  const children = () => toElements(element, depth + 1);

  if (tag === "a") return link(element, children(), key);
  if (tag === "img") return imagePlaceholder(element, key);
  if (tag === "input") return checkbox(element, key);
  if (tag === "pre") return codeBlock(element, children(), key);
  if (tag === "blockquote") {
    const alert = element.getAttribute("data-alert");
    if (isAlertKind(alert)) return alertBlock(alert, children(), key);
  }
  if (!ALLOWED.has(tag)) return <>{children()}</>;
  return h(tag, { key, ...attributes(element, tag) }, children());
}

function attributes(element: Element, tag: string) {
  const props: Record<string, unknown> = {};
  const id = element.getAttribute("id");
  if (id) props.id = ID_PREFIX + id;
  for (const name of ["title", "lang", "dir"]) {
    const value = element.getAttribute(name);
    if (value !== null) props[name] = value;
  }
  const align = element.getAttribute("align")?.toLowerCase();
  if (align && ALIGNABLE.has(tag) && ALIGNMENTS.has(align)) {
    props.align = align;
  }
  if (tag === "td" || tag === "th") {
    // markdown-it writes table column alignment as an inline style. Only that
    // exact form is carried over, as a CSSOM property rather than an attribute.
    const textAlign = /^text-align:(left|right|center)$/.exec(
      element.getAttribute("style") ?? "",
    )?.[1];
    if (textAlign) props.style = { textAlign };
    copyNumber(element, props, "colspan", 1, 1000);
    copyNumber(element, props, "rowspan", 0, 65534);
  }
  if (tag === "ol") {
    copyNumber(element, props, "start", -1e9, 1e9);
    if (element.hasAttribute("reversed")) props.reversed = true;
  }
  if (tag === "li") copyNumber(element, props, "value", -1e9, 1e9);
  if (tag === "details" && element.hasAttribute("open")) props.open = true;
  if (tag === "time") {
    const datetime = element.getAttribute("datetime");
    if (datetime !== null) props.dateTime = datetime;
  }
  return props;
}

function copyNumber(
  element: Element,
  props: Record<string, unknown>,
  name: string,
  min: number,
  max: number,
) {
  const value = Number.parseInt(element.getAttribute(name) ?? "", 10);
  if (Number.isFinite(value)) props[name] = Math.min(max, Math.max(min, value));
}

function link(element: Element, children: ComponentChildren, key: number) {
  const href = element.getAttribute("href")?.trim() ?? "";
  const id = element.getAttribute("id");
  const props = id ? { id: ID_PREFIX + id } : {};
  if (href.startsWith("#") && href.length > 1) {
    return (
      <a key={key} {...props} href={href}>
        {children}
      </a>
    );
  }
  const url = absoluteUrl(href);
  if (url && LINK_PROTOCOLS.has(url.protocol)) {
    return (
      <a
        key={key}
        {...props}
        href={url.href}
        target="_blank"
        rel="noopener noreferrer nofollow"
      >
        {children}
      </a>
    );
  }
  return (
    <span
      key={key}
      {...props}
      class="markdown-inert-link"
      title={href ? `Link not opened: ${href}` : undefined}
    >
      {children}
    </span>
  );
}

function absoluteUrl(href: string) {
  try {
    return new URL(href);
  } catch {
    return undefined;
  }
}

function imagePlaceholder(element: Element, key: number) {
  const alt = element.getAttribute("alt")?.trim();
  return (
    <span
      key={key}
      class="markdown-image-placeholder"
      title="Images in Markdown are not loaded"
    >
      <ImageOff aria-hidden="true" size={14} />
      {alt ? alt : "Image"}
    </span>
  );
}

function checkbox(element: Element, key: number) {
  if (element.getAttribute("type")?.toLowerCase() !== "checkbox") return null;
  return (
    <input
      key={key}
      type="checkbox"
      class="markdown-task"
      disabled
      checked={element.hasAttribute("checked")}
    />
  );
}

function codeBlock(element: Element, children: ComponentChildren, key: number) {
  const code =
    element.children.length === 1 &&
    element.firstElementChild?.localName === "code"
      ? element.firstElementChild
      : undefined;
  if (!code) {
    return (
      <pre key={key} class="markdown-code" tabIndex={0}>
        {children}
      </pre>
    );
  }
  const source = (code.textContent ?? "").replace(/\n$/, "");
  const info = /(?:^|\s)language-(\S+)/.exec(code.getAttribute("class") ?? "");
  const language = info ? highlightLanguage(info[1]!) : undefined;
  if (language) {
    return (
      <HighlightedCode
        key={key}
        source={source}
        language={language}
        wrap={false}
        label="Code block"
      />
    );
  }
  return (
    <pre key={key} class="markdown-code" tabIndex={0} aria-label="Code block">
      <code>{source}</code>
    </pre>
  );
}

const ALERTS: Record<AlertKind, { title: string; icon: typeof Info }> = {
  note: { title: "Note", icon: Info },
  tip: { title: "Tip", icon: Lightbulb },
  important: { title: "Important", icon: MessageSquareWarning },
  warning: { title: "Warning", icon: TriangleAlert },
  caution: { title: "Caution", icon: OctagonAlert },
};

function isAlertKind(value: string | null): value is AlertKind {
  return value !== null && Object.hasOwn(ALERTS, value);
}

function alertBlock(kind: AlertKind, children: ComponentChildren, key: number) {
  const { title, icon: Icon } = ALERTS[kind];
  return (
    <div key={key} class={`markdown-alert markdown-alert-${kind}`} role="note">
      <p class="markdown-alert-title">
        <Icon aria-hidden="true" size={16} />
        {title}
      </p>
      {children}
    </div>
  );
}
