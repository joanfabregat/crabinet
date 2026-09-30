import MarkdownIt, { type StateCore, type Token } from "markdown-it";
import footnote from "markdown-it-footnote";

/**
 * GitHub Flavored Markdown to an HTML string.
 *
 * The output still contains the file's raw HTML. It is only ever parsed into a
 * detached document and walked through the allowlist in `safe-markdown.tsx`;
 * it must never be assigned to `innerHTML`.
 */
export type AlertKind = "note" | "tip" | "important" | "warning" | "caution";

const markdown = new MarkdownIt({
  html: true,
  linkify: true,
  typographer: false,
}).use(footnote);
// GitHub autolinks URLs with a scheme or `www.`, not bare domain names.
markdown.linkify.set({ fuzzyLink: false });
markdown.core.ruler.push("crabinet_gfm", gitHubExtensions);

export function renderMarkdownHtml(source: string): string {
  return markdown.render(source);
}

function gitHubExtensions(state: StateCore) {
  const slugs = new Map<string, number>();
  const tokens = state.tokens;
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (token.type === "heading_open") {
      const inline = tokens[index + 1];
      if (inline?.type === "inline") {
        token.attrSet("id", uniqueSlug(slugs, plainText(inline)));
      }
    } else if (token.type === "list_item_open") {
      markTaskItem(state, tokens, index);
    } else if (token.type === "blockquote_open") {
      markAlert(tokens, index);
    }
  }
}

function plainText(inline: Token): string {
  return (inline.children ?? [])
    .filter((child) => child.type === "text" || child.type === "code_inline")
    .map((child) => child.content)
    .join("");
}

/** Mirrors github-slugger: lowercase, drop punctuation, spaces to hyphens. */
function uniqueSlug(slugs: Map<string, number>, text: string): string {
  const base = text
    .toLowerCase()
    .trim()
    .replace(/[^\p{L}\p{M}\p{N}\p{Pc} -]/gu, "")
    .replace(/ /g, "-");
  const seen = slugs.get(base);
  slugs.set(base, (seen ?? -1) + 1);
  return seen === undefined ? base : `${base}-${seen + 1}`;
}

const TASK_MARKER = /^\[([ xX])\][ \t]/;

function markTaskItem(state: StateCore, tokens: Token[], index: number) {
  const inline = tokens[index + 2];
  if (tokens[index + 1]?.type !== "paragraph_open" || inline?.type !== "inline")
    return;
  const first = inline.children?.[0];
  const marker = first?.type === "text" && TASK_MARKER.exec(first.content);
  if (!first || !marker) return;
  first.content = first.content.slice(marker[0].length);
  const checkbox = new state.Token("html_inline", "", 0);
  checkbox.content = `<input type="checkbox" disabled${marker[1] === " " ? "" : " checked"}>`;
  inline.children!.unshift(checkbox);
}

const ALERT_MARKER = /^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]$/i;

function markAlert(tokens: Token[], index: number) {
  const paragraph = tokens[index + 1];
  const inline = tokens[index + 2];
  if (paragraph?.type !== "paragraph_open" || inline?.type !== "inline") return;
  const children = inline.children ?? [];
  const marker =
    children[0]?.type === "text" && ALERT_MARKER.exec(children[0].content);
  const next = children[1]?.type;
  if (!marker || (next !== undefined && next !== "softbreak")) return;
  tokens[index]!.attrSet("data-alert", marker[1]!.toLowerCase());
  children.splice(0, 2);
  if (children.length === 0) {
    // The marker was the whole paragraph: render nothing in its place.
    paragraph.hidden = true;
    tokens[index + 3]!.hidden = true;
  }
}
