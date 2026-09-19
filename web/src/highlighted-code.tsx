import { useEffect, useState } from "preact/hooks";
import { createHighlighterCore, type ThemedToken } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";

const languageLoaders: Record<string, () => Promise<{ default: unknown }>> = {
  c: () => import("@shikijs/langs/c"),
  cpp: () => import("@shikijs/langs/cpp"),
  css: () => import("@shikijs/langs/css"),
  go: () => import("@shikijs/langs/go"),
  html: () => import("@shikijs/langs/html"),
  java: () => import("@shikijs/langs/java"),
  javascript: () => import("@shikijs/langs/javascript"),
  json: () => import("@shikijs/langs/json"),
  jsx: () => import("@shikijs/langs/jsx"),
  kotlin: () => import("@shikijs/langs/kotlin"),
  lua: () => import("@shikijs/langs/lua"),
  markdown: () => import("@shikijs/langs/markdown"),
  php: () => import("@shikijs/langs/php"),
  python: () => import("@shikijs/langs/python"),
  ruby: () => import("@shikijs/langs/ruby"),
  rust: () => import("@shikijs/langs/rust"),
  shell: () => import("@shikijs/langs/shellscript"),
  sql: () => import("@shikijs/langs/sql"),
  swift: () => import("@shikijs/langs/swift"),
  toml: () => import("@shikijs/langs/toml"),
  tsx: () => import("@shikijs/langs/tsx"),
  typescript: () => import("@shikijs/langs/typescript"),
  xml: () => import("@shikijs/langs/xml"),
  yaml: () => import("@shikijs/langs/yaml"),
};

const highlighterPromise = createHighlighterCore({
  themes: [import("@shikijs/themes/github-light-high-contrast")],
  langs: [],
  engine: createJavaScriptRegexEngine(),
});
const loaded = new Set<string>();
export const MAX_HIGHLIGHT_CHARACTERS = 256 * 1024;
export const MAX_HIGHLIGHT_LINES = 10_000;

export function shouldHighlight(source: string) {
  if (source.length > MAX_HIGHLIGHT_CHARACTERS) return false;
  let lines = 1;
  for (const character of source) {
    if (character === "\n" && ++lines > MAX_HIGHLIGHT_LINES) return false;
  }
  return true;
}

async function tokens(
  source: string,
  language: string,
): Promise<ThemedToken[][]> {
  const loader = languageLoaders[language];
  if (!loader) return [];
  const highlighter = await highlighterPromise;
  if (!loaded.has(language)) {
    const module = await loader();
    await highlighter.loadLanguage(module.default as never);
    loaded.add(language);
  }
  return highlighter.codeToTokens(source, {
    lang: language,
    theme: "github-light-high-contrast",
  }).tokens;
}

export function HighlightedCode({
  source,
  language,
  wrap,
}: {
  source: string;
  language: string;
  wrap: boolean;
}) {
  const [lines, setLines] = useState<ThemedToken[][]>();

  useEffect(() => {
    let active = true;
    if (!shouldHighlight(source)) {
      setLines([]);
      return () => {
        active = false;
      };
    }
    setLines(undefined);
    void tokens(source, language).then(
      (next) => {
        if (active) setLines(next);
      },
      () => {
        if (active) setLines([]);
      },
    );
    return () => {
      active = false;
    };
  }, [language, source]);

  return (
    <pre
      class={`source-code shiki-source${wrap ? " source-code-wrap" : ""}`}
      tabIndex={0}
      aria-label="File source"
      aria-busy={lines === undefined}
    >
      <code>
        {!lines || lines.length === 0
          ? source
          : lines.map((line, lineIndex) => (
              <span class="shiki-line" key={lineIndex}>
                {line.map((token, tokenIndex) => (
                  <span
                    key={tokenIndex}
                    style={{
                      color: token.color,
                      ...(token.fontStyle === 1
                        ? { "font-style": "italic" }
                        : {}),
                      ...(token.fontStyle === 2
                        ? { "font-weight": "700" }
                        : {}),
                      ...(token.fontStyle === 4
                        ? { "text-decoration": "underline" }
                        : {}),
                    }}
                  >
                    {token.content}
                  </span>
                ))}
                {lineIndex < lines.length - 1 ? "\n" : ""}
              </span>
            ))}
      </code>
    </pre>
  );
}
