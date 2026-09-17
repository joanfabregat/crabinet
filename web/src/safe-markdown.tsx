import { type ComponentChildren, type JSX } from "preact";

/**
 * A deliberately small Markdown reader for the v1 preview.
 *
 * It recognizes only block structure and always passes file content to Preact
 * as text children. Raw HTML, links, images, and embedded content are never
 * interpreted or turned into DOM attributes.
 */
export function SafeMarkdown({ source }: { source: string }) {
  const blocks = parseBlocks(source);
  return (
    <div class="markdown-document" data-testid="markdown-document">
      {blocks.map((block, index) => renderBlock(block, index))}
    </div>
  );
}

type Block =
  | { type: "code"; text: string }
  | { type: "heading"; level: number; text: string }
  | { type: "list"; ordered: boolean; items: string[] }
  | { type: "paragraph"; text: string }
  | { type: "quote"; text: string };

function parseBlocks(source: string): Block[] {
  const lines = source.replaceAll("\r\n", "\n").split("\n");
  const blocks: Block[] = [];
  let paragraph: string[] = [];
  let list: Extract<Block, { type: "list" }> | undefined;
  let code: string[] | undefined;

  const flushParagraph = () => {
    if (paragraph.length > 0) {
      blocks.push({ type: "paragraph", text: paragraph.join(" ") });
      paragraph = [];
    }
  };
  const flushList = () => {
    if (list) {
      blocks.push(list);
      list = undefined;
    }
  };

  for (const line of lines) {
    if (line.startsWith("```")) {
      flushParagraph();
      flushList();
      if (code) {
        blocks.push({ type: "code", text: code.join("\n") });
        code = undefined;
      } else {
        code = [];
      }
      continue;
    }
    if (code) {
      code.push(line);
      continue;
    }

    const heading = /^(#{1,6})\s+(.+)$/.exec(line);
    const unordered = /^[-*+]\s+(.+)$/.exec(line);
    const ordered = /^\d+[.)]\s+(.+)$/.exec(line);
    const quote = /^>\s?(.*)$/.exec(line);

    if (heading) {
      flushParagraph();
      flushList();
      blocks.push({
        type: "heading",
        level: heading[1]!.length,
        text: heading[2]!,
      });
    } else if (unordered || ordered) {
      flushParagraph();
      const nextOrdered = Boolean(ordered);
      if (list && list.ordered !== nextOrdered) flushList();
      list ??= { type: "list", ordered: nextOrdered, items: [] };
      list.items.push((ordered ?? unordered)![1]!);
    } else if (quote) {
      flushParagraph();
      flushList();
      blocks.push({ type: "quote", text: quote[1]! });
    } else if (line.trim() === "") {
      flushParagraph();
      flushList();
    } else {
      flushList();
      paragraph.push(line);
    }
  }

  if (code) blocks.push({ type: "code", text: code.join("\n") });
  flushParagraph();
  flushList();
  return blocks;
}

function renderBlock(block: Block, key: number): ComponentChildren {
  if (block.type === "heading") {
    const Heading = `h${block.level}` as keyof JSX.IntrinsicElements;
    return <Heading key={key}>{block.text}</Heading>;
  }
  if (block.type === "list") {
    const List = block.ordered ? "ol" : "ul";
    return (
      <List key={key}>
        {block.items.map((item, index) => (
          <li key={index}>{item}</li>
        ))}
      </List>
    );
  }
  if (block.type === "code") {
    return (
      <pre key={key} class="markdown-code" tabIndex={0}>
        <code>{block.text}</code>
      </pre>
    );
  }
  if (block.type === "quote") {
    return <blockquote key={key}>{block.text}</blockquote>;
  }
  return <p key={key}>{block.text}</p>;
}
