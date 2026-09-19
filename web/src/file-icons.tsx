import {
  File,
  FileCode2,
  FileJson2,
  FileText,
  Folder,
  Image as ImageIcon,
  type LucideProps,
} from "lucide-preact";

import type { DirectoryEntry } from "./api";

const codeExtensions = new Set([
  "c",
  "cc",
  "cpp",
  "css",
  "go",
  "h",
  "hpp",
  "html",
  "java",
  "js",
  "jsx",
  "kt",
  "lua",
  "php",
  "py",
  "rb",
  "rs",
  "sh",
  "sql",
  "swift",
  "toml",
  "ts",
  "tsx",
  "xml",
  "yaml",
  "yml",
]);

const textExtensions = new Set(["md", "markdown", "rst", "txt"]);
const imageExtensions = new Set(["avif", "gif", "jpeg", "jpg", "png", "webp"]);

export type EntryIconKind =
  "folder" | "file" | "code" | "json" | "text" | "image";

export function entryIconKind(
  entry: Pick<DirectoryEntry, "kind" | "name">,
): EntryIconKind {
  if (entry.kind === "directory") return "folder";
  const extension = entry.name.toLowerCase().split(".").at(-1) ?? "";
  if (extension === "json") return "json";
  if (imageExtensions.has(extension)) return "image";
  if (codeExtensions.has(extension)) return "code";
  if (textExtensions.has(extension)) return "text";
  return "file";
}

export function EntryIcon({
  entry,
  ...props
}: { entry: Pick<DirectoryEntry, "kind" | "name"> } & LucideProps) {
  switch (entryIconKind(entry)) {
    case "folder":
      return <Folder {...props} />;
    case "json":
      return <FileJson2 {...props} />;
    case "image":
      return <ImageIcon {...props} />;
    case "code":
      return <FileCode2 {...props} />;
    case "text":
      return <FileText {...props} />;
    default:
      return <File {...props} />;
  }
}
