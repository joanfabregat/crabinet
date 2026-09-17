const PERCENT_TRIPLET = /%[0-9a-f]{2}/iu;

/**
 * Validates one decoded virtual-path component.
 *
 * This prevents ambiguous client routes; it is not an authorization boundary.
 * The server must independently validate and resolve every path within a share.
 */
export function isValidPathComponent(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value !== "." &&
    value !== ".." &&
    !value.includes("/") &&
    !value.includes("\\") &&
    !hasControlCharacter(value) &&
    !PERCENT_TRIPLET.test(value) &&
    !value.endsWith(".") &&
    !value.endsWith(" ") &&
    value.normalize("NFC") === value &&
    !hasUnpairedSurrogate(value)
  );
}

/** Root is the empty string; every non-root path is slash-separated and canonical. */
export function isValidVirtualPath(value: unknown): value is string {
  if (value === "") return true;
  if (
    typeof value !== "string" ||
    value.startsWith("/") ||
    value.endsWith("/")
  ) {
    return false;
  }
  return value.split("/").every(isValidPathComponent);
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const point = character.codePointAt(0)!;
    if (point <= 0x1f || (point >= 0x7f && point <= 0x9f)) return true;
  }
  return false;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}
