#!/bin/sh
# Checks that every relative Markdown link and image in the files at the top
# of ROOT and in ROOT/docs names a file that exists, so the repository and
# the release archive both read offline. Web, mail, and same-page links are
# skipped, as are fenced code blocks and inline code.
#
# Usage: check-doc-links.sh ROOT
set -eu

root=${1:?usage: check-doc-links.sh ROOT}
status=0
for file in "$root"/*.md "$root"/docs/*.md; do
  [ -f "$file" ] || continue
  dir=$(dirname -- "$file")
  # The targets of ](target), one per line.
  targets=$(awk '
    /^[ \t]*```/ { fenced = !fenced; next }
    fenced { next }
    {
      rest = $0
      gsub(/`[^`]*`/, "", rest)
      while (match(rest, /\]\([^) \t]+/)) {
        print substr(rest, RSTART + 2, RLENGTH - 2)
        rest = substr(rest, RSTART + RLENGTH)
      }
    }' "$file")
  while IFS= read -r target; do
    case $target in
      '' | http://* | https://* | mailto:* | '#'*) continue ;;
    esac
    if [ ! -e "$dir/${target%%#*}" ]; then
      echo "$file: broken relative link: $target" >&2
      status=1
    fi
  done <<TARGETS
$targets
TARGETS
done
exit "$status"
