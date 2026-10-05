#!/usr/bin/env bash
# Checks the sample archives written by the Rust test
# `browse::tests::archives_for_external_extractors` with independent ZIP
# readers: libarchive (bsdtar), Info-ZIP (unzip), and 7-Zip (7z). Each archive
# is listed and integrity-tested, then extracted by every reader and compared
# byte for byte, names and empty folders included, with the tree it must
# produce.
#
# Usage: check-zip-extractors.sh SAMPLES_DIR
# Requires bsdtar, unzip, 7z, and diff.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 SAMPLES_DIR" >&2
  exit 2
fi
samples=$1
# UTF-8 names (flag bit 11) extract as UTF-8 only under a UTF-8 locale.
export LC_ALL=C.UTF-8

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

checked=0
for archive in "$samples"/*.zip; do
  [[ -f "$archive" ]] || continue
  sample=$(basename -- "$archive" .zip)
  expected="$samples/$sample"
  echo "::group::$sample"
  bsdtar -tvf "$archive"
  unzip -t "$archive"
  7z t -bd "$archive"
  for reader in bsdtar unzip 7z; do
    out="$work/$sample-$reader"
    mkdir -p -- "$out"
    case $reader in
      bsdtar) bsdtar -xf "$archive" -C "$out" ;;
      unzip) unzip -q "$archive" -d "$out" ;;
      7z) 7z x -y -bd -o"$out" "$archive" >/dev/null ;;
    esac
    if ! diff -r -- "$expected" "$out"; then
      echo "$reader extracted $sample differently" >&2
      exit 1
    fi
  done
  echo "::endgroup::"
  checked=$((checked + 1))
done

if [[ $checked -eq 0 ]]; then
  echo "no sample archives in $samples" >&2
  exit 1
fi
echo "$checked archives listed, tested, and extracted identically by bsdtar, unzip, and 7z"
