#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Fresh-eyes trial (CIRESNAVE-EXPECTATIONS 6.24): can a person who never saw the
# crate get from `cargo add` to the README's ten-line example, using only the
# README and rustdoc, and how long does it take?
#
#   tools/fresh-eyes-trial.sh start [DIR]   build the packaged crate, make a fresh
#                                           project in DIR (default: a new temp dir),
#                                           print the brief and start the clock
#   tools/fresh-eyes-trial.sh finish DIR    run the person's project, print elapsed
#                                           seconds and pass/fail
#
# The trial uses the crate as `cargo package` ships it (so a missing file in the
# package shows up), as a path dependency, because the version under test is not
# on crates.io yet. The person sees only: the README, the rustdoc, the project.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

case "${1:-}" in
start)
  dir="${2:-$(mktemp -d)}"
  mkdir -p "$dir"
  [ -z "$(ls -A "$dir")" ] || { echo "$dir is not empty" >&2; exit 1; }
  ver="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$root/Cargo.toml" | head -n1)"
  (cd "$root" && cargo package --locked --allow-dirty --no-verify -q)
  mkdir -p "$dir/crate-src"
  tar -xzf "$root/target/package/secretant-$ver.crate" -C "$dir/crate-src"
  # The person's view of the crate: README and docs only, built from the package.
  (cd "$dir/crate-src/secretant-$ver" && cargo doc --no-deps -q)
  cp "$dir/crate-src/secretant-$ver/README.md" "$dir/README-of-secretant.md"
  cargo new --bin "$dir/hello" -q
  date +%s > "$dir/.started"
  cat > "$dir/BRIEF.md" <<EOF
You have never seen the crate \`secretant\` (version $ver). Goal: in $dir/hello,
add it as a dependency and make \`cargo run\` run the README's ten-line example
and succeed (the assert passes).
Allowed: $dir/README-of-secretant.md, the rustdoc under
$dir/crate-src/secretant-$ver/target/doc/secretant/index.html, error messages,
the project in $dir/hello. Not allowed: the crate's source, tests, docs/ folder,
or anything else. Add the crate with:
  cargo add secretant --path $dir/crate-src/secretant-$ver
(in 0.1.0 this is just \`cargo add secretant\`). Write down every place you got
stuck, guessed, or had to leave the allowed material, and the elapsed time.
EOF
  cat "$dir/BRIEF.md"
  echo "trial dir: $dir"
  ;;
finish)
  dir="${2:?usage: finish DIR}"
  start="$(cat "$dir/.started")"
  now="$(date +%s)"
  if (cd "$dir/hello" && cargo run -q); then r=PASS; else r=FAIL; fi
  echo "$r elapsed=$((now - start))s"
  [ "$r" = PASS ]
  ;;
*)
  echo "usage: $0 start [DIR] | finish DIR" >&2
  exit 2
  ;;
esac
