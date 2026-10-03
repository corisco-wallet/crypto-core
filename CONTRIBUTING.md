# Contributing to crypto-core

Thanks for considering a contribution. This crate is the signing-logic
foundation for a hardware wallet -- correctness and clarity matter more
here than almost anywhere else in the project.

## Building and testing

```bash
cargo test --features seed-lock,transfer-crypto
cargo clippy --features seed-lock,transfer-crypto --all-targets -- -D warnings
cargo fmt --check
cargo audit   # needs `cargo install cargo-audit`; run after `cargo generate-lockfile`
```

Not `--all-features`: `hw-sha512` depends on `esp-idf-sys`, which only
builds against the ESP-IDF/Xtensa target, not a plain host. Everything
else here runs on a plain host, no special toolchain needed. CI runs the
same three commands on every PR.

## Before opening a PR

- Add or update tests for any behavior change -- this crate leans on
  known-answer/test-vector tests (e.g. official BIP32 vectors) wherever
  one exists; prefer that over a hand-rolled example when possible.
- Run the three commands above locally first; CI will otherwise just
  bounce the PR back.
- Keep comments focused on *why*, not *what* -- if a comment just restates
  the next line of code, delete it instead.

## Changes to signing/derivation logic get extra scrutiny

Anything touching `bip32.rs`, `frost.rs`, `vss.rs`, `seed_lock.rs`, or
`mnemonic_gen.rs` affects how keys are derived, split, or encrypted --
review here is deliberately more careful than a typical PR. If you think
you've found an actual vulnerability (not just a bug) in this logic,
please follow this org's `SECURITY.md` for private disclosure instead of
opening a public issue.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`; add `!` or a
`BREAKING CHANGE:` footer for breaking changes). release-plz derives the
next version and `CHANGELOG.md` from them. Keep them short, present-tense,
and explain *why* when it's not obvious from the diff.

## Releases

Releases are automated by [release-plz](https://release-plz.dev). On every
push to `main` it opens/updates a release PR that bumps the version and
changelog; merging that PR creates the `vX.Y.Z` tag and GitHub Release.
Nothing is published to crates.io. Consumers pin by tag:

```toml
corisco-crypto-core = { git = "https://github.com/corisco-wallet/crypto-core", tag = "vX.Y.Z" }
```

Repo settings required: Actions > "Allow GitHub Actions to create and
approve pull requests".

## Review

See `.github/CODEOWNERS` for who reviews what. Branch protection on
`main` requires CI to pass and at least one approving review before
merge.
