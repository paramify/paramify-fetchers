# Homebrew tap — publishing & bumping

`Formula/paramify-fetchers.rb` here is the **template**; the live copy belongs
in a tap repo. brew is the Mac/Linux convenience layer — **pipx is the
universal install path** (`pipx install` the release wheel; works on Windows
too). See `docs/distribution_design.md` §9.

## One-time: create the tap

1. Create the repo `paramify/homebrew-tap` with a `Formula/` directory.
2. Copy `Formula/paramify-fetchers.rb` into it (stamped — see below).
3. Users then install with:

   ```bash
   brew tap paramify/tap
   brew install paramify-fetchers
   ```

## Per release: stamp the formula

After `vX.Y.Z` is tagged and the GitHub Release exists (docs/releasing.md):

```bash
# 1. point at the release tarball and record its checksum
curl -fsSL -o /tmp/pf.tar.gz \
  https://github.com/paramify/paramify-fetchers/archive/refs/tags/vX.Y.Z.tar.gz
shasum -a 256 /tmp/pf.tar.gz          # → stamp url + sha256 in the formula

# 2. regenerate every python resource stanza (expands the transitive tree)
brew update-python-resources Formula/paramify-fetchers.rb

# 3. verify locally before pushing the tap
brew install --build-from-source Formula/paramify-fetchers.rb
brew test paramify-fetchers
brew audit --strict paramify-fetchers
```

## Notes

- **Why the external CLIs are deps:** declaring `awscli`/`kubectl`/`jq`/`git`/
  `checkov` is the one thing brew can do that pipx can't — a single install
  that can run the whole catalog. Trim the list in the tap if the closure is
  too heavy for your users.
- **Why setuptools/wheel are resources:** brew builds offline with no build
  isolation, and the `setup.py` `build_py` hook that assembles
  `framework/_bundled/` needs setuptools>=64 at build time.
- **The formula's `test do`** asserts the catalog resolves from `_bundled` —
  the installed-layout guarantee, same as `tests/test_installed.py`.
