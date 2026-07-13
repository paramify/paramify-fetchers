# Homebrew formula for the paramify fetcher CLI.
#
# TEMPLATE — two things get stamped per release (see ../README.md):
#   1. url / sha256 of the release tarball
#   2. the python resource stanzas (`brew update-python-resources`)
#
# GPL licensing rules out homebrew-core, so this lives in the paramify tap
# (github.com/paramify/homebrew-tap → `brew tap paramify/tap`).
class ParamifyFetchers < Formula
  include Language::Python::Virtualenv

  desc "Collect compliance evidence from your infrastructure and upload it to Paramify"
  homepage "https://github.com/paramify/paramify-fetchers"
  url "https://github.com/paramify/paramify-fetchers/archive/refs/tags/vX.Y.Z.tar.gz"
  sha256 "FILL_ME_ON_RELEASE" # shasum -a 256 <downloaded tarball>
  license "GPL-3.0-only"

  depends_on "python@3.13"

  # External CLIs the fetcher catalog shells out to — the one thing pipx can't
  # declare (docs/distribution_design.md §9). Heavy but complete; trim to
  # jq + git if you'd rather let operators bring the cloud CLIs themselves.
  depends_on "awscli"
  depends_on "checkov"
  depends_on "git"
  depends_on "jq"
  depends_on "kubectl"

  # ---------------------------------------------------------------------- #
  # Python resources. Regenerate the whole block after stamping url/sha256:
  #   brew update-python-resources Formula/paramify-fetchers.rb
  # It expands the transitive tree (requests → certifi/idna/urllib3/…,
  # typer → click/rich/…, jsonschema → referencing/rpds-py/…) automatically.
  #
  # setuptools + wheel are BUILD deps: brew builds offline (no build
  # isolation), and the setup.py build_py hook that assembles the
  # framework/_bundled content snapshot needs setuptools>=64 present.
  # ---------------------------------------------------------------------- #

  resource "setuptools" do
    url "FILL_ME"
    sha256 "FILL_ME"
  end

  resource "wheel" do
    url "FILL_ME"
    sha256 "FILL_ME"
  end

  resource "platformdirs" do
    url "FILL_ME"
    sha256 "FILL_ME"
  end

  resource "python-dotenv" do
    url "FILL_ME"
    sha256 "FILL_ME"
  end

  resource "pyyaml" do
    url "FILL_ME"
    sha256 "FILL_ME"
  end

  resource "requests" do
    url "FILL_ME"
    sha256 "FILL_ME"
  end

  resource "jsonschema" do
    url "FILL_ME"
    sha256 "FILL_ME"
  end

  resource "typer" do
    url "FILL_ME"
    sha256 "FILL_ME"
  end

  def install
    # pip install of the source tree runs the build_py hook, so the venv gets
    # framework/_bundled (fetchers + examples) — the content built-ins run from.
    virtualenv_install_with_resources
  end

  test do
    assert_match(/Discovered \d+ fetchers/, shell_output("#{bin}/paramify list"))
    # no checkout, no user dir: catalog must resolve from the installed bundle
    output = shell_output("#{bin}/paramify catalog --json")
    assert_match "_bundled", output
  end
end
