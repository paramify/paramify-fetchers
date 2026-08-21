# Placeholder, matching ../_template/tests/. Per-fetcher test conventions are not
# yet defined; v0.x fetchers are validated by running them end-to-end against a
# real tenant.
#
# For an issue-report fetcher the end-to-end check is specifically: run it, then
# confirm the file in <run>/issue-reports/ opens correctly in the source tool (or
# a plain CSV/XML reader) and is byte-identical to what the tool's own UI export
# produces. That is the property this kind of fetcher exists to preserve, and a
# unit test over a mocked response would not catch losing it.
