# Placeholder, matching ../_template/tests/. Per-fetcher test conventions are not
# yet defined.
#
# For an inventory fetcher the cases worth covering are the failure ones: a
# failed page, an asset without an id, and a credential rejected mid-pagination
# must each write `data: []` with `records_included: false` and exit non-zero.
# framework.inventory.check(payload, exit_code) is the verdict the uploader acts
# on; assert it is complete only for the clean run.
